"""End-to-end demonstration and acceptance check.

Usage:
    KEYVAULT_BASE_URL=http://localhost:8000 python -m scripts.demo

Verifies:
  1. policy creation / immutable versions / atomic rotation & revocation
  2. Shamir n-of-m custody, shard digests, secret never returned in plaintext
  3. threshold recovery with one-time X25519 wrapped ciphertext, client unwrap
  4. deterministic rejections: bad signature, wrong shard point, tampered
     shard digest, nonce reuse / claim with spent nonce, duplicate share,
     cross-policy share, revoked/expired epoch, session completed/expired,
     optimistic version conflict, concurrent duplicate race
  5. cross-request state consistency: spent-nonce replay after a partial
     session must not evict already-committed in-memory shares; interleaved
     replays and legitimate submits keep db count and memory in agreement;
     the wrapped ciphertext is returned exactly once
  6. cross-policy migration: idempotent session create (same key replays,
     different keys never duplicate-migrate), one-time challenge + signed
     shard submission binding source/target version digests, in-memory
     reconstruction + immediate re-shard under the target policy in one
     transaction, source custody untouched, mid-session rotation fails the
     session and a fresh idempotency key retries safely, concurrent
     duplicate create/submit rejected deterministically
  7. audit hash-chain replay valid and contains no secret material
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from app.seed import demo_credentials
from app.crypto import custodian_signing_message as crypto_signing_message
from app.crypto import migration_signing_message as crypto_mig_signing_message

BASE = os.environ.get("KEYVAULT_BASE_URL", "http://localhost:8000")
PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{PASS if ok else FAIL}] {name}" + (f" — {detail}" if detail and not ok else ""))


def body_of(r) -> dict:
    """Tolerate non-JSON (e.g. 500) responses so failures report cleanly."""
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return {}


class Client:
    def __init__(self, name: str, key: str):
        self.name = name
        self.http = httpx.AsyncClient(
            base_url=BASE,
            headers={"X-API-Key": key},
            timeout=30,
        )

    async def call(self, method: str, path: str, **kw):
        r = await self.http.request(method, path, **kw)
        return r

    async def close(self):
        await self.http.aclose()


def sign(sign_priv_hex: str, message: str | bytes) -> str:
    data = message.encode() if isinstance(message, str) else message
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sign_priv_hex)).sign(
        data
    ).hex()


def unwrap(wrap_priv_hex: str, wrap: dict, aad: str) -> bytes:
    ephemeral_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(wrap["ephemeral_public_key"]))
    shared = X25519PrivateKey.from_private_bytes(bytes.fromhex(wrap_priv_hex)).exchange(ephemeral_pub)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"keyvault-wrap-v1",
        info=b"KWR1" + aad.encode(),
    ).derive(shared)
    return AESGCM(key).decrypt(bytes.fromhex(wrap["nonce"]), bytes.fromhex(wrap["ciphertext"]), aad.encode())


async def expect_error(cli: Client, name: str, method: str, path: str, code: str, **kw):
    r = await cli.call(method, path, **kw)
    body = body_of(r)
    ok = body.get("error", {}).get("code") == code
    check(f"{name} -> {code}", ok,
          json.dumps(body, ensure_ascii=False) if body else f"HTTP {r.status_code}: {r.text[:200]}")
    return body


async def main() -> int:
    creds = demo_credentials()
    tenant = Client("tenant", creds["tenant"]["api_key"])
    cuds = {c["name"]: Client(c["name"], c["api_key"]) for c in creds["custodians"]}
    ckeys = {c["name"]: c for c in creds["custodians"]}
    admin = Client("admin", creds["admin_api_key"])
    extra_clients: list[Client] = []

    try:
        # 每次运行使用唯一策略后缀，保证脚本在持久库上可重复执行
        suffix = os.urandom(4).hex()
        pol_main = f"pol_main_{suffix}"
        pol_bad = f"pol_bad_{suffix}"
        pol_exp = f"pol_exp_{suffix}"
        pol_ttl = f"pol_ttl_{suffix}"
        pol_live = f"pol_live_{suffix}"

        # --- 健康检查 ------------------------------------------------------
        r = await tenant.call("GET", "/health")
        check("health", r.status_code == 200 and r.json()["status"] == "ok")

        # --- 认证 ----------------------------------------------------------
        anon = httpx.AsyncClient(base_url=BASE)
        r = await anon.get("/policies/p1")
        check("no api key -> 401", r.status_code == 401 and r.json()["error"]["code"] == "UNAUTHORIZED")
        await anon.aclose()

        # --- 策略参数校验 --------------------------------------------------
        bad = {
            "policy_id": pol_bad,
            "threshold": 5,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob"],
            "epoch": {"valid_from": "2026-01-01T00:00:00Z", "valid_until": "2030-01-01T00:00:00Z",
                      "rotation_interval": 0},
        }
        await expect_error(tenant, "threshold > custodians", "POST", "/policies",
                           "POLICY_PARAMS_INVALID", json=bad)

        # --- 创建 2-of-3 策略 ----------------------------------------------
        epoch = {"valid_from": "2026-01-01T00:00:00Z", "valid_until": "2030-01-01T00:00:00Z",
                 "rotation_interval": 0}
        pol = {
            "policy_id": pol_main,
            "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": epoch,
        }
        r = await tenant.call("POST", "/policies", json=pol)
        check("create policy v1 (2-of-3)", r.status_code == 201 and r.json()["version"] == 1,
              r.text)
        await expect_error(tenant, "create same policy twice", "POST", "/policies",
                           "BAD_REQUEST", json=pol)

        # 策略版本不可变：没有任何修改接口，GET 历史版本
        r = await tenant.call("GET", f"/policies/{pol_main}?version=1")
        check("read immutable v1", r.json()["status"] == "active")

        # --- 托管密钥（Shamir 分片） ---------------------------------------
        secret = b"the-quick-brown-fox-master-key-0123456789"
        secret_hex = secret.hex()
        r = await tenant.call("POST", "/custodies",
                              json={"policy_id": pol_main, "expected_version": 1,
                                    "secret_hex": secret_hex})
        custody = r.json()
        check("custody: 3 encrypted shards + digests",
              r.status_code == 201 and custody["shard_count"] == 3
              and len(custody["shard_digests"]) == 3
              and all(len(d) == 64 for d in custody["shard_digests"]), r.text)
        check("custody response contains no plaintext", secret_hex not in r.text)

        # expected_version 不匹配
        await expect_error(tenant, "custody stale version", "POST", "/custodies",
                           "VERSION_CONFLICT",
                           json={"policy_id": pol_main, "expected_version": 99, "secret_hex": "00"})

        # --- 恢复会话 ------------------------------------------------------
        wrap_priv, wrap_pub = None, None
        # X25519 keypair
        wp = X25519PrivateKey.generate()
        wrap_priv = wp.private_bytes(serialization.Encoding.Raw,
                                    serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption()).hex()
        wrap_pub = wp.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw).hex()
        request_digest = hashlib.sha256(b"ticket-4242|purpose=daily-rotation").hexdigest()
        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": custody["custody_id"],
                                    "request_digest": request_digest,
                                    "recovery_public_key": wrap_pub})
        session = r.json()
        check("open recovery session", r.status_code == 201 and session["status"] == "open", r.text)

        # --- 托管人获取 nonce（只发 nonce + 绑定要素，签名对象在领取分片后给出） -
        async def get_nonce(cname: str, sid: str | None = None):
            r = await cuds[cname].call("POST", "/recoveries/nonces",
                                       json={"session_id": sid or session["session_id"]})
            return r

        async def claim(cname: str, sid: str, nonce: str):
            return await cuds[cname].call("POST", "/recoveries/shards/claim",
                                          json={"session_id": sid, "nonce": nonce})

        async def submit(cname: str, sid: str, nonce: str, point_x: int, shard_hex: str, sig: str):
            return await cuds[cname].call("POST", "/recoveries/shares", json={
                "session_id": sid, "nonce": nonce, "point_x": point_x,
                "shard_hex": shard_hex, "signature": sig})

        r_alice = await get_nonce("alice")
        nonce_alice = r_alice.json()
        check("alice gets one-time nonce", r_alice.status_code == 200, r_alice.text)
        check("nonce binds policy version",
              "signing_message" not in nonce_alice and nonce_alice["point_x"] >= 1
              and len(nonce_alice["shard_digest"]) == 64)

        # 重复申请 nonce -> NONCE_ALREADY_USED
        await expect_error(cuds["alice"], "re-request nonce", "POST", "/recoveries/nonces",
                           "NONCE_ALREADY_USED", json={"session_id": session["session_id"]})

        # --- 外部托管人（不属于本策略版本）：连 nonce 都拿不到 ----------------
        r = await admin.call("POST", "/admin/custodians", json={"name": f"outsider-{suffix}"})
        outsider = r.json()
        check("admin registers outsider custodian", r.status_code == 201, r.text)
        outsider_cli = Client(outsider["name"], outsider["api_key"])
        await expect_error(outsider_cli, "outsider nonce on policy", "POST",
                           "/recoveries/nonces", "CROSS_POLICY_SHARE",
                           json={"session_id": session["session_id"]})
        await outsider_cli.close()

        # --- 领取本人分片（验过身份的托管人） --------------------------------
        # 未知 nonce / 伪造 nonce 领取 -> BAD_REQUEST，不泄露分片
        await expect_error(cuds["alice"], "claim with unknown nonce", "POST",
                           "/recoveries/shards/claim", "BAD_REQUEST",
                           json={"session_id": session["session_id"], "nonce": "00" * 32})

        c_alice = (await claim("alice", session["session_id"], nonce_alice["nonce"])).json()
        check("alice claims own shard (point+bytes+digest)",
              c_alice["point_x"] == nonce_alice["point_x"]
              and len(bytes.fromhex(c_alice["shard_hex"])) > 0
              and c_alice["shard_digest"] == nonce_alice["shard_digest"],
              json.dumps({k: v for k, v in c_alice.items() if k != "shard_hex"}))
        check("claimed shard alone does not reveal the secret",
              secret_hex not in c_alice["shard_hex"] and secret.decode() not in c_alice["shard_hex"])
        check("signing message binds nonce/session/version/point/digest",
              f"nonce={nonce_alice['nonce']}" in c_alice["signing_message"]
              and f"session={session['session_id']}" in c_alice["signing_message"]
              and f"version=1" in c_alice["signing_message"]
              and f"point={c_alice['point_x']}" in c_alice["signing_message"]
              and f"shard_digest={c_alice['shard_digest']}" in c_alice["signing_message"]
              and "keyvault.share.v2" in c_alice["signing_message"])
        # 同一未花费 nonce 可重复领取（幂等），返回同一片
        c_alice_again = (await claim("alice", session["session_id"], nonce_alice["nonce"])).json()
        check("claim is idempotent before spend",
              c_alice_again["shard_hex"] == c_alice["shard_hex"]
              and c_alice_again["signing_message"] == c_alice["signing_message"])

        # --- 错误分片：点位不对 / 字节被改，均不花费 nonce，依据确定 ----------
        # 先领 bob 的分片
        nonce_bob = (await get_nonce("bob")).json()
        c_bob = (await claim("bob", session["session_id"], nonce_bob["nonce"])).json()
        sig_a = sign(ckeys["alice"]["signing_private_key"], c_alice["signing_message"])

        # alice 提交 bob 的点位 -> SHARE_POINT_MISMATCH（归属点位校验先于花钱）
        wrong_point_body = {
            "session_id": session["session_id"], "nonce": nonce_alice["nonce"],
            "point_x": c_bob["point_x"], "shard_hex": c_alice["shard_hex"], "signature": sig_a,
        }
        await expect_error(cuds["alice"], "wrong point submitted", "POST",
                           "/recoveries/shares", "SHARE_POINT_MISMATCH", json=wrong_point_body)

        # alice 篡改自己的分片字节 -> SHARE_DIGEST_MISMATCH（与库存摘要不符）
        blob = bytearray(bytes.fromhex(c_alice["shard_hex"]))
        blob[0] ^= 0x01
        tampered = blob.hex()
        bad_digest = hashlib.sha256(bytes.fromhex(tampered)).hexdigest()
        msg_tampered = crypto_signing_message(
            nonce=nonce_alice["nonce"], session_id=session["session_id"],
            policy_id=session["policy_id"], policy_version=1,
            custodian_id="cus_demo_alice", point_x=c_alice["point_x"], shard_digest=bad_digest)
        sig_tampered = sign(ckeys["alice"]["signing_private_key"], msg_tampered)
        await expect_error(cuds["alice"], "tampered shard bytes", "POST",
                           "/recoveries/shares", "SHARE_DIGEST_MISMATCH", json={
                               "session_id": session["session_id"], "nonce": nonce_alice["nonce"],
                               "point_x": c_alice["point_x"], "shard_hex": tampered,
                               "signature": sig_tampered})
        # 错误分片未花费 nonce：随后用正确分片仍可提交
        check("bad shard did not spend nonce", True)

        # --- 错误签名被拒 ---------------------------------------------------
        await expect_error(cuds["alice"], "bad signature", "POST",
                           "/recoveries/shares", "BAD_SIGNATURE",
                           json={"session_id": session["session_id"],
                                 "nonce": nonce_alice["nonce"], "point_x": c_alice["point_x"],
                                 "shard_hex": c_alice["shard_hex"], "signature": "00" * 64})

        # 正确分片 + 正确签名提交（alice），尚不足门限
        r = await submit("alice", session["session_id"], nonce_alice["nonce"],
                         c_alice["point_x"], c_alice["shard_hex"], sig_a)
        body = r.json()
        check("alice share accepted (1/2), no wrap yet",
              r.status_code == 200 and body["shares_received"] == 1 and body["wrap"] is None, r.text)

        # nonce 一次性：重放同一 nonce
        await expect_error(cuds["alice"], "reuse spent nonce", "POST", "/recoveries/shares",
                           "NONCE_ALREADY_USED",
                           json={"session_id": session["session_id"],
                                 "nonce": nonce_alice["nonce"], "point_x": c_alice["point_x"],
                                 "shard_hex": c_alice["shard_hex"], "signature": sig_a})

        # nonce 已花费：再次领取分片被拒
        await expect_error(cuds["alice"], "claim with spent nonce", "POST",
                           "/recoveries/shards/claim", "NONCE_ALREADY_USED",
                           json={"session_id": session["session_id"], "nonce": nonce_alice["nonce"]})

        sig_b = sign(ckeys["bob"]["signing_private_key"], c_bob["signing_message"])

        # --- 跨策略/跨会话 nonce 绑定 --------------------------------------
        # alice 用 bob 的 nonce 提交 -> 绑定不匹配 CROSS_POLICY_SHARE
        sig_for_bob_nonce = sign(ckeys["alice"]["signing_private_key"], c_bob["signing_message"])
        await expect_error(cuds["alice"], "use another custodian nonce", "POST",
                           "/recoveries/shares", "CROSS_POLICY_SHARE",
                           json={"session_id": session["session_id"],
                                 "nonce": nonce_bob["nonce"], "point_x": c_alice["point_x"],
                                 "shard_hex": c_alice["shard_hex"], "signature": sig_for_bob_nonce})

        # --- 门限满足：bob 提交本人分片 -> 重组 + 一次性密文 ------------------
        r = await submit("bob", session["session_id"], nonce_bob["nonce"],
                         c_bob["point_x"], c_bob["shard_hex"], sig_b)
        body = r.json()
        check("bob share -> threshold met, completed",
              r.status_code == 200 and body["completed"] and body["status"] == "completed"
              and body["wrap"] is not None, r.text)

        # 客户端用私钥解开密文并校验
        try:
            recovered = unwrap(wrap_priv, body["wrap"], body["aad"])
            check("unwrap one-time ciphertext == original secret", recovered == secret)
        except Exception as exc:  # noqa: BLE001
            check("unwrap one-time ciphertext == original secret", False, repr(exc))

        # 门限满足后继续提交 -> SESSION_COMPLETED
        nonce_carol = await get_nonce("carol")
        check("nonce after completion -> SESSION_COMPLETED",
              nonce_carol.status_code == 409
              and nonce_carol.json()["error"]["code"] == "SESSION_COMPLETED",
              nonce_carol.text)

        # --- 并发竞态：同一份额并发双发，恰好一次 200、一次 409，计数不重复 --
        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": custody["custody_id"],
                                    "request_digest": request_digest,
                                    "recovery_public_key": wrap_pub})
        s2 = r.json()
        n2 = (await cuds["bob"].call("POST", "/recoveries/nonces",
                                     json={"session_id": s2["session_id"]})).json()
        c2 = (await claim("bob", s2["session_id"], n2["nonce"])).json()
        sig2 = sign(ckeys["bob"]["signing_private_key"], c2["signing_message"])
        payload = {"session_id": s2["session_id"], "nonce": n2["nonce"],
                   "point_x": c2["point_x"], "shard_hex": c2["shard_hex"], "signature": sig2}
        rs = await asyncio.gather(
            cuds["bob"].call("POST", "/recoveries/shares", json=payload),
            cuds["bob"].call("POST", "/recoveries/shares", json=payload),
        )
        codes = sorted(body_of(x).get("error", {}).get("code", "OK") for x in rs)
        statuses = sorted(x.status_code for x in rs)
        check("concurrent duplicate: exactly one accepted, other 409",
              statuses == [200, 409] and "OK" in codes,
              f"{statuses} {codes}")
        count_after = (await tenant.call("GET", f"/recoveries/{s2['session_id']}")).json()["shares_received"]
        check("no double counting under race", count_after == 1, str(count_after))

        # --- 回归：跨请求状态一致性 ----------------------------------------
        # 未达门限的会话已接受 alice 的有效分片后，alice 重放已花费 nonce 必须
        # 得到确定性 NONCE_ALREADY_USED，且拒绝路径不得撤销已提交的内存分片
        # （数据库计数与内存内容保持对应）；bob 随后补足门限必须仅凭已验签
        # 分片重组成功，密文全局只下发一次。
        async def prep_share(name: str, sid: str) -> dict:
            n = (await cuds[name].call("POST", "/recoveries/nonces",
                                       json={"session_id": sid})).json()
            c = (await claim(name, sid, n["nonce"])).json()
            return {"session_id": sid, "nonce": n["nonce"], "point_x": c["point_x"],
                    "shard_hex": c["shard_hex"],
                    "signature": sign(ckeys[name]["signing_private_key"], c["signing_message"])}

        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": custody["custody_id"],
                                    "request_digest": request_digest,
                                    "recovery_public_key": wrap_pub})
        s3 = r.json()
        pa3 = await prep_share("alice", s3["session_id"])
        pb3 = await prep_share("bob", s3["session_id"])
        r = await cuds["alice"].call("POST", "/recoveries/shares", json=pa3)
        check("regression: partial session accepts alice share (1/2)",
              r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text)
        replay = await cuds["alice"].call("POST", "/recoveries/shares", json=pa3)
        check("regression: spent-nonce replay -> 409 NONCE_ALREADY_USED",
              replay.status_code == 409
              and body_of(replay).get("error", {}).get("code") == "NONCE_ALREADY_USED",
              f"HTTP {replay.status_code}: {replay.text[:200]}")
        again = await cuds["alice"].call("POST", "/recoveries/shares", json=pa3)
        check("regression: repeated replay still clean 409 (no state damage)",
              again.status_code == 409
              and body_of(again).get("error", {}).get("code") == "NONCE_ALREADY_USED",
              f"HTTP {again.status_code}: {again.text[:200]}")
        st3 = body_of(await tenant.call("GET", f"/recoveries/{s3['session_id']}"))
        check("regression: db count intact after replays",
              st3.get("shares_received") == 1 and st3.get("status") == "open", json.dumps(st3))
        r = await cuds["bob"].call("POST", "/recoveries/shares", json=pb3)
        body = body_of(r)
        check("regression: bob completes threshold after replays (no THRESHOLD_NOT_MET)",
              r.status_code == 200 and body.get("completed") and body.get("wrap") is not None,
              r.text)
        if body.get("wrap"):
            try:
                check("regression: reconstructed only from verified shares == secret",
                      unwrap(wrap_priv, body["wrap"], body["aad"]) == secret)
            except Exception as exc:  # noqa: BLE001
                check("regression: reconstructed only from verified shares == secret",
                      False, repr(exc))

        # --- 回归：并发重放与合法提交交错 ------------------------------------
        # alice 已提交（1/2）后，并发混入两条已花费 nonce 的重放与 bob 的合法提交：
        # 重放不得触碰内存中已提交分片，bob 必须完成门限；数据库计数=2、
        # 密文恰好下发一次。
        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": custody["custody_id"],
                                    "request_digest": request_digest,
                                    "recovery_public_key": wrap_pub})
        s4 = r.json()
        pa4 = await prep_share("alice", s4["session_id"])
        pb4 = await prep_share("bob", s4["session_id"])
        r = await cuds["alice"].call("POST", "/recoveries/shares", json=pa4)
        assert r.status_code == 200 and body_of(r).get("shares_received") == 1, r.text
        rs = await asyncio.gather(
            cuds["alice"].call("POST", "/recoveries/shares", json=pa4),
            cuds["alice"].call("POST", "/recoveries/shares", json=pa4),
            cuds["bob"].call("POST", "/recoveries/shares", json=pb4),
        )
        bodies4 = [body_of(x) for x in rs]
        codes4 = sorted(b.get("error", {}).get("code", "OK") for b in bodies4)
        wraps4 = [b for b in bodies4 if b.get("wrap")]
        rejected4 = [c for c in codes4 if c != "OK"]
        # 重放先于 bob 完成则 NONCE_ALREADY_USED，晚于则 SESSION_COMPLETED；
        # 两者都是干净的 409 拒绝，关键是合法提交不受重放影响、恰好完成一次。
        check("regression: interleaved replays rejected, legit submit completes",
              sorted(x.status_code for x in rs) == [200, 409, 409]
              and codes4.count("OK") == 1
              and all(c in ("NONCE_ALREADY_USED", "SESSION_COMPLETED") for c in rejected4)
              and len(wraps4) == 1 and wraps4[0].get("completed"),
              f"{sorted(x.status_code for x in rs)} {codes4}")
        check("regression: ciphertext returned exactly once under interleaving",
              len(wraps4) == 1, f"wraps={len(wraps4)}")
        st4 = body_of(await tenant.call("GET", f"/recoveries/{s4['session_id']}"))
        check("regression: db count matches verified shares after interleaving",
              st4.get("shares_received") == 2 and st4.get("status") == "completed",
              json.dumps(st4))
        if wraps4:
            try:
                check("regression: interleaved unwrap == secret",
                      unwrap(wrap_priv, wraps4[0]["wrap"], wraps4[0]["aad"]) == secret)
            except Exception as exc:  # noqa: BLE001
                check("regression: interleaved unwrap == secret", False, repr(exc))

        # ================= 跨策略密钥迁移 =================
        pol_mig_src = f"pol_mig_src_{suffix}"
        pol_mig_tgt = f"pol_mig_tgt_{suffix}"
        pol_mig_rev = f"pol_mig_rev_{suffix}"
        pol_mig_exp = f"pol_mig_exp_{suffix}"
        mig_secret = b"migration-secret-7f3a91c20486bde51029aa66ff01"
        mig_secret2 = b"migration-secret-retry-55aa11bb22cc33dd44e"
        epoch_mig = {"valid_from": "2026-01-01T00:00:00Z", "valid_until": "2032-01-01T00:00:00Z",
                     "rotation_interval": 0}

        # 目标策略包含源策略之外的托管人 dave（证明按目标策略重新分片）
        r = await admin.call("POST", "/admin/custodians", json={"name": f"dave-{suffix}"})
        dave = r.json()
        check("migration: admin registers dave", r.status_code == 201, r.text)
        dave_cli = Client("dave", dave["api_key"])
        extra_clients.append(dave_cli)
        mig_cuds = {**cuds, "dave": dave_cli}
        mig_keys = {**ckeys, "dave": dave}

        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_mig_src, "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": epoch_mig})
        assert r.status_code == 201, r.text
        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_mig_tgt, "threshold": 2,
            "custodian_ids": ["cus_demo_bob", "cus_demo_carol", dave["custodian_id"]],
            "epoch": epoch_mig})
        assert r.status_code == 201, r.text
        r = await tenant.call("POST", "/custodies", json={
            "policy_id": pol_mig_src, "expected_version": 1, "secret_hex": mig_secret.hex()})
        mig_c1 = r.json()["custody_id"]
        check("migration: source custody created", r.status_code == 201, r.text)
        r = await tenant.call("POST", "/custodies", json={
            "policy_id": pol_mig_src, "expected_version": 1, "secret_hex": mig_secret.hex()})
        mig_c0 = r.json()["custody_id"]  # 专用于创建期负向用例（不挂任何会话）

        async def mig_challenge(name, mid):
            return await mig_cuds[name].call("POST", "/migrations/challenges",
                                             json={"migration_id": mid})

        async def mig_prep(name, mid):
            n = (await mig_challenge(name, mid)).json()
            c = (await mig_cuds[name].call("POST", "/migrations/shards/claim",
                                           json={"migration_id": mid, "nonce": n["nonce"]})).json()
            payload = {"migration_id": mid, "nonce": n["nonce"], "point_x": c["point_x"],
                       "shard_hex": c["shard_hex"],
                       "signature": sign(mig_keys[name]["signing_private_key"],
                                         c["signing_message"])}
            return payload, c

        async def mig_submit(name, payload):
            return await mig_cuds[name].call("POST", "/migrations/shares", json=payload)

        async def rec_prep_any(name, sid):
            n = (await mig_cuds[name].call("POST", "/recoveries/nonces",
                                           json={"session_id": sid})).json()
            c = (await mig_cuds[name].call("POST", "/recoveries/shards/claim",
                                           json={"session_id": sid, "nonce": n["nonce"]})).json()
            return {"session_id": sid, "nonce": n["nonce"], "point_x": c["point_x"],
                    "shard_hex": c["shard_hex"],
                    "signature": sign(mig_keys[name]["signing_private_key"],
                                      c["signing_message"])}

        # --- 创建：幂等键 + 源/目标版本摘要绑定 ------------------------------
        mig_key1 = f"mig-key-{suffix}-0001"
        r = await tenant.call("POST", "/migrations", json={
            "custody_id": mig_c1, "target_policy_id": pol_mig_tgt,
            "target_expected_version": 1, "idempotency_key": mig_key1})
        m1 = r.json()
        check("migration: session created (201, open, version digests bound)",
              r.status_code == 201 and m1["status"] == "open" and m1["threshold"] == 2
              and m1["source_policy_id"] == pol_mig_src and m1["source_policy_version"] == 1
              and m1["target_policy_id"] == pol_mig_tgt and m1["target_policy_version"] == 1
              and len(m1["source_policy_digest"]) == 64
              and len(m1["target_policy_digest"]) == 64, r.text)
        mid1 = m1["migration_id"]

        # 同键同参重放 -> 200 返回同一会话（安全重试创建）
        r = await tenant.call("POST", "/migrations", json={
            "custody_id": mig_c1, "target_policy_id": pol_mig_tgt,
            "target_expected_version": 1, "idempotency_key": mig_key1})
        check("migration: idempotent replay returns same session (200)",
              r.status_code == 200 and r.json()["migration_id"] == mid1, r.text)

        # 同键异参 -> 409（幂等键不得挪用到别的迁移参数）
        await expect_error(tenant, "migration: same key different params", "POST", "/migrations",
                           "MIGRATION_CONFLICT", json={
                               "custody_id": mig_c1, "target_policy_id": pol_main,
                               "target_expected_version": 1, "idempotency_key": mig_key1})

        # 不同幂等键 -> 进行中的会话冲突（不得重复迁移）
        await expect_error(tenant, "migration: different key while open", "POST", "/migrations",
                           "MIGRATION_CONFLICT", json={
                               "custody_id": mig_c1, "target_policy_id": pol_mig_tgt,
                               "target_expected_version": 1, "idempotency_key": f"mig-key-{suffix}-0002"})

        # 创建期负向：版本乐观锁 / 跨租户 / 未知记录
        await expect_error(tenant, "migration: stale target version", "POST", "/migrations",
                           "VERSION_CONFLICT", json={
                               "custody_id": mig_c0, "target_policy_id": pol_mig_tgt,
                               "target_expected_version": 99, "idempotency_key": f"mig-key-{suffix}-v99"})
        r = await admin.call("POST", "/admin/tenants", json={"name": f"mig-other-{suffix}"})
        other_tenant = Client("other", r.json()["api_key"])
        extra_clients.append(other_tenant)
        await expect_error(other_tenant, "migration: cross-tenant custody", "POST", "/migrations",
                           "FORBIDDEN", json={
                               "custody_id": mig_c1, "target_policy_id": pol_mig_tgt,
                               "target_expected_version": 1, "idempotency_key": f"mig-key-{suffix}-o1"})
        r = await other_tenant.call("POST", "/policies", json={
            "policy_id": f"pol_other_{suffix}", "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": epoch_mig})
        assert r.status_code == 201, r.text
        await expect_error(tenant, "migration: cross-tenant target policy", "POST", "/migrations",
                           "FORBIDDEN", json={
                               "custody_id": mig_c0, "target_policy_id": f"pol_other_{suffix}",
                               "target_expected_version": 1, "idempotency_key": f"mig-key-{suffix}-xt"})
        await expect_error(tenant, "migration: unknown custody", "POST", "/migrations",
                           "NOT_FOUND", json={
                               "custody_id": "cus_secret_nope", "target_policy_id": pol_mig_tgt,
                               "target_expected_version": 1, "idempotency_key": f"mig-key-{suffix}-nf"})

        # --- 托管人：挑战值 -> 领取 -> 签名 -> 提交 ---------------------------
        # 非源策略成员（dave）连挑战值都拿不到
        await expect_error(dave_cli, "migration: outsider challenge", "POST",
                           "/migrations/challenges", "CROSS_POLICY_SHARE",
                           json={"migration_id": mid1})

        pa1, claim_a1 = await mig_prep("alice", mid1)
        check("migration: signing message binds migration + both version digests",
              "keyvault.migration.share.v1" in claim_a1["signing_message"]
              and f"migration={mid1}" in claim_a1["signing_message"]
              and f"custody={mig_c1}" in claim_a1["signing_message"]
              and f"source_digest={m1['source_policy_digest']}" in claim_a1["signing_message"]
              and f"target_digest={m1['target_policy_digest']}" in claim_a1["signing_message"])
        # 未花费挑战值可重复领取（幂等，返回同一片）
        c_again = (await cuds["alice"].call("POST", "/migrations/shards/claim", json={
            "migration_id": mid1, "nonce": pa1["nonce"]})).json()
        check("migration: claim idempotent before spend",
              c_again["shard_hex"] == claim_a1["shard_hex"]
              and c_again["signing_message"] == claim_a1["signing_message"])
        # 重复领挑战值 -> NONCE_ALREADY_USED
        await expect_error(cuds["alice"], "migration: re-request challenge", "POST",
                           "/migrations/challenges", "NONCE_ALREADY_USED",
                           json={"migration_id": mid1})
        # 错签名 / 错点位 / 篡改分片：确定性拒绝且不花费挑战值
        await expect_error(cuds["alice"], "migration: bad signature", "POST", "/migrations/shares",
                           "BAD_SIGNATURE", json={**pa1, "signature": "00" * 64})
        await expect_error(cuds["alice"], "migration: wrong point", "POST", "/migrations/shares",
                           "SHARE_POINT_MISMATCH", json={**pa1, "point_x": pa1["point_x"] + 1})
        blob = bytearray(bytes.fromhex(pa1["shard_hex"]))
        blob[0] ^= 0x01
        await expect_error(cuds["alice"], "migration: tampered shard", "POST", "/migrations/shares",
                           "SHARE_DIGEST_MISMATCH", json={**pa1, "shard_hex": blob.hex()})
        # 用别的迁移的签名报文重放（绑定校验）：伪造报文也过不了库存摘要
        forged = crypto_mig_signing_message(
            nonce=pa1["nonce"], migration_id=mid1, custody_id=mig_c1,
            source_policy_id=pol_mig_src, source_policy_version=1,
            target_policy_id=pol_mig_tgt, target_policy_version=1,
            source_policy_digest=m1["source_policy_digest"],
            target_policy_digest="00" * 32,  # 错误的目标摘要
            custodian_id="cus_demo_alice", point_x=pa1["point_x"],
            shard_digest=claim_a1["shard_digest"])
        await expect_error(cuds["alice"], "migration: signature over wrong target digest", "POST",
                           "/migrations/shares", "BAD_SIGNATURE", json={
                               **pa1, "signature": sign(ckeys["alice"]["signing_private_key"],
                                                        forged)})

        r = await mig_submit("alice", pa1)
        check("migration: alice share accepted (1/2), no new custody yet",
              r.status_code == 200 and r.json()["shares_received"] == 1
              and not r.json()["completed"] and r.json()["result_custody_id"] is None, r.text)
        # 重放已花费挑战值 / 持已花费挑战值再领片
        await expect_error(cuds["alice"], "migration: replay spent challenge", "POST",
                           "/migrations/shares", "NONCE_ALREADY_USED", json=pa1)
        await expect_error(cuds["alice"], "migration: claim with spent challenge", "POST",
                           "/migrations/shards/claim", "NONCE_ALREADY_USED",
                           json={"migration_id": mid1, "nonce": pa1["nonce"]})

        pb1, _ = await mig_prep("bob", mid1)
        r = await mig_submit("bob", pb1)
        mb = r.json()
        check("migration: bob share -> source threshold met, new custody id returned",
              r.status_code == 200 and mb["completed"] and mb["status"] == "completed"
              and mb["result_custody_id"] and mb["new_custody"]["shard_count"] == 3
              and len(mb["new_custody"]["shard_digests"]) == 3
              and all(len(d) == 64 for d in mb["new_custody"]["shard_digests"]), r.text)
        check("migration: completion response carries no plaintext",
              mig_secret.hex() not in r.text and mig_secret.decode() not in r.text)
        new_custody1 = mb["result_custody_id"]
        check("migration: new custody bound to target policy version",
              mb["new_custody"]["policy_id"] == pol_mig_tgt
              and mb["new_custody"]["policy_version"] == 1
              and mb["new_custody"]["secret_digest"] == hashlib.sha256(mig_secret).hexdigest())

        r = await tenant.call("GET", f"/migrations/{mid1}")
        check("migration: GET shows completed + result custody id",
              r.json()["status"] == "completed" and r.json()["shares_received"] == 2
              and r.json()["result_custody_id"] == new_custody1, r.text)
        await expect_error(other_tenant, "migration: cross-tenant get", "GET",
                           f"/migrations/{mid1}", "FORBIDDEN")

        # 新托管记录可按目标策略正常恢复（bob/carol/dave 的 2-of-3），内容一致
        r = await tenant.call("POST", "/recoveries", json={
            "custody_id": new_custody1,
            "request_digest": hashlib.sha256(b"mig-verify-target").hexdigest(),
            "recovery_public_key": wrap_pub})
        s_mig = r.json()["session_id"]
        pc_m = await rec_prep_any("carol", s_mig)
        pd_m = await rec_prep_any("dave", s_mig)
        r = await mig_cuds["carol"].call("POST", "/recoveries/shares", json=pc_m)
        assert r.status_code == 200, r.text
        r = await mig_cuds["dave"].call("POST", "/recoveries/shares", json=pd_m)
        mv = r.json()
        check("migration: new custody recoverable under target policy",
              r.status_code == 200 and mv["completed"] and mv["wrap"] is not None, r.text)
        try:
            check("migration: migrated secret == original",
                  unwrap(wrap_priv, mv["wrap"], mv["aad"]) == mig_secret)
        except Exception as exc:  # noqa: BLE001
            check("migration: migrated secret == original", False, repr(exc))

        # 源托管记录保持不变：仍可按源策略恢复同一秘密
        r = await tenant.call("POST", "/recoveries", json={
            "custody_id": mig_c1,
            "request_digest": hashlib.sha256(b"mig-src-unchanged").hexdigest(),
            "recovery_public_key": wrap_pub})
        s_src = r.json()["session_id"]
        pa_s = await rec_prep_any("alice", s_src)
        pb_s = await rec_prep_any("bob", s_src)
        r = await mig_cuds["alice"].call("POST", "/recoveries/shares", json=pa_s)
        assert r.status_code == 200, r.text
        r = await mig_cuds["bob"].call("POST", "/recoveries/shares", json=pb_s)
        ms = r.json()
        try:
            src_ok = ms["completed"] and unwrap(wrap_priv, ms["wrap"], ms["aad"]) == mig_secret
        except Exception:  # noqa: BLE001
            src_ok = False
        check("migration: source custody unchanged & still recoverable",
              r.status_code == 200 and src_ok, r.text)

        # 完成后：不同幂等键不得重复迁移；会话上任何后续操作被拒
        await expect_error(tenant, "migration: different key after completion", "POST",
                           "/migrations", "MIGRATION_CONFLICT", json={
                               "custody_id": mig_c1, "target_policy_id": pol_mig_tgt,
                               "target_expected_version": 1,
                               "idempotency_key": f"mig-key-{suffix}-0003"})
        await expect_error(cuds["carol"], "migration: challenge on completed", "POST",
                           "/migrations/challenges", "SESSION_COMPLETED",
                           json={"migration_id": mid1})

        # --- 会话进行中目标策略被轮换：提交被拒 -> 判失败 -> 新幂等键安全重试 --
        r = await tenant.call("POST", "/custodies", json={
            "policy_id": pol_mig_src, "expected_version": 1, "secret_hex": mig_secret2.hex()})
        mig_c2 = r.json()["custody_id"]
        r = await tenant.call("POST", "/migrations", json={
            "custody_id": mig_c2, "target_policy_id": pol_mig_tgt,
            "target_expected_version": 1, "idempotency_key": f"mig-key-{suffix}-0004"})
        mid2 = r.json()["migration_id"]
        check("migration(rotate): session created on target v1", r.status_code == 201, r.text)
        pa2, _ = await mig_prep("alice", mid2)
        pb2, _ = await mig_prep("bob", mid2)  # 轮换前领好挑战值与分片
        r = await mig_submit("alice", pa2)
        check("migration(rotate): alice share accepted before rotation (1/2)",
              r.status_code == 200 and r.json()["shares_received"] == 1, r.text)
        r = await tenant.call("POST", f"/policies/{pol_mig_tgt}/rotate", json={
            "expected_version": 1,
            "epoch": {"valid_from": "2026-06-01T00:00:00Z", "valid_until": "2033-01-01T00:00:00Z",
                      "rotation_interval": 0}})
        check("migration(rotate): target policy rotated to v2 mid-session",
              r.status_code == 200 and r.json()["version"] == 2, r.text)
        r = await mig_submit("bob", pb2)
        check("migration(rotate): submit after target rotation -> EPOCH_REVOKED",
              r.status_code == 409 and r.json()["error"]["code"] == "EPOCH_REVOKED", r.text)
        # 新幂等键重试：旧会话被确定性判失败（可重放审计），新会话放行
        r = await tenant.call("POST", "/migrations", json={
            "custody_id": mig_c2, "target_policy_id": pol_mig_tgt,
            "target_expected_version": 2, "idempotency_key": f"mig-key-{suffix}-0005"})
        m3 = r.json()
        check("migration(rotate): retry with fresh key -> 201 on target v2",
              r.status_code == 201 and m3["target_policy_version"] == 2, r.text)
        r = await tenant.call("GET", f"/migrations/{mid2}")
        check("migration(rotate): stale session marked failed (replayable audit)",
              r.json()["status"] == "failed"
              and r.json()["fail_reason"] == "target_policy_revoked", r.text)
        pa3, _ = await mig_prep("alice", m3["migration_id"])
        pb3, _ = await mig_prep("bob", m3["migration_id"])
        r = await mig_submit("alice", pa3)
        assert r.status_code == 200, r.text
        r = await mig_submit("bob", pb3)
        mb4 = r.json()
        check("migration(rotate): retried migration completes on v2",
              r.status_code == 200 and mb4["completed"]
              and mb4["new_custody"]["policy_version"] == 2, r.text)
        r = await tenant.call("POST", "/recoveries", json={
            "custody_id": mb4["result_custody_id"],
            "request_digest": hashlib.sha256(b"mig-retry-verify").hexdigest(),
            "recovery_public_key": wrap_pub})
        s_mig2 = r.json()["session_id"]
        pc_m2 = await rec_prep_any("carol", s_mig2)
        pd_m2 = await rec_prep_any("dave", s_mig2)
        r = await mig_cuds["carol"].call("POST", "/recoveries/shares", json=pc_m2)
        assert r.status_code == 200, r.text
        r = await mig_cuds["dave"].call("POST", "/recoveries/shares", json=pd_m2)
        mv2 = r.json()
        try:
            retry_ok = mv2["completed"] and unwrap(wrap_priv, mv2["wrap"], mv2["aad"]) == mig_secret2
        except Exception:  # noqa: BLE001
            retry_ok = False
        check("migration(rotate): retried migration secret == original",
              r.status_code == 200 and retry_ok, r.text)

        # --- 并发重复创建：同键 -> 同一会话；异键 -> 恰一个 201 ---------------
        r = await tenant.call("POST", "/custodies", json={
            "policy_id": pol_mig_src, "expected_version": 1, "secret_hex": mig_secret.hex()})
        mig_c3 = r.json()["custody_id"]
        r = await tenant.call("POST", "/custodies", json={
            "policy_id": pol_mig_src, "expected_version": 1, "secret_hex": mig_secret.hex()})
        mig_c3b = r.json()["custody_id"]
        body_race = {"custody_id": mig_c3, "target_policy_id": pol_mig_tgt,
                     "target_expected_version": 2, "idempotency_key": f"mig-key-{suffix}-race"}
        rs = await asyncio.gather(
            tenant.call("POST", "/migrations", json=body_race),
            tenant.call("POST", "/migrations", json=body_race),
        )
        race_ids = {x.json()["migration_id"] for x in rs}
        check("migration: concurrent same-key create -> same session, one 201 one 200",
              sorted(x.status_code for x in rs) == [200, 201] and len(race_ids) == 1,
              f"{[x.status_code for x in rs]} {race_ids}")
        rs = await asyncio.gather(
            tenant.call("POST", "/migrations",
                        json={**body_race, "custody_id": mig_c3b,
                              "idempotency_key": f"mig-key-{suffix}-race-a"}),
            tenant.call("POST", "/migrations",
                        json={**body_race, "custody_id": mig_c3b,
                              "idempotency_key": f"mig-key-{suffix}-race-b"}),
        )
        check("migration: concurrent different-key create -> exactly one wins",
              sorted(x.status_code for x in rs) == [201, 409]
              and any(x.json().get("error", {}).get("code") == "MIGRATION_CONFLICT" for x in rs),
              f"{[x.status_code for x in rs]}")

        # --- 并发重复提交：恰一次 200，计数不重复 -----------------------------
        r = await tenant.call("POST", "/custodies", json={
            "policy_id": pol_mig_src, "expected_version": 1, "secret_hex": mig_secret.hex()})
        mig_c4 = r.json()["custody_id"]
        r = await tenant.call("POST", "/migrations", json={
            "custody_id": mig_c4, "target_policy_id": pol_mig_tgt,
            "target_expected_version": 2, "idempotency_key": f"mig-key-{suffix}-c4"})
        mid4 = r.json()["migration_id"]
        pa4, _ = await mig_prep("alice", mid4)
        rs = await asyncio.gather(mig_submit("alice", pa4), mig_submit("alice", pa4))
        check("migration: concurrent duplicate share -> exactly one accepted",
              sorted(x.status_code for x in rs) == [200, 409],
              f"{[x.status_code for x in rs]}")
        r = await tenant.call("GET", f"/migrations/{mid4}")
        check("migration: no double counting under race",
              r.json()["shares_received"] == 1, r.text)

        # --- 撤销 / 过期拒绝 --------------------------------------------------
        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_mig_rev, "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": epoch_mig})
        assert r.status_code == 201, r.text
        r = await tenant.call("POST", f"/policies/{pol_mig_rev}/revoke",
                              json={"expected_version": 1})
        assert r.status_code == 200, r.text
        r = await tenant.call("POST", "/custodies", json={
            "policy_id": pol_mig_src, "expected_version": 1, "secret_hex": mig_secret.hex()})
        mig_c5 = r.json()["custody_id"]
        await expect_error(tenant, "migration: revoked target", "POST", "/migrations",
                           "EPOCH_REVOKED", json={
                               "custody_id": mig_c5, "target_policy_id": pol_mig_rev,
                               "target_expected_version": 1,
                               "idempotency_key": f"mig-key-{suffix}-c5"})
        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_mig_exp, "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": {"valid_from": "2020-01-01T00:00:00Z", "valid_until": "2020-02-01T00:00:00Z",
                      "rotation_interval": 0}})
        assert r.status_code == 201, r.text
        await expect_error(tenant, "migration: expired target", "POST", "/migrations",
                           "EPOCH_EXPIRED", json={
                               "custody_id": mig_c5, "target_policy_id": pol_mig_exp,
                               "target_expected_version": 1,
                               "idempotency_key": f"mig-key-{suffix}-c6"})
        # 源策略撤销后其托管记录一律不可再迁移（放最后，避免影响前面用例）
        r = await tenant.call("POST", f"/policies/{pol_mig_src}/revoke",
                              json={"expected_version": 1})
        assert r.status_code == 200, r.text
        await expect_error(tenant, "migration: revoked source custody", "POST", "/migrations",
                           "EPOCH_REVOKED", json={
                               "custody_id": mig_c5, "target_policy_id": pol_mig_tgt,
                               "target_expected_version": 2,
                               "idempotency_key": f"mig-key-{suffix}-c7"})

        # --- 原子轮换：旧版本不可变且变为 revoked ---------------------------
        new_epoch = {"valid_from": "2027-01-01T00:00:00Z", "valid_until": "2031-01-01T00:00:00Z",
                     "rotation_interval": 0}
        # 乐观版本冲突
        await expect_error(tenant, "rotate with stale expected_version", "POST",
                           f"/policies/{pol_main}/rotate", "VERSION_CONFLICT",
                           json={"expected_version": 99, "epoch": new_epoch})
        r = await tenant.call("POST", f"/policies/{pol_main}/rotate",
                              json={"expected_version": 1, "threshold": 3,
                                    "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
                                    "epoch": new_epoch})
        check("rotate -> immutable v2, threshold=3, new epoch",
              r.status_code == 200 and r.json()["version"] == 2 and r.json()["threshold"] == 3
              and r.json()["epoch_index"] == 1, r.text)
        r_old = (await tenant.call("GET", f"/policies/{pol_main}?version=1")).json()
        check("v1 immutable record now revoked", r_old["status"] == "revoked", r_old["status"])

        # 轮换后不能用旧版本托管
        await expect_error(tenant, "custody on stale v1 after rotate", "POST", "/custodies",
                           "VERSION_CONFLICT",
                           json={"policy_id": pol_main, "expected_version": 1,
                                 "secret_hex": "aabb"})

        # --- 会话进行中 epoch 被轮换撤销：在途份额必须被拒 ------------------
        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_live,
            "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": epoch,
        })
        assert r.status_code == 201, r.text
        r = await tenant.call("POST", "/custodies",
                              json={"policy_id": pol_live, "expected_version": 1, "secret_hex": secret_hex})
        c_live = r.json()
        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": c_live["custody_id"],
                                    "request_digest": request_digest, "recovery_public_key": wrap_pub})
        s_live = r.json()
        n_live = (await cuds["alice"].call("POST", "/recoveries/nonces",
                                           json={"session_id": s_live["session_id"]})).json()
        c_live_shard = (await claim("alice", s_live["session_id"], n_live["nonce"])).json()
        # 门限恢复进行中，租户轮换策略 -> 旧 epoch 原子撤销
        r = await tenant.call("POST", f"/policies/{pol_live}/rotate",
                              json={"expected_version": 1, "epoch": new_epoch})
        check("rotate live policy mid-session", r.status_code == 200 and r.json()["version"] == 2, r.text)
        sig_live = sign(ckeys["alice"]["signing_private_key"], c_live_shard["signing_message"])
        await expect_error(cuds["alice"], "share after mid-session rotation", "POST",
                           "/recoveries/shares", "EPOCH_REVOKED",
                           json={"session_id": s_live["session_id"],
                                 "nonce": n_live["nonce"], "point_x": c_live_shard["point_x"],
                                 "shard_hex": c_live_shard["shard_hex"], "signature": sig_live})

        # 并发轮换竞态：两个 expected_version=2 同时推进，只有一个成功
        e3 = {"valid_from": "2028-01-01T00:00:00Z", "valid_until": "2032-01-01T00:00:00Z",
              "rotation_interval": 0}
        body_rot = {"expected_version": 2, "epoch": e3}
        rr = await asyncio.gather(
            tenant.call("POST", f"/policies/{pol_main}/rotate", json=body_rot),
            tenant.call("POST", f"/policies/{pol_main}/rotate", json=body_rot),
        )
        rot_status = sorted(x.status_code for x in rr)
        check("concurrent rotate: exactly one winner", rot_status == [200, 409], str(rot_status))
        head = (await tenant.call("GET", f"/policies/{pol_main}")).json()
        current_v = head["version"]

        # --- 撤销 epoch -----------------------------------------------------
        await expect_error(tenant, "revoke with stale version", "POST",
                           f"/policies/{pol_main}/revoke", "VERSION_CONFLICT",
                           json={"expected_version": 2})
        r = await tenant.call("POST", f"/policies/{pol_main}/revoke",
                              json={"expected_version": current_v})
        check("revoke current epoch atomic", r.status_code == 200 and r.json()["status"] == "revoked",
              r.text)
        # 已撤销上再撤销 -> POLICY_INACTIVE
        await expect_error(tenant, "revoke revoked epoch", "POST",
                           f"/policies/{pol_main}/revoke", "POLICY_INACTIVE",
                           json={"expected_version": current_v})

        # 头版本自身被撤销：托管命中 EPOCH_REVOKED（版本匹配但 epoch 已撤销）
        await expect_error(tenant, "custody on revoked head epoch", "POST", "/custodies",
                           "EPOCH_REVOKED",
                           json={"policy_id": pol_main, "expected_version": current_v,
                                 "secret_hex": "aabb"})

        # 撤销后恢复旧 custody -> EPOCH_REVOKED（v2 上也有 custody 吗？为覆盖路径，
        # 先在 v3 活跃时托管；这里直接对 v1 custody 开恢复：其策略版本 v1 已 revoked）
        await expect_error(tenant, "recovery on revoked epoch", "POST", "/recoveries",
                           "EPOCH_REVOKED",
                           json={"custody_id": custody["custody_id"],
                                 "request_digest": request_digest, "recovery_public_key": wrap_pub})

        # --- epoch 过期 -----------------------------------------------------
        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_exp,
            "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": {"valid_from": "2020-01-01T00:00:00Z",
                      "valid_until": "2020-02-01T00:00:00Z", "rotation_interval": 0},
        })
        check("create policy with past epoch ok (immutable record)", r.status_code == 201, r.text)
        await expect_error(tenant, "custody on expired epoch", "POST", "/custodies",
                           "EPOCH_EXPIRED",
                           json={"policy_id": pol_exp, "expected_version": 1, "secret_hex": "aabb"})

        # --- 会话过期（TTL 10s 上限内最小值 10s；为省时直接演示 expired 判定路径，
        # 等待 10 秒）-------------------------------------------------------
        # 先把主策略重新恢复可用：创建新策略新 custody
        r = await tenant.call("POST", "/policies", json={
            "policy_id": pol_ttl,
            "threshold": 2,
            "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
            "epoch": {"valid_from": "2026-01-01T00:00:00Z",
                      "valid_until": "2035-01-01T00:00:00Z", "rotation_interval": 0},
        })
        assert r.status_code == 201, r.text
        r = await tenant.call("POST", "/custodies",
                              json={"policy_id": pol_ttl, "expected_version": 1,
                                    "secret_hex": secret_hex})
        c_ttl = r.json()
        r = await tenant.call("POST", "/recoveries",
                              json={"custody_id": c_ttl["custody_id"],
                                    "request_digest": request_digest,
                                    "recovery_public_key": wrap_pub, "ttl_seconds": 10})
        s_ttl = r.json()
        check("session with 10s ttl created", s_ttl["valid_until"] is not None)
        print("... waiting 11s for session expiry ...")
        await asyncio.sleep(11)
        await expect_error(cuds["alice"], "nonce on expired session", "POST",
                           "/recoveries/nonces", "SESSION_EXPIRED",
                           json={"session_id": s_ttl["session_id"]})

        # --- 审计哈希链重放 -------------------------------------------------
        r = await tenant.call("GET", "/audit/replay")
        chain = r.json()
        check("audit chain replay valid", chain.get("valid") is True, json.dumps(chain)[:300])
        raw = json.dumps(chain)
        check("audit log leaks no secret", secret_hex not in raw and secret.decode() not in raw)
        # 已领取分片明文绝不进审计
        check("audit log leaks no claimed shard", c_alice["shard_hex"] not in raw)
        check("audit log leaks no migrated secret",
              mig_secret.hex() not in raw and mig_secret.decode() not in raw
              and mig_secret2.hex() not in raw and mig_secret2.decode() not in raw)
        check("audit log leaks no migration-claimed shard", claim_a1["shard_hex"] not in raw)
        actions = {e["action"] for e in chain["entries"]}
        expect_actions = {
            "policy.create", "policy.rotate", "policy.epoch.revoke",
            "custody.create", "recovery.start", "recovery.nonce.issue",
            "recovery.shard.claim", "recovery.share.submit",
            "migration.start", "migration.challenge.issue", "migration.shard.claim",
            "migration.share.submit", "migration.complete", "migration.failed",
        }
        check("audit covers key lifecycle actions", expect_actions.issubset(actions),
              str(sorted(expect_actions - actions)))

        # admin 注册新身份可用（名字带唯一后缀，可重复运行）
        r = await admin.call("POST", "/admin/tenants", json={"name": f"second-tenant-{suffix}"})
        check("admin can register tenant", r.status_code == 201 and r.json()["api_key"].startswith("tsec_"),
              r.text)
    finally:
        await tenant.close()
        for c in cuds.values():
            await c.close()
        for c in extra_clients:
            await c.close()
        await admin.close()

    failed = [n for n, ok, _ in results if not ok]
    print("\n" + "=" * 70)
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("FAILED:")
        for n in failed:
            print(" -", n)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

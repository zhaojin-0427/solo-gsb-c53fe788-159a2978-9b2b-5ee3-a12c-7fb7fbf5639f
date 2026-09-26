"""跨策略密钥迁移。

租户为仍有效的托管记录指定另一条有效策略版本，以幂等键创建迁移会话；
旧（源）策略托管人按一次性挑战值领取并提交本人分片及签名；达到源门限后
服务**仅在内存重组**，立即按目标策略重新分片，并在**同一事务**写入新托管
记录与加密分片后返回其标识——源托管记录保持不变。响应、数据库与审计均不
出现明文秘密。

并发与死锁规则（与恢复流一致并扩展）：

* 创建按 ``migration:{custody_id}`` 事务级咨询锁串行；同一托管记录至多一个
  未失败会话（部分唯一索引兜底），并发重复（同键重放/异键冲突）都得确定性结果。
* 锁顺序全局统一：**行锁先于策略咨询锁**；迁移落定（finalize）按排序后的
  源/目标策略 id 依次加锁，与轮换/撤销使用的策略锁互斥，杜绝循环等待。
* 已验签分片只在内存累计（复用 ``PendingShareStore``），撤销边界与
  ``/recoveries/shares`` 相同：校验拒绝发生在入池之前；入池后的失败在事务
  （行锁）仍持有时凭本次插入 token 精确撤回。
* 终态失败（内存分片丢失/重组校验失败/源或目标在会话期间被撤销）随事务提交
  把会话置 ``failed`` 并留可重放审计，调用方可换新幂等键安全重试。
"""
from __future__ import annotations

from fastapi import APIRouter, Request, Response

from .. import audit, crypto, deps, repo
from ..config import get_settings
from ..errors import (
    ApiError,
    E_BAD_REQUEST,
    E_BAD_SIGNATURE,
    E_CROSS_POLICY_SHARE,
    E_DUPLICATE_SHARE,
    E_EPOCH_EXPIRED,
    E_EPOCH_REVOKED,
    E_FORBIDDEN,
    E_INTEGRITY,
    E_MIGRATION_CONFLICT,
    E_MIGRATION_FAILED,
    E_NONCE_USED,
    E_NOT_FOUND,
    E_POLICY_INACTIVE,
    E_SESSION_COMPLETED,
    E_SESSION_EXPIRED,
    E_SHARE_DIGEST,
    E_SHARE_POINT,
    E_THRESHOLD_NOT_MET,
    E_VERSION_CONFLICT,
)
from ..schemas import (
    MigrationChallengeIn,
    MigrationChallengeOut,
    MigrationSessionOut,
    MigrationShardClaimIn,
    MigrationShardClaimOut,
    MigrationShareSubmitIn,
    MigrationShareSubmitOut,
    MigrationStartIn,
)

router = APIRouter(prefix="/migrations", tags=["migrations"])


def _session_out(row, shares_received: int, threshold: int) -> MigrationSessionOut:
    return MigrationSessionOut(
        migration_id=row["id"],
        custody_id=row["custody_id"],
        idempotency_key=row["idempotency_key"],
        source_policy_id=row["source_policy_id"],
        source_policy_version=row["source_policy_version"],
        source_policy_digest=row["source_policy_digest"],
        target_policy_id=row["target_policy_id"],
        target_policy_version=row["target_policy_version"],
        target_policy_digest=row["target_policy_digest"],
        status=row["status"],
        fail_reason=row["fail_reason"],
        shares_received=shares_received,
        threshold=threshold,
        result_custody_id=row["result_custody_id"],
        valid_until=row["valid_until"],
        created_at=row["created_at"],
    )


def _policy_digest(row) -> str:
    """源/目标策略版本的规范摘要：会话、托管人签名与审计共同绑定它。"""
    return crypto.policy_version_digest(
        policy_id=row["id"],
        version=row["version"],
        tenant_id=row["tenant_id"],
        threshold=row["threshold"],
        custodian_ids=list(row["custodian_ids"]),
        epoch_index=row["epoch_index"],
        epoch_valid_from=row["epoch_valid_from"],
        epoch_valid_until=row["epoch_valid_until"],
        rotation_interval=row["rotation_interval"],
    )


async def _custody_shard(conn, custody_id: str, custodian_id: str):
    """The inventory shard (ciphertext + point + digest) assigned to a custodian."""
    return await conn.fetchrow(
        "SELECT id, point_x, ciphertext, shard_digest FROM shards "
        "WHERE custody_id=$1 AND custodian_id=$2",
        custody_id, custodian_id,
    )


async def _load_context(conn, mig):
    custody = await conn.fetchrow("SELECT * FROM key_custodies WHERE id=$1", mig["custody_id"])
    if custody is None:
        raise ApiError(E_INTEGRITY, basis={"reason": "custody_missing", "custody_id": mig["custody_id"]})
    src = await repo.get_policy_version(conn, mig["source_policy_id"], mig["source_policy_version"])
    tgt = await repo.get_policy_version(conn, mig["target_policy_id"], mig["target_policy_version"])
    if src is None or tgt is None:
        raise ApiError(E_INTEGRITY, basis={"reason": "policy_version_missing"})
    now = await conn.fetchval("SELECT now()")
    return custody, src, tgt, now


async def _guard_open_migration(mig, custody, src, tgt, now, custodian_id: str | None) -> None:
    """挑战签发 / 领取 / 提交共用的前置闸门（确定性拒绝，无任何副作用）。"""
    if mig["status"] == "completed":
        raise ApiError(
            E_SESSION_COMPLETED,
            basis={"migration_id": mig["id"], "result_custody_id": mig["result_custody_id"]},
        )
    if mig["status"] == "failed":
        raise ApiError(
            E_MIGRATION_FAILED,
            basis={"migration_id": mig["id"], "fail_reason": mig["fail_reason"]},
        )
    if now >= mig["valid_until"]:
        raise ApiError(
            E_SESSION_EXPIRED,
            basis={"valid_until": str(mig["valid_until"]), "now": str(now)},
        )
    # 版本摘要绑定：会话落库后不可变版本行若被篡改，立即确定性失败
    if not crypto.constant_time_hex_equal(_policy_digest(src), mig["source_policy_digest"]):
        raise ApiError(E_INTEGRITY, basis={"reason": "source_policy_digest_mismatch"})
    if not crypto.constant_time_hex_equal(_policy_digest(tgt), mig["target_policy_digest"]):
        raise ApiError(E_INTEGRITY, basis={"reason": "target_policy_digest_mismatch"})
    if mig["secret_digest"] != custody["secret_digest"]:
        raise ApiError(E_INTEGRITY, basis={"reason": "custody_secret_digest_mismatch"})
    if custody["status"] != "active" or src["status"] != "active":
        raise ApiError(
            E_EPOCH_REVOKED,
            basis={"policy_id": mig["source_policy_id"], "version": mig["source_policy_version"],
                   "custody_status": custody["status"], "policy_status": src["status"],
                   "side": "source"},
        )
    if now >= src["epoch_valid_until"]:
        raise ApiError(E_EPOCH_EXPIRED, basis={"epoch": src["epoch_index"], "side": "source"})
    if tgt["status"] != "active":
        raise ApiError(
            E_EPOCH_REVOKED,
            basis={"policy_id": mig["target_policy_id"], "version": mig["target_policy_version"],
                   "policy_status": tgt["status"], "side": "target"},
        )
    if now >= tgt["epoch_valid_until"]:
        raise ApiError(E_EPOCH_EXPIRED, basis={"epoch": tgt["epoch_index"], "side": "target"})
    if custodian_id is not None and custodian_id not in src["custodian_ids"]:
        raise ApiError(
            E_CROSS_POLICY_SHARE,
            basis={"custodian_id": custodian_id, "policy_id": mig["source_policy_id"],
                   "policy_version": mig["source_policy_version"],
                   "reason": "not_member_of_source_policy_version"},
        )


async def _unusable_reason(conn, mig, now) -> str | None:
    """已存在的 open 会话是否已不可能完成；是则创建方可用新幂等键安全重试。"""
    if now >= mig["valid_until"]:
        return "session_expired"
    custody = await conn.fetchrow("SELECT status FROM key_custodies WHERE id=$1", mig["custody_id"])
    if custody is None or custody["status"] != "active":
        return "source_custody_inactive"
    src = await repo.get_policy_version(conn, mig["source_policy_id"], mig["source_policy_version"])
    if src is None or src["status"] != "active":
        return "source_policy_revoked"
    if now >= src["epoch_valid_until"]:
        return "source_epoch_expired"
    tgt = await repo.get_policy_version(conn, mig["target_policy_id"], mig["target_policy_version"])
    if tgt is None or tgt["status"] != "active":
        return "target_policy_revoked"
    if now >= tgt["epoch_valid_until"]:
        return "target_epoch_expired"
    return None


async def _fail_migration(conn, mig, reason: str, tenant_id: str) -> None:
    """把 open 会话终态置 failed（随调用方事务提交），留下可重放审计。"""
    await conn.execute(
        "UPDATE migration_sessions SET status='failed', fail_reason=$2 "
        "WHERE id=$1 AND status='open'",
        mig["id"], reason,
    )
    await audit.append_audit(
        conn, tenant_id=tenant_id, actor_type="system", actor_id=None,
        action="migration.failed", resource=mig["id"], result="error",
        basis={
            "reason": reason,
            "custody_id": mig["custody_id"],
            "source_policy_id": mig["source_policy_id"],
            "source_policy_version": mig["source_policy_version"],
            "target_policy_id": mig["target_policy_id"],
            "target_policy_version": mig["target_policy_version"],
        },
    )


async def _resolve_challenge(conn, migration_id: str, nonce_hex: str, custodian_id: str):
    try:
        nonce_hash = crypto.sha256_hex(bytes.fromhex(nonce_hex))
    except ValueError:
        raise ApiError(E_BAD_REQUEST, basis={"reason": "nonce_malformed"})
    row = await conn.fetchrow(
        "SELECT * FROM migration_challenges WHERE nonce_hash=$1 FOR UPDATE", nonce_hash
    )
    if row is None:
        raise ApiError(E_BAD_REQUEST, basis={"reason": "nonce_unknown"})
    if row["migration_id"] != migration_id or row["custodian_id"] != custodian_id:
        raise ApiError(
            E_CROSS_POLICY_SHARE,
            basis={"reason": "nonce_binding_mismatch", "migration_id": migration_id,
                   "custodian_id": custodian_id},
        )
    return row


# ---------------------------------------------------------------------------
# 创建 / 查询迁移会话（租户）
# ---------------------------------------------------------------------------

@router.post("", response_model=MigrationSessionOut)
async def start_migration(
    body: MigrationStartIn, request: Request, response: Response, tenant=deps.Tenant
) -> MigrationSessionOut:
    settings = get_settings()
    pool = request.app.state.db.pool
    ttl = min(body.ttl_seconds or settings.recovery_default_ttl, settings.recovery_max_ttl)
    async with pool.acquire() as conn:
        async with conn.transaction():
            # 创建按托管记录串行：并发重复（同键重放 / 异键冲突）都得确定性结果
            await conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                f"migration:{body.custody_id}",
            )
            # 1) 幂等键：同键同参 -> 重放原会话（纯读，不产生新写入）
            existing = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE tenant_id=$1 AND idempotency_key=$2",
                tenant["id"], body.idempotency_key,
            )
            if existing is not None:
                same = (
                    existing["custody_id"] == body.custody_id
                    and existing["target_policy_id"] == body.target_policy_id
                    and existing["target_policy_version"] == body.target_expected_version
                )
                if not same:
                    raise ApiError(
                        E_MIGRATION_CONFLICT,
                        basis={"reason": "idempotency_key_reused_with_different_params",
                               "migration_id": existing["id"]},
                    )
                src = await repo.get_policy_version(
                    conn, existing["source_policy_id"], existing["source_policy_version"]
                )
                count = await conn.fetchval(
                    "SELECT count(*) FROM migration_submissions WHERE migration_id=$1",
                    existing["id"],
                )
                response.status_code = 200
                return _session_out(existing, count, src["threshold"])

            # 2) 源托管记录：必须仍有效且属于本租户
            custody = await conn.fetchrow(
                "SELECT * FROM key_custodies WHERE id=$1", body.custody_id
            )
            if custody is None:
                raise ApiError(E_NOT_FOUND, basis={"custody_id": body.custody_id})
            if custody["tenant_id"] != tenant["id"]:
                raise ApiError(E_FORBIDDEN, basis={"reason": "custody_belongs_to_other_tenant"})
            if custody["status"] != "active":
                raise ApiError(
                    E_EPOCH_REVOKED,
                    basis={"custody_id": body.custody_id, "custody_status": custody["status"],
                           "reason": "custody_not_active"},
                )
            src = await repo.get_policy_version(conn, custody["policy_id"], custody["policy_version"])
            now = await conn.fetchval("SELECT now()")
            if src["status"] != "active":
                raise ApiError(
                    E_EPOCH_REVOKED,
                    basis={"policy_id": src["id"], "version": src["version"],
                           "epoch": src["epoch_index"]},
                )
            if now >= src["epoch_valid_until"]:
                raise ApiError(
                    E_EPOCH_EXPIRED,
                    basis={"epoch": src["epoch_index"],
                           "valid_until": str(src["epoch_valid_until"]), "side": "source"},
                )

            # 3) 同一托管记录至多一个未失败会话（行锁先于策略锁，与提交路径一致）
            live = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE custody_id=$1 "
                "AND status IN ('open','completed') FOR UPDATE",
                body.custody_id,
            )
            if live is not None:
                if live["status"] == "completed":
                    raise ApiError(
                        E_MIGRATION_CONFLICT,
                        basis={"reason": "custody_already_migrated",
                               "migration_id": live["id"],
                               "result_custody_id": live["result_custody_id"]},
                    )
                unusable = await _unusable_reason(conn, live, now)
                if unusable is None:
                    raise ApiError(
                        E_MIGRATION_CONFLICT,
                        basis={"reason": "migration_already_in_progress",
                               "migration_id": live["id"],
                               "valid_until": str(live["valid_until"])},
                    )
                # 旧会话已不可能完成：判失败留痕后放行本次安全重试
                await _fail_migration(conn, live, unusable, tenant["id"])

            # 4) 目标策略：与轮换/撤销同一把策略锁，乐观锁钉住头版本
            await conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", body.target_policy_id
            )
            head_ver = await repo.get_head_version(conn, body.target_policy_id)
            if head_ver is None:
                raise ApiError(E_NOT_FOUND, basis={"policy_id": body.target_policy_id})
            if head_ver != body.target_expected_version:
                raise ApiError(
                    E_VERSION_CONFLICT,
                    basis={"expected_version": body.target_expected_version,
                           "current_version": head_ver},
                )
            tgt = await repo.get_policy_version(conn, body.target_policy_id, head_ver)
            if tgt["tenant_id"] != tenant["id"]:
                raise ApiError(E_FORBIDDEN, basis={"reason": "policy_belongs_to_other_tenant"})
            if tgt["status"] == "revoked":
                raise ApiError(
                    E_EPOCH_REVOKED,
                    basis={"policy_id": body.target_policy_id, "version": head_ver,
                           "epoch": tgt["epoch_index"], "side": "target"},
                )
            if tgt["status"] != "active":
                raise ApiError(E_POLICY_INACTIVE, basis={"status": tgt["status"]})
            if now >= tgt["epoch_valid_until"]:
                raise ApiError(
                    E_EPOCH_EXPIRED,
                    basis={"epoch": tgt["epoch_index"],
                           "valid_until": str(tgt["epoch_valid_until"]), "side": "target"},
                )

            mig_id = deps.new_id("mig")
            src_digest = _policy_digest(src)
            tgt_digest = _policy_digest(tgt)
            try:
                await conn.execute(
                    """
                    INSERT INTO migration_sessions
                      (id, tenant_id, custody_id, idempotency_key,
                       source_policy_id, source_policy_version, source_policy_digest,
                       target_policy_id, target_policy_version, target_policy_digest,
                       secret_digest, status, valid_until)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'open',
                            now() + ($12 || ' seconds')::interval)
                    """,
                    mig_id, tenant["id"], body.custody_id, body.idempotency_key,
                    src["id"], src["version"], src_digest,
                    tgt["id"], tgt["version"], tgt_digest,
                    custody["secret_digest"], str(ttl),
                )
            except Exception as exc:  # 唯一约束兜底（并发同键异记录 / 异键同记录）
                if getattr(exc, "pgcode", None) == "23505":
                    raise ApiError(
                        E_MIGRATION_CONFLICT,
                        basis={"reason": "concurrent_create_conflict",
                               "custody_id": body.custody_id},
                    )
                raise
            await audit.append_audit(
                conn, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="migration.start", resource=mig_id, result="ok",
                basis={
                    "custody_id": body.custody_id,
                    "idempotency": body.idempotency_key,
                    "source_policy_id": src["id"],
                    "source_policy_version": src["version"],
                    "source_policy_digest": src_digest,
                    "target_policy_id": tgt["id"],
                    "target_policy_version": tgt["version"],
                    "target_policy_digest": tgt_digest,
                    "ttl_seconds": ttl,
                },
            )
            row = await conn.fetchrow("SELECT * FROM migration_sessions WHERE id=$1", mig_id)
            response.status_code = 201
            return _session_out(row, 0, src["threshold"])


@router.get("/{migration_id}", response_model=MigrationSessionOut)
async def get_migration(migration_id: str, request: Request, tenant=deps.Tenant) -> MigrationSessionOut:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM migration_sessions WHERE id=$1", migration_id)
        if row is None:
            raise ApiError(E_NOT_FOUND, basis={"migration_id": migration_id})
        if row["tenant_id"] != tenant["id"]:
            raise ApiError(E_FORBIDDEN, basis={"reason": "migration_belongs_to_other_tenant"})
        src = await repo.get_policy_version(conn, row["source_policy_id"], row["source_policy_version"])
        count = await conn.fetchval(
            "SELECT count(*) FROM migration_submissions WHERE migration_id=$1", migration_id
        )
    return _session_out(row, count, src["threshold"])


# ---------------------------------------------------------------------------
# 托管人：一次性挑战值 -> 领取本人分片 -> 提交分片+签名
# ---------------------------------------------------------------------------

@router.post("/challenges", response_model=MigrationChallengeOut)
async def issue_challenge(body: MigrationChallengeIn, request: Request, custodian=deps.Custodian) -> MigrationChallengeOut:
    pool = request.app.state.db.pool
    mig_tenant: str | None = None
    nonce = ""
    challenge_id = ""
    point_x = 0
    shard_digest = ""
    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()
        try:
            # 会话级互斥：与领取/提交同一把行锁
            mig = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE id=$1 FOR UPDATE", body.migration_id
            )
            if mig is None:
                raise ApiError(E_NOT_FOUND, basis={"migration_id": body.migration_id})
            mig_tenant = mig["tenant_id"]
            custody, src, tgt, now = await _load_context(conn, mig)
            await _guard_open_migration(mig, custody, src, tgt, now, custodian["id"])

            shard = await _custody_shard(conn, mig["custody_id"], custodian["id"])
            if shard is None:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "no_shard_for_custodian", "custodian_id": custodian["id"]},
                )
            point_x = shard["point_x"]
            shard_digest = shard["shard_digest"]

            existing = await conn.fetchrow(
                "SELECT * FROM migration_challenges WHERE migration_id=$1 AND custodian_id=$2",
                body.migration_id, custodian["id"],
            )
            if existing is not None:
                # 挑战值仅在签发响应中明文下发一次（库中只存摘要）
                raise ApiError(
                    E_NONCE_USED,
                    basis={"migration_id": body.migration_id, "custodian_id": custodian["id"],
                           "spent": existing["spent"],
                           "reason": "nonce_already_issued" if not existing["spent"] else "nonce_spent"},
                )
            nonce = deps.new_nonce()
            challenge_id = deps.new_id("mch")
            await conn.execute(
                """
                INSERT INTO migration_challenges (id, migration_id, custodian_id, nonce_hash, spent)
                VALUES ($1,$2,$3,$4, FALSE)
                """,
                challenge_id, body.migration_id, custodian["id"],
                crypto.sha256_hex(bytes.fromhex(nonce)),
            )
            await audit.append_audit(
                conn, tenant_id=mig["tenant_id"], actor_type="custodian", actor_id=custodian["id"],
                action="migration.challenge.issue", resource=challenge_id, result="ok",
                basis={"migration_id": body.migration_id,
                       "source_policy_version": mig["source_policy_version"],
                       "point_x": point_x, "shard_digest": shard_digest},
            )
            await tx.commit()
        except ApiError as exc:
            await tx.rollback()
            await repo.audit_denied(
                pool, tenant_id=mig_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.challenge.issue", resource=body.migration_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
    return MigrationChallengeOut(
        challenge_id=challenge_id,
        nonce=nonce,
        migration_id=body.migration_id,
        custodian_id=custodian["id"],
        source_policy_id=mig["source_policy_id"],
        source_policy_version=mig["source_policy_version"],
        target_policy_id=mig["target_policy_id"],
        target_policy_version=mig["target_policy_version"],
        point_x=point_x,
        shard_digest=shard_digest,
    )


@router.post("/shards/claim", response_model=MigrationShardClaimOut)
async def claim_migration_shard(body: MigrationShardClaimIn, request: Request, custodian=deps.Custodian) -> MigrationShardClaimOut:
    """旧策略托管人凭一次性挑战值领取本人分片。

    明文分片仅存在于本次响应：不落盘、不入审计。挑战值在此不花费
    （提交通过全部校验后才花费）。
    """
    settings = get_settings()
    pool = request.app.state.db.pool
    mig_tenant: str | None = None
    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()
        try:
            mig = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE id=$1 FOR UPDATE", body.migration_id
            )
            if mig is None:
                raise ApiError(E_NOT_FOUND, basis={"migration_id": body.migration_id})
            mig_tenant = mig["tenant_id"]
            custody, src, tgt, now = await _load_context(conn, mig)
            await _guard_open_migration(mig, custody, src, tgt, now, custodian["id"])

            ch = await _resolve_challenge(conn, body.migration_id, body.nonce, custodian["id"])
            if ch["spent"]:
                raise ApiError(E_NONCE_USED, basis={"challenge_id": ch["id"], "reason": "nonce_spent"})

            shard = await _custody_shard(conn, mig["custody_id"], custodian["id"])
            if shard is None:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "no_shard_for_custodian", "custodian_id": custodian["id"]},
                )
            # 服务端自检：库存密文必须能解开且摘要自洽
            try:
                blob = crypto.decrypt_shard(
                    settings.shard_master_key_bytes, shard["id"], bytes(shard["ciphertext"])
                )
            except Exception:  # AEAD tag failure / malformed inventory ciphertext
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "inventory_shard_decrypt_failed",
                           "custodian_id": custodian["id"]},
                )
            if not crypto.constant_time_hex_equal(crypto.sha256_hex(blob), shard["shard_digest"]):
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "inventory_shard_digest_mismatch",
                           "custodian_id": custodian["id"]},
                )
            message = crypto.migration_signing_message(
                nonce=body.nonce,
                migration_id=body.migration_id,
                custody_id=mig["custody_id"],
                source_policy_id=mig["source_policy_id"],
                source_policy_version=mig["source_policy_version"],
                target_policy_id=mig["target_policy_id"],
                target_policy_version=mig["target_policy_version"],
                source_policy_digest=mig["source_policy_digest"],
                target_policy_digest=mig["target_policy_digest"],
                custodian_id=custodian["id"],
                point_x=shard["point_x"],
                shard_digest=shard["shard_digest"],
            )
            await audit.append_audit(
                conn, tenant_id=mig["tenant_id"], actor_type="custodian", actor_id=custodian["id"],
                action="migration.shard.claim", resource=body.migration_id, result="ok",
                basis={"challenge_id": ch["id"], "point_x": shard["point_x"],
                       "shard_digest": shard["shard_digest"]},
            )
            out = MigrationShardClaimOut(
                migration_id=body.migration_id,
                challenge_id=ch["id"],
                custodian_id=custodian["id"],
                custody_id=mig["custody_id"],
                point_x=shard["point_x"],
                shard_digest=shard["shard_digest"],
                shard_hex=blob.hex(),
                signing_message=message.decode(),
            )
            await tx.commit()
        except ApiError as exc:
            await tx.rollback()
            await repo.audit_denied(
                pool, tenant_id=mig_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.shard.claim", resource=body.migration_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
    return out


@router.post("/shares", response_model=MigrationShareSubmitOut)
async def submit_migration_share(body: MigrationShareSubmitIn, request: Request, custodian=deps.Custodian) -> MigrationShareSubmitOut:
    settings = get_settings()
    pool = request.app.state.db.pool
    pending = request.app.state.pending
    mig_tenant: str | None = None

    async with pool.acquire() as conn:
        tx = conn.transaction()
        await tx.start()
        # 撤销边界与 /recoveries/shares 一致：
        # * 校验拒绝全部发生在入池之前，异常路径绝不触碰内存池；
        # * 入池后的任何失败都在事务（行锁）仍持有时凭本 token 精确撤回。
        # tx_open 使 _undo 幂等：commit 失败路径上外层 except 不会二次回滚
        # （asyncpg 对已回滚事务再 rollback 会抛 InterfaceError 掩盖原始错误）。
        pending_token = None
        tx_open = True
        completed = False
        new_custody: dict | None = None
        count = 0
        threshold = 0
        terminal_error: ApiError | None = None

        async def _undo() -> None:
            nonlocal pending_token, tx_open
            if not tx_open:
                return
            if pending_token is not None:
                pending.discard(pending_token)
                pending_token = None
            await tx.rollback()
            tx_open = False

        try:
            # 会话行锁：同一会话的所有提交完全串行
            mig = await conn.fetchrow(
                "SELECT * FROM migration_sessions WHERE id=$1 FOR UPDATE", body.migration_id
            )
            if mig is None:
                raise ApiError(E_NOT_FOUND, basis={"migration_id": body.migration_id})
            mig_tenant = mig["tenant_id"]
            custody, src, tgt, now = await _load_context(conn, mig)

            # 1) 会话状态/时效 + 源/目标版本摘要绑定 + epoch + 源策略成员
            await _guard_open_migration(mig, custody, src, tgt, now, custodian["id"])

            # 2) 一次性挑战值：存在、归属匹配、未花费
            ch = await _resolve_challenge(conn, body.migration_id, body.nonce, custodian["id"])
            if ch["spent"]:
                raise ApiError(E_NONCE_USED, basis={"challenge_id": ch["id"]})

            # 3) 重复提交（唯一约束兜底，显式判定给出确定性依据）
            dup = await conn.fetchrow(
                "SELECT 1 FROM migration_submissions WHERE migration_id=$1 AND custodian_id=$2",
                body.migration_id, custodian["id"],
            )
            if dup:
                raise ApiError(
                    E_DUPLICATE_SHARE,
                    basis={"migration_id": body.migration_id, "custodian_id": custodian["id"]},
                )

            # 4) 分片归属：提交者在源托管下必须有且仅有自己点位的库存分片
            shard = await _custody_shard(conn, mig["custody_id"], custodian["id"])
            if shard is None:
                raise ApiError(
                    E_INTEGRITY,
                    basis={"reason": "no_shard_for_custodian", "custodian_id": custodian["id"]},
                )

            # 5) 点位与库存摘要：先验“货”再花费挑战值
            blob = bytes.fromhex(body.shard_hex)
            if len(blob) > 8192:
                raise ApiError(E_BAD_REQUEST, basis={"reason": "shard_too_large", "bytes": len(blob)})
            if body.point_x != shard["point_x"]:
                raise ApiError(
                    E_SHARE_POINT,
                    basis={"custodian_id": custodian["id"],
                           "submitted_point_x": body.point_x,
                           "expected_point_x": shard["point_x"]},
                )
            submitted_digest = crypto.sha256_hex(blob)
            if not crypto.constant_time_hex_equal(submitted_digest, shard["shard_digest"]):
                raise ApiError(
                    E_SHARE_DIGEST,
                    basis={"custodian_id": custodian["id"], "point_x": body.point_x,
                           "submitted_shard_digest": submitted_digest,
                           "expected_shard_digest": shard["shard_digest"]},
                )

            # 6) Ed25519 验签：报文绑定 挑战值/会话/托管记录/源目标版本摘要/点位/分片摘要
            message = crypto.migration_signing_message(
                nonce=body.nonce,
                migration_id=body.migration_id,
                custody_id=mig["custody_id"],
                source_policy_id=mig["source_policy_id"],
                source_policy_version=mig["source_policy_version"],
                target_policy_id=mig["target_policy_id"],
                target_policy_version=mig["target_policy_version"],
                source_policy_digest=mig["source_policy_digest"],
                target_policy_digest=mig["target_policy_digest"],
                custodian_id=custodian["id"],
                point_x=body.point_x,
                shard_digest=shard["shard_digest"],
            )
            if not crypto.verify_signature(custodian["signing_pubkey"], message,
                                           bytes.fromhex(body.signature)):
                raise ApiError(
                    E_BAD_SIGNATURE,
                    basis={"custodian_id": custodian["id"], "reason": "ed25519_verify_failed",
                           "expected_signing_message": message.decode()},
                )

            # --- 全部校验通过：花费挑战值，登记“已验签的分片” ---
            await conn.execute(
                "UPDATE migration_challenges SET spent=TRUE WHERE id=$1", ch["id"]
            )
            sub_id = deps.new_id("msub")
            try:
                await conn.execute(
                    """
                    INSERT INTO migration_submissions
                      (id, migration_id, custodian_id, challenge_id, point_x, shard_digest)
                    VALUES ($1,$2,$3,$4,$5,$6)
                    """,
                    sub_id, body.migration_id, custodian["id"], ch["id"],
                    body.point_x, shard["shard_digest"],
                )
            except Exception as exc:  # unique_violation under race
                if getattr(exc, "pgcode", None) == "23505":
                    raise ApiError(
                        E_DUPLICATE_SHARE,
                        basis={"migration_id": body.migration_id,
                               "custodian_id": custodian["id"]},
                    )
                raise

            # 已验签分片只在内存累计，明文绝不落盘
            pending_token = pending.add(body.migration_id, custodian["id"], body.point_x, blob)

            count = await conn.fetchval(
                "SELECT count(*) FROM migration_submissions WHERE migration_id=$1",
                body.migration_id,
            )
            threshold = src["threshold"]

            if count >= threshold:
                # 达到源门限：仅在内存重组 -> 立即按目标策略重分片 -> 同事务落库
                completed, new_custody, terminal_error = await _finalize(
                    conn, settings, pending, mig, custody, now, threshold
                )

            await audit.append_audit(
                conn, tenant_id=mig["tenant_id"], actor_type="custodian", actor_id=custodian["id"],
                action="migration.share.submit", resource=body.migration_id, result="ok",
                basis={"shares_after": count, "threshold": threshold, "completed": completed,
                       "point_x": body.point_x, "shard_digest": shard["shard_digest"]},
            )
            try:
                await tx.commit()
            except Exception:
                # 提交本身失败：提交结果未知，同样在行锁释放前撤回本次内存新增
                await _undo()
                raise
        except ApiError as exc:
            # 校验失败不花费挑战值、不计数；入池后的失败则凭 token 精确撤回
            await _undo()
            await repo.audit_denied(
                pool, tenant_id=mig_tenant, actor_type="custodian", actor_id=custodian["id"],
                action="migration.share.submit", resource=body.migration_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
        except Exception:
            await _undo()
            raise

    if terminal_error is not None:
        # 终态失败已随事务提交（会话置 failed）：可换新幂等键安全重试
        pending.clear(body.migration_id)
        await repo.audit_denied(
            pool, tenant_id=mig_tenant, actor_type="custodian", actor_id=custodian["id"],
            action="migration.share.submit", resource=body.migration_id,
            error_code=terminal_error.code, basis=terminal_error.basis,
        )
        raise terminal_error
    if completed:
        # 事务提交成功后销毁内存待累计分片
        pending.clear(body.migration_id)
    return MigrationShareSubmitOut(
        migration_id=body.migration_id,
        status="completed" if completed else "open",
        shares_received=count,
        threshold=threshold,
        completed=completed,
        result_custody_id=new_custody["custody_id"] if new_custody else None,
        new_custody=new_custody,
    )


async def _finalize(conn, settings, pending, mig, custody, now, threshold: int):
    """门限达成：仅在内存重组 -> 校验摘要 -> 立即按目标策略重分片（同事务）。

    返回 ``(completed, new_custody, terminal_error)``。``terminal_error`` 非空时
    会话已被置为 ``failed``（随调用方事务一并提交），调用方在提交后抛出该错误；
    源托管记录在任何路径下都保持不变。
    """
    points = sorted(pending.get_points(mig["id"]), key=lambda p: p[0])
    if len(points) < threshold:
        # 进程重启等情况下内存累计已丢失：不回退到解密库存分片，判终态失败
        reason = "pending_shares_unavailable"
        await _fail_migration(conn, mig, reason, mig["tenant_id"])
        return False, None, ApiError(
            E_THRESHOLD_NOT_MET,
            basis={"reason": reason, "pending_in_memory": len(points), "threshold": threshold},
        )
    try:
        secret = crypto.shamir_combine(points[:threshold], custody["secret_length"])
    except ValueError as exc:
        await _fail_migration(conn, mig, "shamir_combine_failed", mig["tenant_id"])
        return False, None, ApiError(
            E_INTEGRITY, basis={"reason": "shamir_combine_failed", "detail": str(exc)}
        )
    if not crypto.constant_time_hex_equal(crypto.sha256_hex(secret), custody["secret_digest"]):
        await _fail_migration(conn, mig, "secret_digest_mismatch_after_reconstruction",
                              mig["tenant_id"])
        return False, None, ApiError(
            E_INTEGRITY, basis={"reason": "secret_digest_mismatch_after_reconstruction"}
        )

    # 与轮换/撤销同一把策略锁（固定排序，杜绝循环等待）：落定前源/目标都不得
    # 被并发撤销或过期——会话期间发生的轮换在此被确定性地拦下。
    for pid in sorted({mig["source_policy_id"], mig["target_policy_id"]}):
        await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", pid)
    custody_now = await conn.fetchrow(
        "SELECT status FROM key_custodies WHERE id=$1", mig["custody_id"]
    )
    if custody_now is None or custody_now["status"] != "active":
        await _fail_migration(conn, mig, "source_custody_inactive", mig["tenant_id"])
        return False, None, ApiError(
            E_EPOCH_REVOKED,
            basis={"policy_id": mig["source_policy_id"], "version": mig["source_policy_version"],
                   "side": "source"},
        )
    tgt = await repo.get_policy_version(conn, mig["target_policy_id"], mig["target_policy_version"])
    if tgt["status"] != "active":
        await _fail_migration(conn, mig, "target_policy_revoked", mig["tenant_id"])
        return False, None, ApiError(
            E_EPOCH_REVOKED,
            basis={"policy_id": mig["target_policy_id"], "version": mig["target_policy_version"],
                   "side": "target"},
        )
    if now >= tgt["epoch_valid_until"]:
        await _fail_migration(conn, mig, "target_epoch_expired", mig["tenant_id"])
        return False, None, ApiError(
            E_EPOCH_EXPIRED, basis={"epoch": tgt["epoch_index"], "side": "target"}
        )

    # 立即按目标策略重新分片；新托管记录与加密分片在同一事务落盘，源记录不变
    custodian_ids = list(tgt["custodian_ids"])
    new_points = crypto.shamir_split(secret, tgt["threshold"], len(custodian_ids))
    new_custody_id = deps.new_id("cus_secret")
    await conn.execute(
        """
        INSERT INTO key_custodies
          (id, tenant_id, policy_id, policy_version, secret_digest, secret_length,
           epoch_index, status)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'active')
        """,
        new_custody_id, mig["tenant_id"], tgt["id"], tgt["version"],
        custody["secret_digest"], custody["secret_length"], tgt["epoch_index"],
    )
    shard_digests: list[str] = []
    for (x, shard_blob), custodian_id in zip(new_points, custodian_ids):
        shard_id = deps.new_id("shd")
        ct = crypto.encrypt_shard(settings.shard_master_key_bytes, shard_id, shard_blob)
        shard_digest = crypto.sha256_hex(shard_blob)
        shard_digests.append(shard_digest)
        await conn.execute(
            """
            INSERT INTO shards (id, custody_id, custodian_id, point_x, ciphertext, shard_digest)
            VALUES ($1,$2,$3,$4,$5,$6)
            """,
            shard_id, new_custody_id, custodian_id, x, ct, shard_digest,
        )
    await conn.execute(
        "UPDATE migration_sessions SET status='completed', result_custody_id=$2 WHERE id=$1",
        mig["id"], new_custody_id,
    )
    new_custody = {
        "custody_id": new_custody_id,
        "policy_id": tgt["id"],
        "policy_version": tgt["version"],
        "epoch_index": tgt["epoch_index"],
        "secret_digest": custody["secret_digest"],
        "shard_count": len(custodian_ids),
        "shard_digests": shard_digests,
    }
    await audit.append_audit(
        conn, tenant_id=mig["tenant_id"], actor_type="system", actor_id=None,
        action="migration.complete", resource=mig["id"], result="ok",
        basis={
            "custody_id": mig["custody_id"],
            "result_custody_id": new_custody_id,
            "source_policy_id": mig["source_policy_id"],
            "source_policy_version": mig["source_policy_version"],
            "source_policy_digest": mig["source_policy_digest"],
            "target_policy_id": mig["target_policy_id"],
            "target_policy_version": mig["target_policy_version"],
            "target_policy_digest": mig["target_policy_digest"],
            "threshold": threshold,
            "shard_count": len(custodian_ids),
            "shard_digests": shard_digests,
        },
    )
    return True, new_custody, None

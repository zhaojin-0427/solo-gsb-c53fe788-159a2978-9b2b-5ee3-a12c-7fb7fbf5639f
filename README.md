# 多方密钥分片托管与门限恢复 API

租户把待托管密钥交给服务后，服务按 **Shamir 门限秘密分享 (n-of-m)** 切成多份，每份独立加密落盘，
任何单一托管人（甚至数据库运维）都无法还原秘密。恢复时托管人须**先经身份验证领取本人分片**，
再对**一次性 nonce + 会话 + 策略版本 + 托管人 + 分片点位 + 分片摘要**签名，连同**自己的分片字节**
一并提交；服务校验**分片归属、点位与库存摘要**通过后才花费 nonce 并计数。达到门限后，秘密**只由
这些已验签的提交分片在请求内存中重组**（服务端不再解密自己的库存分片来凑数），并用恢复方临时公钥
包装成**一次性密文**返回。

**跨策略密钥迁移（v1.4）**：租户可为仍有效的托管记录指定另一条有效策略版本，以**幂等键**创建迁移
会话；旧策略托管人按**一次性挑战值**领取并提交本人分片及签名（签名绑定**源/目标策略版本摘要**）。
达到**源门限**后，服务**仅在内存重组**秘密，立即按目标策略**重新分片**，在**同一事务**写入新托管
记录（分片独立加密落盘）并返回其标识——**源托管记录保持不变**，响应、数据库与审计均不出现明文。
同一托管记录至多一个未失败迁移会话：**不同幂等键不得重复迁移**；撤销/过期/跨租户/并发重复均被
确定性拒绝；终态失败（如会话期间目标被轮换）留可重放审计，可换新幂等键**安全重试**。

技术栈：Python 3.12 · FastAPI · PostgreSQL 16 · `cryptography` · Docker Compose。

> **新增（v1.4）**：跨策略密钥迁移 API（`/migrations`）。
> * 创建：`POST /migrations` 以 `idempotency_key` 幂等创建——同键同参重放返回原会话（200），
>   同键异参 409；同一托管记录在任意时刻至多一个 `open/completed` 会话（部分唯一索引 +
>   每托管记录咨询锁，并发重复恰一个成功）。
> * 托管人流程与恢复同构：`POST /migrations/challenges` 领一次性挑战值 →
>   `POST /migrations/shards/claim` 领本人分片（明文仅本次响应）→ Ed25519 签名
>   `keyvault.migration.share.v1` 报文（绑定挑战值/会话/托管记录/**源目标版本摘要**/点位/分片摘要）
>   → `POST /migrations/shares` 提交。
> * 达到源门限的那一次提交：内存重组 → 校验 `secret_digest` → 按目标策略重新 Shamir 分片 →
>   同事务写入新 `key_custodies` + 加密分片 + 会话置 `completed` → 响应只含新 `custody_id` 与
>   分片摘要。落定前持源/目标策略锁复检双方仍有效（会话期间的轮换/撤销/过期使会话终态失败）。
> * 终态失败（`failed`）后可换新幂等键安全重试；过期或源/目标失效的旧会话在新建时被确定性
>   判失败并留 `migration.failed` 审计。全程无明文：重组秘密只存在于请求内存，新分片
>   AES-256-GCM 加密落盘，审计只记 ID/版本/摘要/计数。
> * 验收覆盖：`scripts/demo.py` 迁移段落 48 项断言（幂等重放/异键冲突/跨租户/撤销/过期/
>   并发双发/会话中轮换后安全重试/迁移结果可按目标策略恢复且源记录不变），
>   `scripts/race_recovery.py` 的 `M1` 场景 8 项断言（模拟重启丢失内存分片后的终态失败与重试）。
>
> **修复要点（v1.3）**：修复 `/recoveries/shares` 在“分片**已入内存池之后**异常回滚”时的交错竞态
> （重组失败、审计写入失败、连接中止等）。旧代码在异常路径上**先 `ROLLBACK` 释放会话行锁、
> 再移除本次内存分片**：① 同会话正在锁队列里等待的请求可能在这一瞬间读到未提交分片；
> ② 同一托管人重试先成功入池时，旧请求随后的无条件 `remove(custodian)` 会**误删掉新分片**——
> 数据库计数保留、内存缺片，后续门限满足时报 `THRESHOLD_NOT_MET`，会话被永久卡死。
> 现划定双重撤销边界：
> 1. **顺序**：异常路径在事务仍打开（行锁仍持有）时先撤回本次内存分片，再 `ROLLBACK`——
>    等待者拿锁时内存池与数据库已重新一致，绝不可能读到未提交分片；
> 2. **凭证**：`pending.add()` 返回仅属于本次插入的 token，回滚只能 `discard(本 token)`，
>    即使撤销顺序被任何改动意外打破，旧请求也无法删除同托管人成功重试产生的新分片。
>
> 由此保证：并发重试后重组**只使用已提交且验签通过的分片**（服务端绝不拿库存分片凑数），
> 门限达成只发生一次，**一次性密文只下发一次**；确定性校验拒绝（验签/点位/摘要/nonce 等）
> 全发生在入池之前，异常路径根本不触碰内存池。可精确钉住该交错的回归验证见
> `scripts/race_recovery.py`（38 项断言，`regression/R1·R2·R4·R5/U1`），
> 与原有 `scripts/demo.py` 一起由 demo 容器一键执行。
>
> **修复要点（v1.2）**：修复 `/recoveries/shares` 的跨请求状态损坏。旧实现的拒绝路径无条件
> 从内存分片池移除“本托管人”的分片：未达门限的会话已接受某托管人的有效分片后，该托管人重放
> 已花费 nonce（返回 `NONCE_ALREADY_USED`）会把**先前已验签的内存分片**一并删掉，而数据库提交
> 计数保留——随后其他托管人补足门限时内存分片不足，得到 `THRESHOLD_NOT_MET`，会话被永久卡死。
> 现明确提交事务与进程内分片池的撤销边界：**校验拒绝发生在分片入池之前，绝不触碰已提交分片；
> 事务回滚只撤回本次请求新增的分片**。并发重放与合法提交交错时，数据库计数与内存内容始终对应，
> 门限满足时仅用已验签分片重组、密文只下发一次。同批修正若干拒绝路径上 `ApiError` 的位置参数
> 调用（会把确定性 4xx 拒绝变成 500）。回归验证见 `scripts/demo.py` 中 `regression:` 前缀用例。
>
> **修复要点（v1.1）**：旧实现里托管人取得 nonce 后只交签名、不交分片也会计入份额，凑满门限即由
> 服务端解密库存分片重组——托管人无需真正持有自己的分片即可“代表”本人。现改为**凭本人已领取分片
> 的点位与字节提交**，签名绑定该分片摘要；归属/点位/库存摘要校验全部通过后才花费 nonce 计数，
> 待累计分片只在内存中保存、绝不明文落盘。

---

## 1. 一键启动

```bash
docker compose up --build
```

- API：<http://localhost:8000>
- Swagger 交互文档：<http://localhost:8000/docs>
- OpenAPI JSON：<http://localhost:8000/openapi.json>
- 健康检查：<http://localhost:8000/health>
- PostgreSQL：`localhost:5432`（用户/库/密码均为 `keyvault`）

首次启动会自动建表并写入一组**演示身份**（1 个租户 + 3 个托管人，仅用于本地联调，密钥是确定性的，
**严禁用于生产**）。演示凭据可随时打印：

```bash
docker compose exec api python -m app.seed
```

生产部署通过环境变量覆盖（见 `.env.example`）：

| 变量 | 说明 |
| --- | --- |
| `KEYVAULT_DATABASE_URL` | PostgreSQL DSN |
| `KEYVAULT_SHARD_MASTER_KEY` | ≥32 字节字符串或 64 位 hex，用于 HKDF 派生分片加密密钥 |
| `KEYVAULT_ADMIN_API_KEY` | 管理端注册身份用的 API Key |
| `KEYVAULT_RECOVERY_DEFAULT_TTL` / `KEYVAULT_RECOVERY_MAX_TTL` | 恢复/迁移会话默认/上限 TTL（秒） |
| `KEYVAULT_FAULT_INJECTION` | 仅测试：`1` 开启并发交错故障注入闸门；默认 `0`（关闭时零开销，切勿在生产开启） |

---

## 2. 快速体验（端到端）

容器自带完整验收脚本，覆盖正常恢复、每一种拒绝依据、并发竞态、跨策略迁移全流程与审计链重放：

```bash
# 1) 并发回滚竞态回归（scripts.race_recovery，46 项，含迁移终态失败重试 M1）
# 2) 端到端验收（scripts.demo，112 项，含跨策略迁移 48 项）
docker compose --profile demo run --rm demo
```

期望依次输出 `RACE REGRESSION CHECKS PASSED` 与 `ALL CHECKS PASSED`。

`scripts.race_recovery.py` 在进程内以真实 ASGI + 真实 PostgreSQL 行锁运行，通过仅测试构建启用的
故障注入闸门（`KEYVAULT_FAULT_INJECTION=1`，API 服务默认关闭、关闭时零开销）精确钉住交错点：
一个请求的已验签分片已入内存池、行锁仍持有时注入重组/审计/连接类失败，另一个请求正排队等待行锁；
断言**未提交分片在行锁释放前撤回**、等待者读不到它、同托管人重试的新分片不会被旧回滚误删，
且门限只按已提交且验签的分片达成一次、密文只下发一次。本地单独运行：

```bash
KEYVAULT_FAULT_INJECTION=1 \
KEYVAULT_DATABASE_URL=postgresql://keyvault:keyvault@localhost:5432/keyvault \
python -m scripts.race_recovery
```

以下用 curl 走一遍核心流程（演示凭据见 `python -m app.seed` 输出）：

```bash
TENANT=tsec_01ea27eafbe8e5c6c1fb1c6a4f9c18b5ae9a3a4b6d7e8f9a0b1c2d3e4f506172   # 以实际输出为准
ADMIN=admin-dev-key

# 2.1 管理员创建托管人（已由 seed 预置 alice/bob/carol，也可新建）
curl -s -X POST localhost:8000/admin/custodians -H "X-API-Key: $ADMIN" \
  -H 'Content-Type: application/json' -d '{"name":"dave"}'
# -> custodian_id / api_key / signing_private_key(仅返回一次) / signing_public_key

# 2.2 创建不可变策略 2-of-3，带 epoch 有效期与轮换间隔
curl -s -X POST localhost:8000/policies -H "X-API-Key: $TENANT" -H 'Content-Type: application/json' -d '{
  "policy_id": "pol_main",
  "threshold": 2,
  "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
  "epoch": {"valid_from":"2026-01-01T00:00:00Z","valid_until":"2030-01-01T00:00:00Z","rotation_interval":0}
}'

# 2.3 托管密钥（hex），服务立即 Shamir 分片 + AES-GCM 加密落盘
curl -s -X POST localhost:8000/custodies -H "X-API-Key: $TENANT" -H 'Content-Type: application/json' -d '{
  "policy_id":"pol_main","expected_version":1,"secret_hex":"7468652d736563726574"}'
# -> custody_id、secret_digest、各分片 shard_digest（响应不含任何明文）

# 2.4 租户凭申请摘要 + 恢复方 X25519 公钥发起恢复会话（绑定策略版本，带过期时间）
curl -s -X POST localhost:8000/recoveries -H "X-API-Key: $TENANT" -H 'Content-Type: application/json' -d '{
  "custody_id":"cus_secret_...",
  "request_digest":"<sha256(ticket|purpose)>",
  "recovery_public_key":"<32B X25519 公钥 hex>",
  "ttl_seconds": 300
}'

# 2.5 托管人领取一次性 nonce（返回 nonce、本人分片点位与分片摘要；此时还没有签名报文）
curl -s -X POST localhost:8000/recoveries/nonces \
  -H "X-API-Key: $CUSTODIAN_KEY" -H 'Content-Type: application/json' \
  -d '{"session_id":"rec_..."}'
# -> nonce + point_x + shard_digest（绑定 custodian/policy/version/session）

# 2.6 托管人凭该 nonce 领取“本人分片”（明文仅在本次响应出现，服务端不落盘、不入审计）
curl -s -X POST localhost:8000/recoveries/shards/claim \
  -H "X-API-Key: $CUSTODIAN_KEY" -H 'Content-Type: application/json' \
  -d '{"session_id":"rec_...","nonce":"..."}'
# -> point_x / shard_hex / shard_digest / signing_message
#    signing_message 绑定 nonce+会话+策略版本+托管人+点位+分片摘要

# 2.7 托管人用 Ed25519 私钥对 signing_message 签名，连同点位与分片字节提交；
#     归属/点位/库存摘要/验签全部通过才花费 nonce；达到门限的那一次返回一次性密文
curl -s -X POST localhost:8000/recoveries/shares \
  -H "X-API-Key: $CUSTODIAN_KEY" -H 'Content-Type: application/json' \
  -d '{"session_id":"rec_...","nonce":"...","point_x":1,
       "shard_hex":"<领取到的本人分片 hex>","signature":"<64B ed25519 hex>"}'
# -> completed=true 时附带 wrap：X25519 临时 ECDH + HKDF-SHA256 + AES-256-GCM
```

客户端解包（Python 示例见 `scripts/demo.py` 的 `unwrap()`）：用本地 X25519 私钥与
`wrap.ephemeral_public_key` 做 ECDH，HKDF 的 info 为 `b"KWR1" + aad`，AAD 即响应中的 `aad`
（内含 session/policy/version/epoch/request_digest，防密文被挪用）。

### 2.8 托管人领取与提交分片（分步说明）

恢复不是“签个名就行”，托管人必须真正交出自己的分片，步骤固定为 **nonce → claim → sign → submit**：

1. **领 nonce**：`POST /recoveries/nonces`，仅会话成员、且会话处于 open 且未过期时可领。
   响应含 `nonce`、该托管人在此托管下的 `point_x` 与 `shard_digest`（每会话每人至多一张，明文仅此次下发）。
2. **领本人分片**：`POST /recoveries/shards/claim`，携带 `session_id + nonce`。
   服务端校验身份、会话状态、nonce 归属与未花费后，解密**该托管人名下**的库存分片，自检摘要自洽，
   返回 `shard_hex`（明文仅存在于这一次 HTTPS 响应）与待签名的 `signing_message`。
   - nonce 未花费前可重复领取（幂等，返回同一片）；nonce 一旦花费，领取返回 `NONCE_ALREADY_USED`。
   - 不属于该策略版本 / nonce 不属于本人或会话 / 会话已完成或过期，一律拒绝，拿不到分片。
3. **本地签名**：对 `signing_message`（`keyvault.share.v2`，逐行绑定
   custodian/policy/version/session/nonce/**point**/**shard_digest**）做 Ed25519 签名。
4. **提交分片**：`POST /recoveries/shares`，携带 `nonce + point_x + shard_hex + signature`。
   服务端依次校验：会话/epoch 状态 → nonce 归属与未花费 → 未重复提交 → **分片归属**（该托管人名下确有其片）
   → **点位一致** → **`sha256(shard_hex)` 与库存 `shard_digest` 一致** → Ed25519 验签；
   **全部通过才花费 nonce 并计数**。点位不符返回 `SHARE_POINT_MISMATCH`，字节被改返回
   `SHARE_DIGEST_MISMATCH`，验签失败返回 `BAD_SIGNATURE`——三者都**不花费 nonce**，basis 给出确定性事实。
5. **门限重组**：有效提交数达到门限时，服务端只用**这些已验签的提交分片**在内存中插值重组，
   校验 `secret_digest` 后包装成一次性密文；同事务把会话置 `completed`，并立即销毁内存中的待累计分片。
   重复提交、会话撤销/过期、并发双发都只会得到拒绝，密文**全局只下发一次**。

**异常与重试语义**（客户端可据此安全重试）：

- 验签/点位/摘要/nonce/重复/会话状态等**确定性拒绝**全部发生在花费 nonce 与分片入池**之前**：
  nonce 未花费、计数不变、内存池不被触碰，客户端修正后用同一 nonce 重试即可。
- 分片入池**之后**才可能失败的环节（门限重组、审计写入、连接中止）一律在**会话行锁仍持有时**
  先凭本次插入凭证撤回内存分片，再回滚事务释放锁：等待锁的并发请求拿锁时内存与数据库计数必然一致，
  读不到任何未提交分片；同托管人的重试即使先成功，旧请求的回滚也只能撤回自己的插入，**绝不会误删
  新分片**。因此任何 4xx/500 之后，调用方查询 `GET /recoveries/{id}` 看到的 `shares_received`
  就是内存中可用于重组的已验签分片数——重试只会得到干净结果，不会出现 `THRESHOLD_NOT_MET` 卡死。
- nonce 已花费后该 nonce 不可再用；需要继续补片时沿用已领取的其他 nonce，或另开恢复会话。
- 进程重启丢失内存待累计分片时，达到门限的提交返回确定性的 `THRESHOLD_NOT_MET`
  （basis.reason=`pending_shares_unavailable`），此时另开恢复会话重来。

> 待累计分片**只存进程内存**（`app/pending.py`），不写库、不写日志、不进审计；进程重启后内存清空，
> 已计数的会话无法继续重组，需另开恢复会话（提交接口此时返回 `THRESHOLD_NOT_MET`，basis.reason 为
> `pending_shares_unavailable`）。这是本演示基线在“明文不落盘”与“多副本部署”之间的明确取舍。

轮换 / 撤销：

```bash
# 原子推进到 v2（乐观锁 expected_version；可同时改托管集合/门限/epoch）
curl -s -X POST localhost:8000/policies/pol_main/rotate -H "X-API-Key: $TENANT" \
  -H 'Content-Type: application/json' \
  -d '{"expected_version":1,"epoch":{"valid_from":"2027-01-01T00:00:00Z",
        "valid_until":"2031-01-01T00:00:00Z","rotation_interval":0}}'

# 撤销当前 epoch（原子；之后新托管/恢复一律 EPOCH_REVOKED）
curl -s -X POST localhost:8000/policies/pol_main/revoke -H "X-API-Key: $TENANT" \
  -H 'Content-Type: application/json' -d '{"expected_version":2}'

# 审计哈希链按序重放并自校验
curl -s localhost:8000/audit/replay -H "X-API-Key: $TENANT"
```

### 2.9 跨策略密钥迁移

把一条仍有效的托管记录迁移到另一条有效策略版本（换托管集合/门限/epoch），
秘密全程只在服务内存中重组、立即重分片，任何响应/落盘/审计都不含明文：

```bash
# 2.9.1 目标策略（可以是不同的托管集合与门限；此处 3-of-3）
curl -s -X POST localhost:8000/policies -H "X-API-Key: $TENANT" -H 'Content-Type: application/json' -d '{
  "policy_id": "pol_next",
  "threshold": 3,
  "custodian_ids": ["cus_demo_alice", "cus_demo_bob", "cus_demo_carol"],
  "epoch": {"valid_from":"2026-01-01T00:00:00Z","valid_until":"2032-01-01T00:00:00Z","rotation_interval":0}
}'

# 2.9.2 以幂等键创建迁移会话（绑定源/目标版本摘要；target_expected_version 乐观锁）
curl -s -X POST localhost:8000/migrations -H "X-API-Key: $TENANT" -H 'Content-Type: application/json' -d '{
  "custody_id": "cus_secret_...",
  "target_policy_id": "pol_next",
  "target_expected_version": 1,
  "idempotency_key": "migrate-2026-09-0001",
  "ttl_seconds": 300
}'
# -> 201: migration_id、source/target_policy_digest、threshold（源门限）、valid_until
#    相同幂等键+相同参数重发 -> 200 返回同一会话（安全重试创建）；
#    换幂等键再迁同一托管记录 -> 409 MIGRATION_CONFLICT

# 2.9.3 旧（源）策略托管人领取一次性挑战值（返回本人分片点位与摘要）
curl -s -X POST localhost:8000/migrations/challenges \
  -H "X-API-Key: $CUSTODIAN_KEY" -H 'Content-Type: application/json' \
  -d '{"migration_id":"mig_..."}'
# -> nonce + point_x + shard_digest（每会话每人至多一张，库中只存摘要）

# 2.9.4 凭挑战值领取本人分片（明文仅本次响应）与待签名报文
curl -s -X POST localhost:8000/migrations/shards/claim \
  -H "X-API-Key: $CUSTODIAN_KEY" -H 'Content-Type: application/json' \
  -d '{"migration_id":"mig_...","nonce":"..."}'
# -> shard_hex + signing_message（keyvault.migration.share.v1，绑定
#    挑战值/会话/托管记录/源目标版本摘要/点位/分片摘要）

# 2.9.5 托管人本地 Ed25519 签名后提交本人分片；达到源门限的那一次返回新托管记录标识
curl -s -X POST localhost:8000/migrations/shares \
  -H "X-API-Key: $CUSTODIAN_KEY" -H 'Content-Type: application/json' \
  -d '{"migration_id":"mig_...","nonce":"...","point_x":1,
       "shard_hex":"<领取到的本人分片 hex>","signature":"<64B ed25519 hex>"}'
# -> completed=true 时：result_custody_id + new_custody（policy/version/secret_digest/
#    shard_digests，绝不含明文）；源托管记录保持 active 不变

# 2.9.6 查询迁移状态（shares_received / status / result_custody_id / fail_reason）
curl -s localhost:8000/migrations/mig_... -H "X-API-Key: $TENANT"
```

迁移的异常与重试语义：

- 验签/点位/摘要/挑战值/重复提交等**确定性拒绝**全部发生在花费挑战值与分片入池**之前**，
  客户端修正后用同一挑战值重试即可（与恢复流同一套撤销边界）。
- 达到门限后的终态失败（进程重启丢失内存待累计分片 `pending_shares_unavailable`、
  重组校验失败、源/目标在会话期间被轮换撤销或过期）会把会话置 `failed` 并写
  `migration.failed` 审计——**换新幂等键**重新创建即可安全重试；过期或已失效的旧会话
  会在新建时被自动判失败放行重试。
- 迁移完成后该托管记录不可再迁移（`MIGRATION_CONFLICT`）；如需继续迁移，应对**新**托管
  记录发起新的迁移会话。

---

## 3. API 总览

| 方法 & 路径 | 调用方 | 说明 |
| --- | --- | --- |
| `POST /admin/tenants` | admin | 注册租户，返回 API Key（仅一次） |
| `POST /admin/custodians` | admin | 注册托管人，返回 API Key 与 Ed25519 签名私钥（仅一次） |
| `POST /policies` | 租户 | 创建不可变策略 v1：n-of-m、epoch、轮换间隔 |
| `GET /policies/{id}?version=` | 租户 | 读取头版本或任意历史版本（版本永不修改） |
| `POST /policies/{id}/rotate` | 租户 | 原子推进版本（写入新版本 + 旧版本置 revoked + 头指针前移） |
| `POST /policies/{id}/revoke` | 租户 | 原子撤销当前 epoch |
| `POST /custodies` | 租户 | 提交待托管密钥，返回 custody_id 与各分片摘要 |
| `POST /recoveries` | 租户 | 创建恢复会话（绑定策略版本 + 申请摘要 + TTL） |
| `GET /recoveries/{id}` | 租户 | 查询会话状态与已收份额数 |
| `POST /recoveries/nonces` | 托管人 | 领取一次性 nonce（含本人分片点位与摘要） |
| `POST /recoveries/shards/claim` | 托管人 | 验身份后领取**本人分片**明文 + 待签名报文（绑定 nonce） |
| `POST /recoveries/shares` | 托管人 | 提交**本人分片点位+字节**与 Ed25519 签名；门限满足时返回一次性密文 |
| `POST /migrations` | 租户 | 以幂等键创建跨策略迁移会话（绑定源/目标版本摘要；同键重放返回原会话） |
| `GET /migrations/{id}` | 租户 | 查询迁移会话状态、已收份额、结果托管记录与失败原因 |
| `POST /migrations/challenges` | 托管人 | 领取迁移一次性挑战值（含本人分片点位与摘要） |
| `POST /migrations/shards/claim` | 托管人 | 凭挑战值领取**本人分片**明文 + 迁移签名报文（绑定源/目标版本摘要） |
| `POST /migrations/shares` | 托管人 | 提交本人分片+签名；达源门限时内存重组并按目标策略重分片，返回新托管记录标识 |
| `GET /audit/replay` | 租户 | 重放哈希链并验证完整性 |

所有拒绝响应结构统一且确定性：

```json
{"error": {"code": "NONCE_ALREADY_USED",
           "message": "nonce has already been spent",
           "basis": {"nonce_id": "non_...", "...": "机器可判定的事实依据"}}}
```

调用方应依据 `code`（稳定）而非 `message`（可读）做分支。

| code | 含义 |
| --- | --- |
| `VALIDATION_FAILED` / `BAD_REQUEST` | 报文格式/取值非法（basis.fields 给出字段级原因） |
| `UNAUTHORIZED` / `FORBIDDEN` | 缺 Key、Key 无效或资源属于其他租户 |
| `NOT_FOUND` | 资源不存在 |
| `POLICY_PARAMS_INVALID` | 不满足 1 ≤ threshold ≤ 托管人数 |
| `VERSION_CONFLICT` | `expected_version` 与当前头版本不符（乐观锁） |
| `POLICY_INACTIVE` | 头版本已撤销，不能再轮换 |
| `EPOCH_REVOKED` / `EPOCH_EXPIRED` | epoch 已撤销 / 已过 `valid_until` |
| `NONCE_ALREADY_USED` | nonce 重复领取、已花费或持已花费 nonce 再领片（一次性） |
| `BAD_SIGNATURE` | Ed25519 验签失败（验签失败不花费 nonce） |
| `SHARE_POINT_MISMATCH` | 提交分片的点位不是该托管人在该托管下被分配的点位（不花费 nonce） |
| `SHARE_DIGEST_MISMATCH` | `sha256(提交分片)` 与库存 `shard_digest` 不符，分片被改/非本人片（不花费 nonce） |
| `DUPLICATE_SHARE` | 同一托管人对同一会话重复提交 |
| `CROSS_POLICY_SHARE` | 托管人不属于该策略版本，或 nonce/领取/提交绑定的会话、托管人不匹配 |
| `SESSION_COMPLETED` / `SESSION_EXPIRED` | 会话已完成（密文只下发一次）/ 已过 TTL |
| `MIGRATION_CONFLICT` | 同一托管记录已有未失败迁移会话（不同幂等键不得重复迁移），或幂等键被挪用到不同参数 |
| `MIGRATION_FAILED` | 迁移会话已终态失败；需换新幂等键重新创建 |
| `THRESHOLD_NOT_MET` / `INTEGRITY_CHECK_FAILED` | 有效分片不足（含重启后内存待累计分片丢失 `pending_shares_unavailable`）/ 重组结果摘要不匹配 |

---

## 4. 安全设计要点

**不可变策略 + 版本/epoch 推进**
`policies` 以 `(policy_id, version)` 为复合主键，只 INSERT、永不 UPDATE 内容；
`policy_heads` 保存当前头指针。轮换与撤销在**单事务**内完成（行级 advisory lock + 头行 `FOR UPDATE`）：
插入新版本 → 旧版本置 `revoked`、其下 custody 置 `rotated/revoked` → 前移指针。
并发轮换只有一方成功，另一方得到 `VERSION_CONFLICT`。所有写入接口都要求 `expected_version` 乐观锁。

**Shamir 分片（GF(p)，p = 2²⁵⁶−2³²−977）**
秘密按 31 字节分块，每块构造独立的 `(threshold−1)` 次多项式；分片点 x 为托管人序号，
y 拼接编码。任意 ≥ threshold 个分片可插值还原，少于门限不提供任何信息（50 组随机参数性质测试见
`scripts/demo.py`）。每个分片以 `HKDF(master_key, shard_id)` 派生独立密钥，AES-256-GCM 加密落盘；
数据库同时保存 `secret_digest` 与各 `shard_digest`，重组后做常量时间比对。

**领取本人分片 + 一次性 nonce + 签名绑定实际分片**
nonce 是 32 字节随机数，库里只存 `sha256(nonce)`，且有 `UNIQUE(nonce_hash)` 与
`UNIQUE(session_id, custodian_id)` 两重约束。托管人**先用 nonce 领取本人分片**，
再对规范报文（`keyvault.share.v2`）签名，报文逐行绑定
`custodian / policy_id / policy_version / session_id / nonce / point_x / shard_digest`。
提交时必须同时给出 `point_x` 与 `shard_hex`，因此：

- 只拿到 nonce 就签名、不交自己的分片 → 无法计数（点位/摘要校验过不了），凑门限无从谈起；
- 提交别人的点位或被篡改的分片字节 → 分别得到 `SHARE_POINT_MISMATCH` / `SHARE_DIGEST_MISMATCH`；
- 同一 nonce 用两次 → 第二次 `NONCE_ALREADY_USED`；
- 把别的托管人/别的会话的 nonce 拿来用 → `CROSS_POLICY_SHARE`；
- 策略轮换后重放旧版本场景的 nonce → 版本不匹配，且会话侧直接 `EPOCH_REVOKED`；
- 归属、点位、摘要、验签任一失败都**不花费 nonce**（合法网络重试不会锁死托管人）；
  全部通过后才在同一事务内花费 nonce、写入计数。

**并发竞态**
nonce 签发、分片领取与份额提交都先对 `recovery_sessions` 行 `SELECT ... FOR UPDATE`，
同一会话完全串行化；重复提交再由唯一约束兜底。内存待累计分片在全部校验通过、数据库写入
完成后才入池，其撤销边界有双重保证：**校验拒绝发生在入池之前，回滚时绝不触碰已提交的内存分片；
入池后的任何失败（重组/审计写入/连接中止）都在行锁释放之前、凭本次插入的私有 token 精确撤回
本次新增**——token 不匹配（例如同托管人的成功重试已先把新分片放入池中）时撤销为安全 no-op。
因此即使在“失败回滚 × 锁等待者 × 同托管人重试”的交错下，数据库提交计数与内存内容始终对应，
等待者拿锁时绝不会读到未提交分片，旧请求也无法误删新分片；门限只按**已提交且验签**的分片
达成一次，重放已花费 nonce 等拒绝不会破坏进行中的会话。演示脚本用 `asyncio.gather` 双发验证：
同一份额并发提交恰好一次 200、一次 409，份额计数不重复；另有“重放 × 合法提交”交错用例，
验证合法分片补足门限恰好完成一次、密文只下发一次；`scripts/race_recovery.py` 进一步用故障注入
闸门钉住行锁等待与回滚的精确交错（38 项断言）；`M1` 场景另以模拟重启验证迁移会话的
终态失败与安全重试（8 项断言，合计 46 项）。

**恢复会话与一次性密文**
会话绑定 `custody/policy_version/epoch_index/request_digest/valid_until`；提交时实时校验
会话未完成、未过期、epoch 未被撤销或过期——即使会话进行中租户突然轮换/撤销，在途份额也会被拒。
门限满足后秘密只存在于当前请求栈内存，且**只由托管人实际提交、并已通过归属/点位/摘要/验签的
分片**插值得到（服务端**不**解密自己的库存分片来凑数）→ 校验 `secret_digest` →
X25519 临时 ECDH + HKDF + AES-GCM 包装 → 同事务把会话置 `completed`，提交成功后立即清空内存待累计分片，
密文不再可获取（重复提交、撤销、并发下都只返回这一次）。
AAD 绑定会话全部要素，密文无法被挪到别的会话复用。待累计分片明文绝不落盘（见 `app/pending.py`）。

**跨策略密钥迁移**
迁移会话在创建时把**源/目标策略版本的规范摘要**（不可变参数：策略 id、版本、租户、门限、
托管集合、epoch、轮换间隔的 SHA-256）随会话落库；托管人签名报文
（`keyvault.migration.share.v1`）与审计同样绑定这两个摘要——签名不可能被挪到另一场迁移、
另一条托管记录或另一个策略版本上重放；每次挑战/领取/提交都会复算版本行摘要与库存摘要，
不一致即确定性失败。创建以 `migration:{custody_id}` 咨询锁串行，
`UNIQUE(tenant_id, idempotency_key)` + 部分唯一索引（同一托管记录至多一个
`open/completed` 会话）兜底：同键重放返回原会话，异键并发恰一个成功。
达到源门限的提交在**会话行锁**内：只凭已验签的内存分片重组 → 常量时间比对
`secret_digest` → 按排序后的源/目标策略 id 取**与轮换/撤销同一把策略锁**复检双方仍有效
（锁顺序全局统一为“行锁先于策略锁”，无循环等待）→ 立即按目标策略 `shamir_split` →
新分片以 `HKDF(master_key, shard_id)` 派生密钥 AES-256-GCM 加密，与新托管记录、会话
`completed` 状态在**同一事务**落盘。秘密明文只存在于该请求栈内存，事务提交成功后内存
待累计分片立即销毁；源托管记录与其库存分片全程不被修改。终态失败（内存分片丢失、
重组校验失败、源/目标被并发撤销或过期）随事务提交会话 `failed` 状态并写
`migration.failed` 审计，此后换新幂等键即可安全重试；审计链可完整重放每一次
`migration.start / challenge.issue / shard.claim / share.submit / complete / failed`。

**审计：按序、可重放、不泄密**
`audit_log` 仅追加，每条记录 `seq`（事务级 advisory lock 串行分配）与
`entry_hash = SHA256(规范字段 || prev_hash)`，形成哈希链；`GET /audit/replay`
逐条复算并报告首个断裂点。审计内容只含 ID、版本、epoch、**分片点位与摘要**、计数等事实，
写入口还会按字段名（secret/private/ciphertext/plaintext/share_blob/nonce/key…）二次过滤，
拒绝事件同样留痕。

---

## 5. 本地开发（不用 Docker）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# 准备一个 PostgreSQL 16，设置 KEYVAULT_DATABASE_URL 后：
python -m app.seed                      # 建表 + 演示身份
uvicorn app.main:app --reload --port 8000
KEYVAULT_BASE_URL=http://localhost:8000 python -m scripts.demo       # 端到端验收
KEYVAULT_FAULT_INJECTION=1 python -m scripts.race_recovery           # 并发回滚竞态回归
```

## 6. 生产注意（本仓库为演示强化基线，上线前至少完成）

- 替换全部演示密钥；分片主密钥建议接入 KMS，进程只持有短期解封装后的密钥；
- 启用 TLS；为管理端与租户/托管人端分离网关与限流；
- `pgcrypto`/列级权限或独立加密服务进一步隔离分片；按租户评估分片落盘地域；
- 轮换主密钥时需要对分片做 rewrap（数据模型中 `shards.id` 即派生密钥标识，可据此迁移）。

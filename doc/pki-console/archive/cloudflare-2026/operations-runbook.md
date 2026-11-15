> 状态：历史归档。以下内容保留旧版本的部署与操作记录，不能作为当前环境状态或当前版本操作依据。
> 当前入口：[项目文档](../../README.md)、[部署指南](../../production-deployment.md)。

# PKI-Console 生产运维 Runbook

本文是 `pki.altasci.com`、`pki-console.altasci.com` 和 LD-S2 生产实例的日常运维、
监控、备份、恢复、轮换、变更和故障处置手册。首次部署步骤见
[production-deployment.md](../../production-deployment.md)，Cloudflare 资源清单见
[cloudflare-wrangler-operations.md](cloudflare-wrangler-operations.md)。

原生产基线核验日期：2026-08-24；2026-10-09 按源码修正 healthcheck 说明。
部署、迁移和导出命令见 [部署、迁移与数据导出手册](deployment-migration-export.md)。

## 1. 当前生产基线

| 层 | 生产基线 |
| --- | --- |
| 公共入口 | `https://pki.altasci.com`，匿名访问，不配置 Cloudflare Access |
| 管理入口 | `https://pki-console.altasci.com`，由 Cloudflare Access 保护 |
| Pages | 项目 `pki-web`，同时发布 React 静态资源和 Pages Functions |
| 内部 origin | `https://pki-origin.altasci.com`，无共享密钥访问应为 403 |
| Tunnel | `LD-S2`，ID `2fe5715e-451e-4a9d-9527-544434996390` |
| 应用主机 | LD-S2 / `103.23.11.117`，SSH 端口 `27472` |
| 应用进程 | 原生静态 Go 二进制 `/usr/local/bin/pki-console` |
| systemd | `pki-console.service` 和现有 `cloudflared.service`，均应 active + enabled |
| 应用监听 | `127.0.0.1:8080`，不直接暴露公网 |
| 数据库 | PostgreSQL 18.4，由 1Panel 容器 `1Panel-postgresql-Ux15` 管理 |
| 数据库连接 | 应用使用 `127.0.0.1:5432` 和 `sslmode=disable` |
| 应用配置 | `/etc/pki-console/pki-console.env`，`root:pki-console 0640` |
| 日志 | stdout/stderr JSON，由 journald 接收 |

“不使用 Docker”是指 PKI-Console 应用以 Go 二进制和 systemd 运行，不构建或运行
应用容器。PostgreSQL 是独立的外部持久化服务；当前恰好由同机 1Panel Docker 管理，
不属于 PKI-Console 的应用生命周期。

当前 PostgreSQL 的 Docker 端口发布曾观察为 `0.0.0.0:5432` 和 `[::]:5432`。项目
负责人已在 2026-08-24 明确接受当前测试/上线阶段的该网络边界，运维操作不因它阻塞。
这是一项已接受风险，不代表 PKI-Console 需要该暴露；后续若调整，只能作为独立网络
变更处理，不能与应用发布混在同一窗口。

## 2. 责任边界

| 角色 | 责任 |
| --- | --- |
| PKI 负责人 | CA 生命周期、签发策略、吊销、根密钥事件和最终变更批准 |
| 平台运维 | systemd、主机、Tunnel、Pages、监控、备份任务和恢复演练 |
| 数据库管理员 | PostgreSQL 可用性、容量、备份、PITR、恢复和权限 |
| 安全负责人 | Access 策略、root 凭据、TOTP、KEK、审计与事件响应 |
| 发布负责人 | 已审核 tag、构建校验和、迁移顺序、验收与回滚记录 |

生产变更至少记录：时间、操作者、原因、关联 commit/tag、变更前状态、变更内容、验证
结果和回滚结果。不要在工单、聊天、日志或截图中记录密码、TOTP、JWT、Tunnel Token、
origin secret、数据库 URL 或 `PKI_MASTER_KEYS`。

标准巡检、变更、恢复、轮换和事件表单见
[operations-record-templates.md](operations-record-templates.md)。

## 3. 服务目标和事件等级

以下是初始运行基线，可在取得实际流量数据后调整：

| 指标 | 初始目标 |
| --- | --- |
| 公共 PKI 月可用性 | 99.9% |
| Console 月可用性 | 99.5%，计划维护窗口除外 |
| 公共请求延迟 | 95% 小于 1 秒 |
| 已审批签发任务 | 正常情况下 2 分钟内完成 |
| CRL/OCSP | 在 `next_update` 前始终存在可用的新响应 |
| 数据恢复点目标 RPO | 由数据库负责人确认；建议不超过 15 分钟 |
| 服务恢复时间目标 RTO | 由 PKI 负责人确认；建议不超过 2 小时 |

| 等级 | 判定 | 响应 |
| --- | --- | --- |
| P0 | CA 私钥/KEK疑似泄漏、错误签发、错误吊销、审计篡改、数据库与 KEK 同时泄漏 | 立即冻结签发，通知 PKI 与安全负责人，保全证据 |
| P1 | 公共 CRL/OCSP/AIA 不可用、数据库不可用、全部登录或签发失败 | 15 分钟内响应，持续处置到恢复 |
| P2 | Console 局部故障、任务积压、单个 CA/功能异常、备份失败 | 4 小时内响应 |
| P3 | 容量趋势、文档偏差、单次非关键告警 | 下一个工作日处理 |

## 4. 标准巡检

### 每次值班或每日

- 检查公共首页、live、ready 和 authorities 接口；
- 检查 `pki-console.service`、`cloudflared.service` 和 PostgreSQL 容器；
- 检查最近 24 小时的应用 ERROR/WARN、HTTP 5xx 和 panic；
- 检查待签发/失败任务、即将到期的 CA、CRL 和 OCSP 响应；
- 检查最近一次数据库备份是否成功且大小合理；
- 检查主机磁盘、内存、时间同步和 PostgreSQL 连接数。

### 每周

- 抽查一条公共 CA 证书、CRL 和证书状态查询；
- 查看 root/运维人员登录失败和被拒绝操作的审计记录；
- 检查非活跃用户、CA grants 和长期未处理申请；
- 检查 Pages、Access、DNS 和 Tunnel 配置是否与资源清单一致；
- 确认异地备份上传成功，且 KEK 备份与数据库备份分开保存。

### 每月

- 确认下个月审计分区可以创建，默认分区没有异常增长；
- 生成证书和 CA 到期报告；
- 复核 Access Allow Policy、GitHub Actions secrets 和 Cloudflare Token 权限；
- 复核生产主机补丁、cloudflared 和 PostgreSQL 支持状态；
- 复核容量趋势、告警噪声和事件记录。

### 每季度

- 在隔离环境执行数据库和 KEK 联合恢复演练；
- 验证恢复后的 CA key envelope 可以解密，并执行非生产签发/吊销/CRL/OCSP 全链路；
- 复核 RPO/RTO、值班联系人、root 紧急访问和密钥保管人；
- 检查本文所有命令、资源 ID 和文件路径仍然有效。

## 5. 快速健康检查

从运维终端执行匿名检查：

```sh
curl --fail --silent --show-error https://pki.altasci.com/health/live
curl --fail --silent --show-error https://pki.altasci.com/pki/v1/authorities
curl --silent --show-error -o /dev/null -w '%{http_code}\n' \
  https://pki-origin.altasci.com/health/live
curl --silent --show-error -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  https://pki-console.altasci.com/
```

预期依次是：live JSON 200、authorities JSON 200、origin 403、Console 到 Cloudflare
Access 的 302。`/health/live` 只证明 Go 进程能响应；需要验证 PostgreSQL 时使用 Console
侧 `/api/v1/health/ready`；内置 healthcheck 仅检查存活。

连接服务器：

```sh
ssh -p 27472 root@103.23.11.117 -i /home/phil616/ssh_keys/id_ed25519.key
```

服务器内检查：

```sh
systemctl is-active pki-console.service cloudflared.service
systemctl is-enabled pki-console.service cloudflared.service
ss -ltnp 'sport = :8080'
docker ps --filter name=1Panel-postgresql-Ux15

sudo -u pki-console env -i /bin/sh -c \
  'set -a; . /etc/pki-console/pki-console.env; set +a; exec /usr/local/bin/pki-console healthcheck'
```

`pki-console healthcheck` 会带正确的内部 origin 头访问 Console live 路径，请求超时为 3 秒，
仅确认 Go 存活；数据库可用性应另查 `/api/v1/health/ready`。服务 restart 后应短间隔重试最多 15 秒，不能在第一次
`connection refused` 时直接认定新版本失败。

## 6. 日志和指标

查看日志时优先使用结构化字段和 `request_id` 串联请求：

```sh
journalctl -u pki-console.service --since '1 hour ago' --no-pager
journalctl -u pki-console.service --since today -o cat --no-pager \
  | jq -R 'fromjson? | select(.level == "ERROR" or .level == "WARN")'
journalctl -u cloudflared.service -n 100 --no-pager
```

应用请求日志包含 `request_id`、method、path、host、status、response_bytes 和
duration_ms。重点告警消息包括：

- `PKI-Console stopped`；
- `issuance worker stopped`；
- `certificate issuance failed`；
- `request panic`；
- `write audit event` 或 `write login audit event`；
- `login denied` 的异常突增；
- HTTP status 500、502、503 或 504。

日志可以记录认证失败阶段和布尔状态，但不得记录密码、TOTP、JWT、Cookie、CSRF Token、
origin secret、数据库 URL、明文私钥或 KEK。浏览器继续只显示统一认证错误。

Prometheus 指标位于 Console 的 `/api/v1/metrics`，包含 Go/process 指标以及
`pki_console_http_requests_total` 和 `pki_console_http_request_duration_seconds`。该端点
要求 PKI-Console operator 或 super administrator 会话，不应把个人长期会话 Cookie
写入 Prometheus 配置。尚未建立专用机器身份前，以外部健康探针、journald 和数据库
只读查询为主。

## 7. 建议告警

| 告警 | 条件 | 等级 |
| --- | --- | --- |
| PublicPKIDown | 公共 live 连续 2 分钟非 200 | P1 |
| PKIReadyFailed | `/api/v1/health/ready` 连续 2 次失败 | P1 |
| TunnelDown | `cloudflared.service` inactive 或 Tunnel 无连接 | P1 |
| HTTP5xxBurst | 5 分钟内 5xx 比例超过 2% 且至少 5 次 | P1/P2 |
| IssuanceBacklog | queued/failed 超过 10 条或最老任务超过 5 分钟 | P2 |
| IssuanceStuck | running 超过 10 分钟 | P2 |
| CRLExpiring | 当前 CRL 距 `next_update` 少于 6 小时 | P1 |
| OCSPExpiring | 任一响应距 `next_update` 少于 1 小时 | P1 |
| CAExpiring | 根/中间 CA 距到期少于 180/90 天 | P2 |
| AuditWriteFailure | 任意 audit write error | P1 |
| BackupFailed | 计划备份失败或 24 小时无成功备份 | P1 |
| DiskPressure | 数据盘使用率超过 80%/90% | P2/P1 |
| RootLoginDeniedBurst | 10 分钟内 root 拒绝次数超过 3 | P2，先查 Access/TOTP |

## 8. PostgreSQL 只读巡检

通过 1Panel 的 PostgreSQL 终端或受控 `psql` 会话执行。不要把包含密码的
`DATABASE_URL` 展开到 shell 历史或进程参数。

签发队列和工作流：

```sql
SELECT status, count(*)
FROM certificate_requests
GROUP BY status
ORDER BY status;

SELECT status, count(*) AS jobs, min(created_at) AS oldest
FROM issuance_jobs
GROUP BY status
ORDER BY status;

SELECT id, request_id, attempt_count, locked_by, locked_at, last_error_code
FROM issuance_jobs
WHERE (status = 'running' AND locked_at < now() - interval '10 minutes')
   OR (status IN ('queued', 'failed') AND next_attempt_at < now() - interval '5 minutes')
ORDER BY created_at;
```

CA、CRL、OCSP 和叶证书到期：

```sql
SELECT slug, kind, status, not_after, not_after - now() AS remaining
FROM certificate_authorities
WHERE status = 'active'
ORDER BY not_after;

SELECT ca.slug, crl.crl_number, crl.next_update,
       crl.next_update - now() AS remaining
FROM crls crl
JOIN certificate_authorities ca ON ca.id = crl.ca_id
WHERE crl.is_current
ORDER BY crl.next_update;

SELECT ca.slug, min(o.next_update) AS earliest_next_update,
       count(*) AS responses
FROM ocsp_responses o
JOIN certificates c ON c.id = o.certificate_id
JOIN certificate_authorities ca ON ca.id = c.issuer_ca_id
GROUP BY ca.slug
ORDER BY earliest_next_update;

SELECT count(*) FILTER (WHERE not_after < now() + interval '30 days') AS within_30d,
       count(*) FILTER (WHERE status = 'good') AS currently_good
FROM certificates;
```

审计分区和基本完整性条件：

```sql
SELECT inhrelid::regclass AS partition
FROM pg_inherits
WHERE inhparent = 'audit_events'::regclass
ORDER BY 1;

SELECT tableoid::regclass AS partition, count(*)
FROM audit_events
GROUP BY tableoid
ORDER BY tableoid::regclass::text;

SELECT count(*) AS invalid_rows
FROM audit_events
WHERE metadata IS NULL
   OR octet_length(prev_hash) <> 32
   OR octet_length(event_hash) <> 32;
```

这些查询只用于诊断。不要直接 UPDATE/DELETE 队列、证书、吊销、CRL、OCSP 或审计表；
业务变更必须通过 API 完成。审计表有不可变触发器，直接修改本身就是安全事件。

## 9. 备份体系

一份可恢复的 PKI 备份至少包含：

1. PostgreSQL 全量备份和连续 WAL/PITR 数据；
2. 与数据库版本对应的全部 `PKI_MASTER_KEYS`，包括非 active 的旧 key ID；
3. `/etc/pki-console/pki-console.env` 的受控加密副本；
4. root TOTP 应急恢复材料；
5. Pages/Tunnel/Access/DNS 资源清单和 Git 仓库的已发布 tag；
6. 每份文件的校验和、创建时间、加密方法和保管人。

数据库备份与 KEK 必须分开加密、分开存储和分开授权。只有数据库没有 KEK时，CA 私钥
无法恢复；数据库与 KEK 同时泄漏时，攻击者可能解密 CA 私钥。

建议基线：

- PostgreSQL 持续归档 WAL；
- 每日一次全量或可验证增量备份；
- 至少保留 7 份日备、5 份周备和 12 份月备；
- 至少一份异地主机/对象存储副本；
- 备份加密密钥不放在数据库主机；
- 每日自动校验备份任务、大小和 checksum；
- 每季度在隔离环境完成一次真实恢复。

当前 PostgreSQL 由 1Panel 管理，优先使用已配置的 1Panel/PostgreSQL 备份与 PITR能力，
并在运维记录中写明实际存储位置、保留策略和最近恢复演练结果。仅看到“备份成功”状态
不等于可恢复。

## 10. 恢复演练

恢复只能在隔离主机、隔离数据库和测试 hostname 中进行，不能让恢复副本连接生产
Tunnel、生产 Pages 或生产 Access 应用。

标准步骤：

1. 记录目标时间点、备份 ID、Git tag、数据库版本和 KEK key IDs；
2. 新建隔离 PostgreSQL 18 实例并恢复基础备份与 WAL；
3. 使用恢复副本专用数据库账户，不修改原生产数据库；
4. 安装对应 tag 的 Go 二进制，加载隔离配置和完整 KEK 集合；
5. 执行只读表数量、审计分区和 expiry 查询；
6. 执行 `pki-console migrate`，确认 schema 与二进制兼容；
7. 在隔离域名完成非生产 CA 的签发、审批、下载、吊销、CRL 和 OCSP 验证；
8. 验证旧 KEK 对应的 CA envelope 可以解密；
9. 记录实际 RPO、RTO、缺失数据和所有人工步骤；
10. 销毁隔离副本前保留演练报告，安全删除临时明文材料。

生产灾难恢复必须由 PKI 负责人和数据库负责人共同批准。若怀疑私钥或 KEK泄漏，不能
把恢复当作普通可用性事件处理，应先进入 P0 密钥事件流程。

## 11. 凭据和密钥轮换

### Root 密码或 TOTP

先生成并由两名授权人员确认新值，更新安全副本和生产环境文件，重启应用使 root 配置
同步，再完成一次真实 Access + 密码 + 新 TOTP 登录。旧 TOTP 材料随后按安全流程销毁。
不要连续测试旧码；连续 5 次失败会锁定 15 分钟。

### Origin shared secret

当前只支持一个值，因此按维护窗口处理：

1. 生成新的 32-byte 随机十六进制值并记录安全副本；
2. 更新 Pages encrypted Secret；
3. 重新发布 Pages 使新 binding 进入 deployment；
4. 立即更新后端环境文件并重启服务；
5. 验证公共接口、真实 Console 登录和匿名 origin 403；
6. 删除旧值的临时副本。

第 3 到第 4 步之间 API 会短暂 403。任一侧不一致都会造成 API 403，轮换步骤不得由
并行操作者无协调地执行。Cloudflare 要求 Secret 在使用它的 deployment 之前创建，
因此不能先删除旧 Secret 再准备部署。

### Access 应用或 AUD

Access 应用重建会产生新 AUD。先记录 Allow Policy 和旧 AUD，再同步更新后端
`CF_ACCESS_AUD` 并重启。必须验证 root 邮箱、JWT issuer 和新 AUD；不得为了恢复登录
临时使用 Everyone 或 Bypass。

### PKI master key

新增 KEK 时先把新 ID 和旧 IDs 一起写入 `PKI_MASTER_KEYS`，再把新 ID 设为
`PKI_MASTER_KEY_ACTIVE_ID`。确认新 envelope 使用新 ID，并完成旧 envelope重加密和
恢复验证之前，绝不能删除旧 key。KEK 丢失可能永久失去 CA 私钥。

### 数据库密码和 Tunnel Token

数据库密码需要协调 PostgreSQL role 和服务环境文件，重启后检查 ready。Tunnel Token
在 Cloudflare Dashboard 轮换后更新 `cloudflared.service` 实际使用的 token位置并重启；
不要启用仓库中的备用 `cloudflared-pki.service` 覆盖现有 LD-S2 服务。

## 12. 发布与回滚控制

本文不触发发布，只定义运维顺序。实际发布必须使用已审核 tag，并遵循：

1. 测试和构建全部通过，记录二进制 SHA-256；
2. 创建可恢复的数据库检查点；
3. 保存当前二进制为 `/usr/local/bin/pki-console.previous`；
4. 校验上传文件后替换二进制；
5. 执行显式数据库迁移；
6. restart 后循环执行 healthcheck，最长等待 15 秒；
7. 验证 public 200、origin 403、Console Access 302 和真实 root 登录；
8. 观察 5xx、签发队列和审计写入至少一个完整业务周期。

健康失败时先恢复 previous binary 并重启。迁移不保证向后兼容；如果本次包含 schema
变更，不能只回滚二进制，必须在发布前明确数据库回退或前向修复方案。不要运行
`git reset --hard` 或直接覆盖数据库数据作为回滚。

## 13. 故障处置

### Console 超级管理员登录失败

1. 停止连续尝试，记录一次失败的准确时间和响应 `X-Request-ID`；
2. 确认 Access 页面已登录且邮箱等于 `ROOT_USER_EMAIL`；
3. 检查服务器和验证器时间，等待新的 30 秒 TOTP；
4. 查看 `login denied` 的安全字段：`login_matches_root`、
   `access_jwt_present`、`access_email_present` 和 `access_email_matches_root`；
5. JWT 缺失时查 Access/Pages，邮箱缺失时查 Pages 身份桥接，邮箱不匹配时查 Access
   身份和 root 配置；
6. 只有 Access 阶段通过后才检查密码/TOTP和账户锁定；
7. 不打印或复制 JWT、密码、TOTP 和 Secret。

本次已解决事件的完整根因见
[incident-2026-08-24-access-login.md](incident-2026-08-24-access-login.md)。

### Pages 502/504

按“Pages deployment → `pki-origin` DNS → Tunnel → cloudflared → 127.0.0.1:8080 →
PostgreSQL”顺序检查。origin 1016 通常是 DNS/Tunnel；502 通常是 Connector 到本地服务；
Go live 200 但 ready 503 通常是 PostgreSQL。

### Origin 403

匿名 origin 403 是正常状态。只有 Pages API 同时 403 才检查 Pages Secret与后端
`PKI_ORIGIN_SHARED_SECRET`、可信代理 CIDR 和转发 hostname。不要临时关闭 gateway。

### 签发队列积压

检查 `certificate issuance failed` 日志和 `issuance_jobs` 查询；判断是 CA/KEK、CSR、
profile、数据库锁还是 worker。不要直接把 failed 行改为 queued。保留请求 ID、
last_error_code 和审计证据，通过正常审批/重试逻辑处置。

### CRL 或 OCSP 即将过期

立即确认受影响 CA、当前响应的 `next_update`、Go worker和数据库状态。先恢复生成链路，
再从公网取回并解析实际响应。不要仅修改数据库时间字段。若公共客户端已无法获得有效
吊销状态，按 P1 处理。

### 私钥、KEK 或错误签发事件

立即按 P0 处理：冻结受影响 CA 的新签发、保全日志/审计/数据库快照、通知 PKI与安全
负责人、确定影响的证书和时间窗。不要删除审计、不销毁旧 key material、不擅自创建
新根 CA。是否吊销 CA、发布新 CRL、替换信任锚和通知依赖方必须由正式密钥事件流程决定。

## 14. 已知风险和待确认项

| ID | 项目 | 当前处理 |
| --- | --- | --- |
| RISK-001 | PostgreSQL Docker port 发布到 `0.0.0.0:5432` | 负责人已接受当前阶段风险；单独跟踪，不阻塞应用运维 |
| RISK-002 | Access 保护整个 Console hostname | 运维人员和普通用户也必须先通过 Access Allow Policy |
| RISK-003 | Prometheus metrics 需要个人 Console 会话 | 未建立机器身份前不保存长期个人 Cookie |
| RISK-004 | origin secret 仅支持单值 | 在维护窗口按固定顺序轮换 |
| RISK-005 | 数据库运行角色拥有 schema CREATE | 审计月分区当前需要；权限拆分需先调整分区函数模型 |
| RISK-006 | 备份/PITR 的实际 RPO、保留和最近恢复结果 | 数据库负责人应在运行台账中补齐并按季度验证 |

## 15. 交接清单

- [ ] 接班人能访问 LD-S2、Cloudflare、GitHub、1Panel 和备份平台；
- [ ] 接班人知道生产 secrets 的位置，但文档中没有 secret 内容；
- [ ] 当前 tag、二进制 SHA-256、Pages deployment 和数据库迁移版本已记录；
- [ ] 两个 systemd 服务和 PostgreSQL 当前健康；
- [ ] 最近一次备份、PITR 状态和恢复演练日期已记录；
- [ ] 待审批、失败和积压签发任务已说明；
- [ ] 未来 180 天 CA/OCSP/证书到期事项已说明；
- [ ] 未关闭事件、已接受风险和计划变更已移交；
- [ ] 值班人与 PKI/安全/数据库升级联系人有效。

运行台账应放在受控运维系统中，不把动态密码或密钥回写到 Git 文档。

# 日常运维与故障处理

状态：当前指南；核对日期：2026-11-15。适用于单体 `pki-console`、外部 Nginx 和
PostgreSQL 18+。示例域名、路径和服务名需按部署修改，不代表已核实的线上状态。
安装见 [部署指南](production-deployment.md)，恢复见 [备份与迁移](deployment-migration-export.md)。

## 服务检查

```sh
sudo systemctl status pki-console --no-pager
sudo journalctl -u pki-console -n 100 --no-pager
sudo nginx -t
curl --fail -H 'Host: pki-console.example.com' http://127.0.0.1:8080/api/v1/health/ready
curl --fail -H 'Host: pki.example.com' http://127.0.0.1:8080/health/live
curl --fail https://pki-console.example.com/api/v1/version
```

`health/live` 仅表示进程能处理 HTTP；管理端 `health/ready` 检查数据库连通性，失败
返回 503。两者均不需要登录。`pki-console healthcheck` 也只做本机存活检查，不能
代替数据库、签发、时钟和代理的完整验收。版本值在构建时写入。

`/api/v1/metrics` 需要超级管理员或运维人员会话，目前没有独立的 Prometheus 服务令牌。
内置指标覆盖 Go 进程和 HTTP 数量、延迟；队列积压、证书到期和备份恢复需另行监控。

## 登录、会话与限流

- 普通账户密码为 15–128 字节；超级管理员环境密码至少 32 字节，建议随机 ASCII。
- 普通会话空闲上限 8 小时、绝对上限 24 小时；超级管理员分别为 30 分钟、4 小时。
  目前是代码常量，不能通过自行添加环境变量调整。
- 账户连续 5 次认证失败锁定 15 分钟；登录另限每客户端 IP 每分钟 10 次。
- 超级管理员使用 SHA-256、6 位、30 秒 TOTP；接受当前时间步前后各一格，已成功接受
  的时间步不能再次用于登录或敏感导出。
- 导出二次验证每用户每分钟最多 5 次，失败或超限返回 403 `step_up_failed`。
  通用流量或并发限制返回 429，按 `Retry-After` 等待。

401 先核对账户、Cookie、CSRF、锁定状态和 TOTP 算法/时间，避免反复快速重试。
生产 Cookie 为 `__Host-pki_session`，仅 HTTPS、HttpOnly、SameSite=Strict。
CA 私钥导出需要重新输入**当前密码**和未使用的 TOTP。

## 签发任务

`serve` 已包含 worker。审批返回 202 表示进入签发流程，需继续查看最终是否为 `issued`。
所有角色都不能审批自己的申请。运维人员需要相应中间 CA 的 `approve` 授权；读取申请
详情另需 `view_requests`。见 [业务配置](enterprise-pki-web-setup.md)。

任务使用数据库租约，超时运行任务约 5 分钟后可接管；单次处理上下文为 2 分钟。
处理中断将申请退回可重试状态并延后约 5 分钟，业务校验失败进入终态。
不要将全部 `failed` 直接改回 `queued`。目前没有人工重试任务的管理 API；
先根据日志和错误码定位原因，再通过正常申请流程处理。

以下只读 SQL 可诊断队列，请使用受控 PostgreSQL 连接配置：

```sql
SELECT status, count(*) FROM issuance_jobs GROUP BY status;
SELECT status, count(*) FROM certificate_requests GROUP BY status;
SELECT id, request_id, status, attempt_count, next_attempt_at, locked_at, last_error_code
FROM issuance_jobs
WHERE status IN ('queued', 'running', 'failed')
ORDER BY created_at LIMIT 50;
```

监控积压、长时间运行任务、数据库和审计失败。认证后写请求在执行业务前写审计，
审计不可用时返回 503；读取接口不受此写入门禁控制。审计只追加、按月分区并带哈希链，
备份需包含分区、函数和约束。哈希链不能替代隔离备份和数据库管理员权限控制。

## CRL、OCSP 与 TSA

CRL 在初始化、吊销及公开读取时按需生成或刷新，没有独立的定时刷新任务。
公开读取发现缺失或距 `NextUpdate` 不足一分钟时尝试刷新；失败可能返回 503。
有效期最多 7 天，还会受签发链限制。

OCSP 动态响应有效期最多 4 小时，受响应者和 CA 链限制，HTTP 缓存最长 1 小时。
OCSP、TSA 分别限每客户端 IP 每分钟 120 次；部分密码运算接口共享 4 个并发槽，
超限返回 429。多实例的内存限流并非全局配额。

生产 TSA 需要 Linux 内核 NTP 健康检查；非 Linux 或时钟不可靠时拒绝签发。
`TSA_MAX_CLOCK_UNCERTAINTY` 默认 `5s`，允许 `1ms`–`1m`，详见 [TSA](tsa.md)。
监控 CA、OCSP 响应者和 TSU 有效期并提前准备替代证书与地址。
当前没有 CA/TSU 原地续期、密钥重加密或生命周期状态修改的管理 API。

## 凭据和主密钥变更

超级管理员凭据由环境配置在启动时同步，更换密码后重启服务。普通账户密码重置和
禁用会撤销会话。TOTP 秘钥变更本身不保证撤销已有会话；泄露时应在受控数据库维护中
一并撤销受影响会话并核查审计，不能只更换验证器配置。

新增 KEK 时保留 `PKI_MASTER_KEYS` 全部旧条目，再切换 `PKI_MASTER_KEY_ACTIVE_ID`
并重启。active ID 只影响后续加密，不会自动重新加密已有密钥。当前没有批量重加密
工具；确认在线数据与所有保留备份均不再需要旧 KEK 前不能删除它。
数据库备份与 KEK 分开加密保管，恢复演练需同时验证两者。

## 常见故障

| 表现 | 排查方向 |
| --- | --- |
| Nginx 502 | systemd、监听地址、启动配置、本机 health |
| 421 | Host 是否匹配配置域名 |
| 写操作 401 | 会话、CSRF、Cookie 是否经 HTTPS 发送 |
| 写操作 503 | 数据库或审计分区写入失败 |
| 私钥导出 403 | 当前密码、未使用的 TOTP、角色、二次验证限流 |
| 一次性私钥 404/410 | 归属、已领取或超过 24 小时 |
| 解密失败 | 对应 KEK ID 和密钥是否仍在环境配置中 |
| TSA HTTP 200 但拒绝 | 解析 DER 状态，检查 TSU、链、NTP 和日志 |

变更、恢复和故障记录使用 [记录模板](operations-record-templates.md)。

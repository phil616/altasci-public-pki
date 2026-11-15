# 日常运维与故障处理

状态：当前指南；核对日期：2026-11-16。适用于单体 `pki-console`、外部 Nginx 和
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

- 普通账户密码为 15–128 字节；超级管理员环境密码为 32–1024 字节，建议随机 ASCII。
- 普通会话空闲上限 8 小时、绝对上限 24 小时；超级管理员分别为 30 分钟、4 小时。
  目前是代码常量，不能通过自行添加环境变量调整。
- 账户连续 5 次认证失败锁定 15 分钟；登录另限每客户端 IP 每分钟 10 次。
  锁定期间重试不延长锁定；锁定到期后的首次失败从 1 重新计数。
- CA 私钥导出要求确认当前管理员密码，每用户每分钟最多 5 次，失败或超限返回 403 `password_verification_failed`。
  通用流量或并发限制返回 429，按 `Retry-After` 等待。

401 先核对具体错误码、账户、Cookie、锁定状态，避免反复快速重试。
403 `csrf_failed` 单独检查 CSRF；503 `authentication_unavailable` 检查数据库和服务日志，不能当作密码错误。
密码验证通过但仍被锁定时，返回 401 `account_locked` 和 `Retry-After`。
生产 Cookie 为 `__Host-pki_session`，仅 HTTPS、HttpOnly、SameSite=Strict。
CA 私钥导出需要重新输入**当前密码**。

### 超级管理员始终登录失败

1. 确认访问的是 `CONSOLE_BASE_URL` 的 HTTPS 管理域名，核对 `/api/v1/version` 是刚部署的版本。
   Nginx 保留管理 Host；不要在公开域名或直接通过 HTTP/IP 测试生产 Cookie。
2. 使用运行进程实际加载的 `ROOT_USER_EMAIL` 和 `ROOT_USER_PASSWORD`。程序不自动读取 `.env`；
   修改 systemd 环境文件后重启才生效。密码按原文校验，不移除首尾空格，不附加环境文件的引用符。
3. 核对日志 `login denied` 的 `stage`/`error` 和请求编号。`password` 表示密码不匹配，
   `account_locked` 表示密码正确但仍在锁定期，`user_lookup` 表示登录标识不匹配。
4. 确认数据库已按 [首版基线初始化](schema-initialization.md)，并完整更新内嵌前端的二进制。
5. 若之前已累计锁定，停止重试并等待 15 分钟。需要凭据恢复时，更新环境中的 root 密码后重启
   新版本，密码同步会清除旧锁定。仅重启且不修改凭据会保留密码失败锁定。

受控测试库或运维连接可使用只读查询检查状态，不读取密码 hash：

```sql
SELECT username, email, status, failed_login_count, locked_until
FROM users WHERE role = 'super_admin';
```

用户名/邮箱共享登录标识空间，新建账户禁止跨字段重复。历史库若存在一个账户的用户名等于
另一个账户的邮箱，该标识将被拒绝；用无歧义的另一标识登录，再按受控数据维护流程修正历史冲突。
当前协议及账户配置见 [密码认证](password-authentication.md)。

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

本节描述系统管理的 CA。独立签发工具使用自己的作用域 CRL、凭据与额度，
见 [独立签发策略](independent-signing.md)，不共享这里的 CRL/OCSP 记录。

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
禁用会撤销会话。管理员密码实际改变时也会撤销其旧会话，需重新登录。
凭据泄露后同时检查审计、受影响业务操作及独立签发凭据。

新增 KEK 时保留 `PKI_MASTER_KEYS` 全部旧条目，再切换 `PKI_MASTER_KEY_ACTIVE_ID`
并重启。active ID 只影响后续加密，不会自动重新加密已有密钥。当前没有批量重加密
工具；确认在线数据与所有保留备份均不再需要旧 KEK 前不能删除它。
数据库备份与 KEK 分开加密保管，恢复演练需同时验证两者。

## 常见故障

| 表现 | 排查方向 |
| --- | --- |
| Nginx 502 | systemd、监听地址、启动配置、本机 health |
| 421 | Host 是否匹配配置域名 |
| 写操作 401 | 会话是否有效、Cookie 是否经 HTTPS 发送 |
| 写操作 403 csrf_failed | 是否发送对应会话的 CSRF token |
| 登录/会话 503 authentication_unavailable | 数据库连通性、权限、schema 与服务日志 |
| 写操作 503 | 数据库或审计分区写入失败 |
| 私钥导出 403 | 当前密码、角色、密码确认限流 |
| 一次性私钥 404/410 | 归属、已领取或超过 24 小时 |
| 解密失败 | 对应 KEK ID 和密钥是否仍在环境配置中 |
| TSA HTTP 200 但拒绝 | 解析 DER 状态，检查 TSU、链、NTP 和日志 |

变更、恢复和故障记录使用 [记录模板](operations-record-templates.md)。

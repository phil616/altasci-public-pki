# 管理员认证诊断

状态：当前指南；核对日期：2026-11-15。适用于包含 `auth-check` 子命令的新二进制。
该命令不迁移数据库、不初始化 root、不改密码、不创建会话、不增加失败次数，也不消费验证码。
认证算法与 [服务实现](../../console/auth/service.go) 共用；参数为 SHA-256、6 位、30 秒。

## 先确认失败阶段

查找同一 `request_id` 的 `login denied` 日志。新版本另有不含凭据的 `stage` 字段。

| 阶段/错误 | 含义 |
| --- | --- |
| `password` | 尚未通过密码验证，先核对进程实际加载的密码 |
| `totp` | 密码已通过；核对实际密钥、时间、重放记录 |
| `account_state` | 旧版本在禁用/锁定时的通用结果，尚未验证本次 TOTP |
| `account_locked` | 新版本确认密码正确，但锁定尚未到期；响应含 Retry-After |
| `totp_replayed` 响应码 | 密码正确，验证码与已使用时间步匹配，必须等待新验证码 |
| `totp_clock_behind` | 当前验证码的 HMAC 正确，但已用时间步位于允许窗口之后；返回 503，不再计作错误凭据 |
| `internal` | 认证依赖故障，查服务日志和 503 错误码 |

未登录时 `/auth/session` 返回 401 是正常行为，不能据此断言密码错误。
时区显示为 `+08:00` 不会改变 Unix 时间；核对实际系统时间和 NTP，不是将本地时间强行改为 UTC。

## 从运行进程读取配置

推荐使用新诊断二进制读取当前服务 PID 的启动环境，而不是重新 `source` 一份可能已改动的环境文件。
这使用与启动完全相同的配置解析器，不输出密码、密钥、指纹、数据库 URL 或验证码。
Linux 上需要有权限读取 `/proc/PID/environ`，通常由 root 执行；PID 变化后重新取得。

```sh
pki_service_pid=$(systemctl show pki-console.service --property=MainPID --value)
test "$pki_service_pid" -gt 0
sudo /path/to/new/pki-console auth-check --pid "$pki_service_pid"
```

`/path/to/new/pki-console` 替换为已构建的新诊断二进制；可以单独上传执行，无需先替换正在运行的旧服务。
目标数据库需已有认证迁移 `00005_root_totp_state.sql`。命令不会自动补迁移。
输出的 `diagnostic_binary_version` 只代表诊断二进制版本，不代表目标进程版本；运行版本另查 `/api/v1/version`。

也可在已经正确加载配置的环境中运行 `pki-console auth-check`，此时输出
`configuration_source: current_environment`，检查的是当前 shell 传入的配置，不能证明服务已重启加载它。
程序本身不自动读取 `.env`。systemd EnvironmentFile 与 shell 的处理规则不同，参见
[systemd 官方说明](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#EnvironmentFile=)。

## 验证一个新验证码

在 Bash 中从终端隐藏读取，避免写进命令行参数或 shell 历史；只通过 stdin 交给诊断命令：

```bash
pki_service_pid=$(systemctl show pki-console.service --property=MainPID --value)
test "$pki_service_pid" -gt 0
read -r -s -p '新的 TOTP: ' pki_check_code
printf '\n'
printf '%s\n' "$pki_check_code" |
  sudo /path/to/new/pki-console auth-check --pid "$pki_service_pid" --totp-stdin
unset pki_check_code
```

命令正常退出仅表示诊断完成，仍需检查 `issues` 和 `totp_code_status`。
诊断不尝试 HTTP 登录，不验证 Nginx 路由或浏览器 Cookie，也不能保证查询完成后账户未被其他进程更改。
错误输入、配置或数据库读取失败才返回非零退出码。

| 输出 | 判断与处理 |
| --- | --- |
| `configured_password_matches: false` | 目标进程环境密码与数据库不一致；核查服务/worker 的环境和最近启动记录 |
| `configured_totp_secret_matches: false` 且状态已初始化 | 目标进程加载的 TOTP 密钥与数据库指纹不同；检查是否有不同环境的实例覆盖 root |
| `totp_state_initialized: false` | 没有登记指纹；核查迁移和服务版本，诊断本身不会补登记 |
| `lock_active: true` | 等待 locked_until 到期；不能靠正确验证码绕过锁定 |
| `totp_code_status: invalid` | 输入不是该配置、当前 ±30 秒内生成的 SHA-256 验证码；核查生成端和服务端时间/密钥 |
| `totp_code_status: replayed` | 匹配了已经使用的时间步；等待新代码，连续重放仍会计入失败次数 |
| `totp_code_status: clock_behind` | 当前代码正确但旧重放计数位于未来；校正时钟，必要时受控轮换 TOTP 密钥 |
| `totp_code_status: valid` | 单独的验证码检查通过；还需确认 issues 无密码/锁定等问题，并检查 HTTP 链路 |
| `totp_code_status: not_supplied` | 没提供代码，仅检查配置和账户状态 |

`server_time_utc` 是执行诊断机器的当前时间；`database_time_utc` 是数据库时间，
两者差值包含查询延迟。登录验证使用应用服务器时间，不是数据库时间；使用 PID 模式时应在服务所在主机运行。
`current_totp_step` 与 `last_accepted_totp_step` 均为 Unix 秒数除以 30。
不要自动清零重放计数，也不要改成接受 SHA-1 或跳过 TOTP；这会绕开已有认证保护。

排障时可提供诊断 JSON、HTTP 状态码/错误码和日志阶段，不提供原始登录请求体或环境文件。
源码见 [auth_check.go](../../cmd/pki-console/auth_check.go) 和 [check.go](../../console/auth/check.go)。

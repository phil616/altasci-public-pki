# PKI-Console 单体应用

状态：当前文档；核对日期：2026-11-15。行为以同一提交的代码、配置和迁移为准，
示例不代表线上资源状态。维护约定见 [文档维护规范](documentation-maintenance.md)。

PKI-Console 基于 CFSSL Go 库实现证书管理。一个 `pki-console` 二进制内置 React
前端、HTTP API、认证和证书签发后台任务，外部 Nginx 负责 TLS 与反向代理，外部
PostgreSQL 18+ 保存全部持久化数据。运行时不需要 Node.js、Cloudflare Pages、
Functions、Access 或 Tunnel，也不调用单独的 CFSSL 命令。

```text
浏览器 / PKI 客户端 → Nginx (HTTPS)
                       ↓
              pki-console (127.0.0.1:8080)
              ├─ 内嵌前端、API、本地认证
              └─ 签发后台任务
                       ↓
                 PostgreSQL 18+
```

已有根 CA / 中间 CA 的上传、校验和迁移范围见 [ca-import.md](ca-import.md)。

完整部署、迁移、回滚和验证步骤见 [production-deployment.md](production-deployment.md)，
Nginx 示例见 [nginx.conf.example](nginx.conf.example)，systemd 单元见
[pki-console.service](pki-console.service)。API 合约见 [openapi.yaml](openapi.yaml)，
桌面客户端认证见 [desktop-client-integration.md](desktop-client-integration.md)。

| 任务 | 当前指南 |
| --- | --- |
| 业务配置、授权与签发 | [业务指南](enterprise-pki-web-setup.md) |
| 日常运维与故障排查 | [运维指南](operations-runbook.md) |
| 本地认证检查与登录故障修复记录 | [认证检查快照](authentication-review-2026-11-15.md) |
| 备份、恢复、迁移与导出 | [数据维护](deployment-migration-export.md) |
| 独立 CA、凭据授权与 CSR 自动签发 | [独立签发策略及接入](independent-signing.md) |
| 时间戳服务 | [TSA](tsa.md) |
| 构建、依赖与发布 | [发布指南](release.md) |
| 变更、演练与故障记录 | [记录模板](operations-record-templates.md) |
| 旧 Cloudflare 资料与原始需求 | [历史归档](archive/cloudflare-2026/README.md) |

本次偏差修正和验证范围见 [2026-11-15 文档核对记录](documentation-review-2026-11-15.md)。

## 构建与启动

构建机需要 `go.mod` 指定的 Go 工具链和 Node.js 20.19+ / npm；生产机只需要二进制。

```sh
make pki-console
# 可选交叉编译：make pki-console TARGETOS=linux TARGETARCH=arm64

# 配置 .env.example 的所有必填项并生成独立的随机密钥，再加载到进程环境。
set -a
. /etc/pki-console/pki-console.env
set +a

./bin/pki-console migrate
./bin/pki-console serve
```

`make pki-console` 先构建前端，再将资源编入 `bin/pki-console`（`CGO_ENABLED=0`）。
迁移是显式部署步骤。`serve` 同时启动签发任务，无需第二个进程。
原有 `worker` 子命令仍可供额外扩容使用，`healthcheck` 检查当前本机服务。

同一个监听端口继续区分两个域名：`CONSOLE_BASE_URL` 提供管理页面和 `/api/v1/*`，
`PUBLIC_BASE_URL` 提供公开页面及证书、CRL、OCSP、TSA 发布接口。两者必须使用不同
域名，但可由同一 Nginx、同一 IP 提供。前端根据服务端写入 HTML 的站点类型选择页面，
支持任意配置的域名，不要求域名以 `pki.` 开头。

## 配置

| 变量 | 用途 |
| --- | --- |
| `DATABASE_URL` | 外部 PostgreSQL URL；远程生产数据库必须显式设置 `sslmode=verify-full`，明确的回环 IP 可使用 `sslmode=disable` |
| `PKI_LISTEN_ADDRESS` | 默认 `127.0.0.1:8080`；生产只允许回环地址 |
| `PUBLIC_BASE_URL` | 公开服务 HTTPS origin，不含路径 |
| `CONSOLE_BASE_URL` | 管理控制台 HTTPS origin，不含路径 |
| `ROOT_USER_EMAIL` | 超级管理员邮箱/登录名 |
| `ROOT_USER_PASSWORD` | 超级管理员密码，32–1024 字节；建议随机 ASCII，按原文校验，不裁剪空格 |
| `ROOT_USER_TOTP_SECRET` | 至少 20 随机字节的无填充 Base32 编码；SHA-256、6 位、30 秒 |
| `PKI_MASTER_KEY_ACTIVE_ID` | 新加密信封使用的密钥 ID |
| `PKI_MASTER_KEYS` | JSON 对象；每个值是 32 字节密钥的标准 Base64 编码 |
| `TRUSTED_PROXY_CIDRS` | 允许传入真实客户 IP 的直接 Nginx 对端；同机通常为 `127.0.0.1/32,::1/128` |
| `TSA_MAX_CLOCK_UNCERTAINTY` | Linux 内核 NTP 不确定度上限，默认 `5s`，范围 `1ms`–`1m` |
| `PKI_DEVELOPMENT_INSECURE` | 仅本地开发设为 `true`，允许 HTTP origin 与非 Secure 开发 Cookie |

除监听地址、时钟阈值和开发开关外，表中配置均须填写；示例密码、全零密钥和 TOTP
会被拒绝。生产两个 origin 必须为不同域名，不能仅用端口区分，不含路径、查询、片段或
用户信息。数据库主机名 `localhost` 不等同于明确的回环 IP。
程序直接读取环境，不自动加载 `.env`；全部子命令均校验配置。`CF_ACCESS_*` 和
`PKI_ORIGIN_SHARED_SECRET` 已不再使用。

## 认证与安全边界

2026-11-14 的检查范围、发现、修复、验证和限制见
[安全检查报告](security-review-2026-11-14.md)。独立签发的后续问题与修复见
[2026-11-15 安全与文档复核](security-docs-review-2026-11-15.md)。

- 超级管理员使用本地密码和 TOTP；普通用户、运维人员使用本地账户密码。
  Web 登录始终显示动态验证码输入框，服务器根据账户角色决定是否必填。
- 服务器端会话使用 Secure、HttpOnly、SameSite=Strict 的 `__Host-pki_session`
  Cookie。写请求仍验证 CSRF token，登录与敏感导出拒绝复用已接受的 TOTP。
- 超级管理员私钥导出要求重新输入当前密码与未使用的 TOTP。密码错误、账户锁定、角色权限、
  中间 CA 授权和禁止自审批规则继续生效。
- Nginx 保留业务域名作为 `Host`，覆盖 `X-Forwarded-For`；应用仅在直接对端属于
  可信代理范围时使用该地址。`X-Forwarded-Host`、`Cf-*` 和旧 `X-PKI-*` 头不用于身份认证。
- 管理和公开接口由域名隔离，未配置的 Host 返回 421。未知 API 不回落到 SPA 页面。
- CA 和其他私钥继续以 AES-256-GCM 信封存储，KEK 保留在运维管理的环境中。
  审计记录仍只追加、按月分区并形成哈希链。
- 数据库结构保持兼容，历史 `cf_access_sub` 审计字段保留，新的本地认证不填写该字段。
  升级前执行 `migrate`；认证迁移保存 TOTP 密钥指纹，首次同步和后续密钥轮换会撤销 root 旧会话。

## 开发与测试

```sh
make pki-console-check
make pki-console-e2e
```

数据库集成测试会清空测试数据库，必须使用独立的临时数据库：

```sh
PKI_TEST_DATABASE_URL='postgresql://postgres:test@127.0.0.1:5432/pki_test?sslmode=disable' \
  go test -p 1 ./console/... ./cmd/pki-console ./web
```

测试覆盖签发、审批、吊销、CRL/OCSP/TSA、本地超级管理员登录、TOTP 重放、
会话/CSRF、前端资源与域名隔离。前端质量检查包含 ESLint、TypeScript、Vitest 和 Vite 构建；
Playwright 使用已安装的 Google Chrome，覆盖桌面和移动布局。

本地开发可设置 `PKI_DEVELOPMENT_INSECURE=true`、
`PUBLIC_BASE_URL=http://pki.localhost:5173`、
`CONSOLE_BASE_URL=http://pki-console.localhost:5173`，分别运行 `./bin/pki-console serve`
和 `cd web && npm run dev`。Vite 转发 API 到 8080；超级管理员仍需密码和 TOTP。

数据库测试未提供 `PKI_TEST_DATABASE_URL` 时会跳过。另运行 `make pki-console-security`
（需要 govulncheck 和漏洞库网络）及安装依赖后的 `make pki-console-docs`，见
[文档维护](documentation-maintenance.md)。带日期报告只记录当次结果，不是持续的安全保证。
旧资料见 [历史归档](archive/cloudflare-2026/README.md)。

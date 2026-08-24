# Cloudflare 与 Wrangler 运维记录

本文记录 PKI-Console 在 Cloudflare 上的实际资源、已经完成的操作、尚未完成的权限步骤，以及后续维护方法。敏感值不写入仓库。

日常巡检、告警、备份恢复和事件处置见
[operations-runbook.md](operations-runbook.md)。2026-08-24 Access 邮箱头故障见
[incident-2026-08-24-access-login.md](incident-2026-08-24-access-login.md)。

## 当前资源状态

记录时间：2026-08-24。

| 资源 | 当前值 | 状态 |
| --- | --- | --- |
| Cloudflare Account | `GSC-Admin-Account` / `716dca4a649887332b817b9d44184aa1` | Wrangler OAuth 已登录 |
| 生产服务器 | `LD-S2` / `103.23.11.117` | Ubuntu 24.04 x86_64，Go 服务 active + enabled |
| Pages 项目 | `pki-web` | 已部署 |
| Pages 默认域名 | `pki-web-bk6.pages.dev` | 静态页面可用，API host guard 返回 421 |
| 公开 PKI 域名 | `pki.altasci.com` | Pages `active`，公开访问，不配置 Access |
| 管理域名 | `pki-console.altasci.com` | Pages `active`，已启用 Access |
| 辅助源站域名 | `pki-origin.altasci.com` | 已通过 LD-S2 上线；无共享密钥返回 403 |
| 生产 Tunnel | `LD-S2` / `2fe5715e-451e-4a9d-9527-544434996390` | Healthy，承载生产 origin |
| 回滚 Tunnel | `pki-console-origin` / `f6e04385-8700-4308-9d84-c9153d206ebf` | Inactive，未接入 DNS |
| Access 应用 | `PKI Console` / `ff0ad6a9-f53d-4fcb-9462-ccd6b3661d17` | 已启用，仅允许 root 邮箱 |
| Pages 预览 Access | `PKI Web Pages Previews` / `27138f1e-ff2e-4991-8fd4-fac1160c0b6b` | 已启用，仅允许 root 邮箱 |

Pages Production 已核验以下运行时变量：

- `PKI_ORIGIN_URL=https://pki-origin.altasci.com`
- `PKI_PUBLIC_HOST=pki.altasci.com`
- `PKI_CONSOLE_HOST=pki-console.altasci.com`
- `PKI_ORIGIN_SHARED_SECRET`，类型为加密 Secret

Console 身份链路已经核验：Pages Function 保留 Access JWT，从其 payload 提取仅用于
传输的未受信任 email claim，并通过 `X-PKI-Access-Authenticated-User-Email` 发往
origin。Go 只在可信 Tunnel 对端、origin secret 和 Console hostname 全部通过后还原
Access 邮箱头，随后独立完成 JWT 签名、issuer、AUD、时间和邮箱一致性校验。公共域名
不会转发该身份。

Tunnel 的远程 ingress 已核验为：

```text
pki-origin.altasci.com -> http://127.0.0.1:8080
catch-all              -> http_status:404
```

## 已经执行的操作

1. 使用 Wrangler 4.125.0 验证 OAuth 登录和账户。
2. 创建并提交 `web/wrangler.jsonc`，由 Git 管理 Pages 的非敏感变量和兼容日期。
3. 本地执行完整的 Go 测试、`go vet`、前端 lint、TypeScript、Vitest、Vite build 和 Pages Functions build。
4. 生成独立的 256-bit origin 共享密钥，并写入 Pages Production 加密 Secret。
5. 从 `web` 目录部署静态资源和 Pages Functions 到 `pki-web`。
6. 通过 Pages API 添加 `pki.altasci.com` 和 `pki-console.altasci.com`。
7. 创建专用 Tunnel `pki-console-origin` 作为初始方案；生产部署时改为复用服务器现有的健康 Tunnel `LD-S2`。
8. 确认 Wrangler OAuth 缺少 DNS Write 与 Access Write 后，改用保存在仓库外的最小权限 Custom API Token 完成一次性管理操作。
9. 创建三个 proxied CNAME，并确认两个 Pages 自定义域名的 DNS 与证书状态均为 `active`。
10. 删除错误覆盖公共域名 `pki.altasci.com` 的旧 Access 应用；公共首页已核验为匿名 HTTP 200。
11. 创建 `PKI Console` Self-hosted Access 应用和精确邮箱 Allow Policy，会话有效期为 4 小时。
12. 为 `*.pki-web-bk6.pages.dev` 启用 root-only Access。曾为 Pages 默认域名添加 Access，但它会继承到公共自定义域名，因此已删除；默认域名上的 API 由 Function host allowlist 拒绝。
13. 把新 Console Access AUD 同步到本机和生产环境。
14. 在 LD-S2 安装、迁移并启动 Go 服务，将 origin DNS 和 ingress 切换到 `LD-S2`，完成公网验收。
15. 诊断并修复 Pages 子请求丢失保留 Access 邮箱头的问题；完成后端安全桥接、Pages
    部署、public/origin/Access 探针和真实 root 登录验收。

## 本机凭据位置

以下文件都在仓库外，必须保持 `0600`，不得上传 Git、发送到日志或粘贴到 Issue：

| 文件 | 用途 |
| --- | --- |
| `/home/phil616/.wrangler/config/default.toml` | Wrangler OAuth，由 Wrangler 自己维护 |
| `/home/phil616/.config/pki-console/pki-origin-shared-secret` | Pages 与 Go 共用的 origin 密钥 |
| `/home/phil616/.config/pki-console/cloudflared-tunnel-token` | 未启用的回滚 Tunnel 令牌 |
| `/home/phil616/.config/pki-console/cloudflare-admin-api-token` | 一次性 DNS 与 Access 管理 Token；不再维护 Cloudflare 时可以撤销并删除 |
| `/home/phil616/.config/pki-console/pki-console-production.env` | 生产服务器环境文件的安全本机副本 |
| `/home/phil616/.config/pki-console/pki-console-db-password` | `pki_console` 数据库角色密码 |
| `/home/phil616/.config/pki-console/pki-console-root-password` | 生产 root 登录密码 |
| `/home/phil616/.config/pki-console/pki-console-root-totp-secret` | 生产 root TOTP Secret |
| `/home/phil616/.config/pki-console/pki-console-root-otpauth-uri` | 可导入验证器的 SHA-256 TOTP URI |
| `/home/phil616/.config/pki-console/pki-console-master-key-v1` | 生产 CA 私钥 envelope KEK；必须独立备份 |

检查权限：

```sh
stat -c '%a %n' \
  /home/phil616/.config/pki-console/pki-origin-shared-secret \
  /home/phil616/.config/pki-console/cloudflared-tunnel-token \
  /home/phil616/.config/pki-console/cloudflare-admin-api-token \
  /home/phil616/.config/pki-console/pki-console-production.env \
  /home/phil616/.config/pki-console/pki-console-{db-password,root-password,root-totp-secret,root-otpauth-uri,master-key-v1}
```

所有文件都应显示 `600`。不要把内容打印到日志、Issue 或聊天。

## 已生效的 Cloudflare 配置

### DNS

`altasci.com` 中已创建以下记录：

| Type | Name | Target | Proxy | 状态 |
| --- | --- | --- | --- | --- |
| CNAME | `pki` | `pki-web-bk6.pages.dev` | Proxied | Active |
| CNAME | `pki-console` | `pki-web-bk6.pages.dev` | Proxied | Active |
| CNAME | `pki-origin` | `2fe5715e-451e-4a9d-9527-544434996390.cfargotunnel.com` | Proxied | Active |

不要把前两条改成非 Pages 目标，也不要给公开域名增加 Access。第三条保持 proxied；它不是普通 Web 源站地址。

完成操作时使用的 Custom API Token 最小权限是：

- Account / Access: Apps and Policies / Edit，仅限 `GSC-Admin-Account`；
- Zone / DNS / Edit，仅限 `altasci.com`；
- Zone / Zone / Read，仅限 `altasci.com`。

Token 当前位于：

```text
/home/phil616/.config/pki-console/cloudflare-admin-api-token
```

若近期不再自动维护 DNS 或 Access，应在 Cloudflare Dashboard 撤销该 Token，再删除本机文件；Wrangler 日常 Pages 发布不依赖它。

### Cloudflare Access

已经创建以下 Self-hosted 应用：

| 项目 | 值 |
| --- | --- |
| Name | `PKI Console` |
| Application ID | `ff0ad6a9-f53d-4fcb-9462-ccd6b3661d17` |
| Public hostname | `pki-console.altasci.com`，Path 留空 |
| Application Audience (`AUD`) | `fff53e279a32a88b89ae6af0eed22881b91668bbe6d62ce9dabede332d30ecf1` |
| Session duration | `4h` |
| Allow policy | Email 精确等于 `phil616@163.com` |

这是安全的初始策略。由于 Access 保护整个 Console hostname，目前运维人员和普通用户也必须先通过 Cloudflare Access；需要让他们登录时，应把明确邮箱或受控企业邮箱域加入 Allow Policy，不要使用 `Include Everyone`。

本机 `.env.local` 已更新。生产服务器中的配置必须使用同一个 AUD：

```dotenv
CF_ACCESS_AUD='fff53e279a32a88b89ae6af0eed22881b91668bbe6d62ce9dabede332d30ecf1'
```

更新为新值。`CF_ACCESS_TEAM_DOMAIN` 保持：

```dotenv
CF_ACCESS_TEAM_DOMAIN='https://altasci.cloudflareaccess.com'
```

不要给 `pki.altasci.com` 或 `pki-origin.altasci.com` 配置交互式 Access。公共 PKI 端点必须允许证书客户端匿名获取；辅助 origin 由 Go 的高熵共享密钥保护。

Pages 的不可变预览部署已加固：

| 应用 | Public hostname | Application ID |
| --- | --- | --- |
| `PKI Web Pages Previews` | `*.pki-web-bk6.pages.dev` | `27138f1e-ff2e-4991-8fd4-fac1160c0b6b` |

Preview 只允许 root 邮箱。不要给 `pki-web-bk6.pages.dev` 本身增加 Access：Pages 会把它继承到 `pki.altasci.com`，破坏公共 AIA、CRL 和 OCSP 访问。默认域名上的生产 API 由 Function host allowlist 返回 421。

## 生产 Tunnel Connector

生产服务器已经运行 `cloudflared 2026.8.2`，systemd unit 为 `cloudflared.service`，连接远程管理 Tunnel `LD-S2`。不要再安装 `cloudflared-pki.service`。日常检查：

```sh
sudo systemctl status cloudflared --no-pager
sudo journalctl -u cloudflared -n 100 --no-pager
cd web
npx --no-install wrangler tunnel info 2fe5715e-451e-4a9d-9527-544434996390
```

LD-S2 的远程 ingress 必须保留 PKI hostname 和最后一条 catch-all 404。更新 Tunnel 配置时必须合并而不是覆盖其他服务的规则。

生产 Go 环境文件还必须包含与 Pages 相同的 origin 密钥：

```dotenv
PKI_LISTEN_ADDRESS='127.0.0.1:8080'
PKI_DEVELOPMENT_INSECURE='false'
PKI_ORIGIN_SHARED_SECRET='64_HEX_VALUE_FROM_THE_SECURE_LOCAL_FILE'
TRUSTED_PROXY_CIDRS='127.0.0.1/32,::1/128'
PUBLIC_BASE_URL='https://pki.altasci.com'
CONSOLE_BASE_URL='https://pki-console.altasci.com'
```

## 日常发布

```sh
cd web
npx --no-install wrangler whoami
npm ci --no-audit --no-fund
npm run check
npx --no-install wrangler pages deploy dist \
  --project-name pki-web \
  --branch main
```

`web/wrangler.jsonc` 是普通变量的 source of truth。Secret 不放在该文件中。GitHub tag workflow 使用独立的 `CLOUDFLARE_API_TOKEN`，本机 Wrangler OAuth 不会自动提供给 GitHub Actions。

## 密钥轮换

origin 密钥只支持一个当前值，轮换会有很短的维护窗口：

1. 生成新的 32-byte 随机值并安全保存；
2. 更新 Pages Secret：`wrangler pages secret put PKI_ORIGIN_SHARED_SECRET --project-name pki-web`；
3. 重新发布 Pages，使新 Secret binding 进入当前 deployment；
4. 立即更新生产 `/etc/pki-console/pki-console.env` 中的同名值并重启服务；
5. 验证公开接口、真实 Console 登录和无密钥 origin 的 403；
6. 删除旧值的所有临时副本并结束维护窗口。

第 3 到第 4 步之间 API 会短暂 403。不要由两名操作者在没有同步的情况下分别更新
Pages 和后端。

LD-S2 Tunnel token 泄漏时，在 Cloudflare Dashboard 轮换 token，更新服务器 `/etc/cloudflared/token`，再重启 `cloudflared.service`。Access 应用重建会产生新 AUD，必须同步更新后端并重启。

## 核验命令

```sh
cd web
npx --no-install wrangler pages secret list --project-name pki-web
npx --no-install wrangler pages project list
npx --no-install wrangler tunnel info 2fe5715e-451e-4a9d-9527-544434996390

curl --fail --silent --show-error https://pki.altasci.com/health/live
curl --silent --show-error -o /dev/null -w '%{http_code}\n' \
  https://pki-origin.altasci.com/health/live
```

最后一条不带共享密钥，预期为 HTTP 403。若是 1016，Tunnel Connector 或 DNS 尚未就绪；若是 502，检查 Go 是否监听 `127.0.0.1:8080`。

## 官方资料

- [Wrangler Pages 部署](https://developers.cloudflare.com/pages/how-to/use-direct-upload-with-continuous-integration/)
- [Pages Functions 变量与 Secret](https://developers.cloudflare.com/pages/functions/bindings/)
- [Pages 自定义域名](https://developers.cloudflare.com/pages/configuration/custom-domains/)
- [Pages Preview 与 Access](https://developers.cloudflare.com/pages/configuration/preview-deployments/)
- [Pages 默认域名 Access 已知事项](https://developers.cloudflare.com/pages/platform/known-issues/#enable-access-on-your-pagesdev-domain)
- [Cloudflare Tunnel DNS](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/dns/)
- [Cloudflare Tunnel API 部署](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel-api/)
- [Cloudflare Access JWT 验证](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)

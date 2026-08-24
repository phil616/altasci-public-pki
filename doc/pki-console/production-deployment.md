# PKI-Console 生产部署手册

本文说明如何把同一份 React 构建部署到 Cloudflare Pages，并在 Linux 生产服务器上以 Go 二进制文件、systemd 和本机 PostgreSQL 运行 PKI-Console。

Cloudflare 账户中的实际资源、Wrangler 操作记录和维护命令见 `cloudflare-wrangler-operations.md`。
日常巡检、监控告警、备份恢复、轮换和事件处置见 `operations-runbook.md`。

本文示例使用以下域名，请按实际环境替换：

| 用途 | 域名 | 是否公开 |
| --- | --- | --- |
| PKI 公共仓库、AIA、CRL、OCSP | `pki.altasci.com` | 必须公开，不配置 Access |
| 管理控制台 | `pki-console.altasci.com` | 配置 Cloudflare Access |
| Pages Function 到生产入口 | `pki-origin.altasci.com` | 仅接受带共享密钥的代理请求 |

PKI-Console 应用不使用 Docker，而是以 Go 二进制和 systemd 运行。Go 进程不保存本地业务数据，证书、加密后的 CA 私钥、用户、会话和审计数据全部保存在独立管理的 PostgreSQL 中。当前生产 PostgreSQL 由同机 1Panel 容器提供；它不属于应用容器或应用发布流程。

## 1. 最终架构

```mermaid
flowchart LR
    U[浏览器或 PKI 客户端] --> CF[Cloudflare]
    CF -->|公开域名，无 Access| P[Cloudflare Pages 静态文件]
    CF -->|Console 域名，Access| P
    P -->|API 路径| F[Pages Function 同源代理]
    F -->|HTTPS + 共享密钥| T[pki-origin / Cloudflare Tunnel]
    T -->|127.0.0.1:8080| G[PKI-Console Go]
    G -->|127.0.0.1:5432| D[(1Panel PostgreSQL 18.4)]
```

这里有三个必须遵守的边界：

1. 前端使用 `/api`、`/pki`、`/issuers`、`/crl`、`/ocsp` 和 `/health` 相对路径。Pages 必须通过 Function 把这些路径代理到后端；不需要在浏览器中配置跨域 API 地址。
2. 生产模式下，Go 后端只接受来自 `TRUSTED_PROXY_CIDRS` 的请求，使用恒定时间比较校验 `PKI_ORIGIN_SHARED_SECRET`，再从受信任的 `X-PKI-Forwarded-Host` 恢复公共或 Console 路由。无需 Nginx。
3. Pages Function 只是网络转发层。它从 Access JWT 提取未受信任的 email claim，通过受 origin secret 保护的内部头传递；Go 网关在可信代理、共享密钥和 hostname 校验后还原邮箱头，并重新验证 JWT 签名、issuer、AUD、时间与邮箱一致性。密码、TOTP、会话和权限仍由 Go 后端最终验证。

## 2. 上线前准备

准备以下资源和信息：

- Cloudflare 账户中已经托管 `altasci.com`。
- Cloudflare Pages 项目 `pki-web`，以及已经完成 `wrangler login` 的运维终端。
- 一台受控 Linux 生产服务器，支持 systemd；示例命令以 Debian/Ubuntu 为主。
- PostgreSQL **18 或更高版本**。当前迁移直接调用内置 `uuidv7()`，PostgreSQL 17 及更早版本会迁移失败。
- 生产服务器本机的 PostgreSQL 18+ 管理员账户。应用始终通过 `127.0.0.1:5432` 连接；当前 1Panel Docker 端口发布边界作为单独的已接受网络风险记录在运维 Runbook 中。
- Cloudflare Access Team Domain 和 Console 应用的 Audience (`AUD`) Tag。
- 一套备份、异地保存和恢复演练流程。
- 生产服务器和身份验证设备均启用可靠的 NTP 时间同步；TOTP 对时间偏差敏感。

不要沿用本地测试环境中的 root 密码、TOTP Secret、数据库密码或主密钥。生产值必须重新随机生成，并保存在密码管理器或密钥管理系统中。

## 3. Cloudflare Pages 部署

### 3.1 Pages 部署前必须存在的代理文件

直接上传 `web/dist` 只能显示静态页面，不能访问生产 API。部署前确认仓库中存在以下代理、身份桥接和路由文件；如果尚不存在，应先按仓库实现和测试补齐并纳入版本控制。

`web/functions/[[path]].ts`（以下片段只说明关键边界，仓库文件是唯一可信实现）：

```ts
import { accessEmailClaim } from '../src/lib/access-jwt';

interface Env {
  PKI_ORIGIN_URL: string;
  PKI_ORIGIN_SHARED_SECRET: string;
  PKI_PUBLIC_HOST: string;
  PKI_CONSOLE_HOST: string;
}

const backendPrefixes = ['/api', '/pki', '/issuers', '/crl', '/ocsp', '/health'];

function isBackendPath(pathname: string): boolean {
  return backendPrefixes.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

export const onRequest: PagesFunction<Env> = async ({ request, env }) => {
  const incoming = new URL(request.url);
  const hostname = incoming.hostname.toLowerCase();
  const publicHost = env.PKI_PUBLIC_HOST.toLowerCase();
  const consoleHost = env.PKI_CONSOLE_HOST.toLowerCase();

  if (hostname !== publicHost && hostname !== consoleHost) {
    return new Response('Unknown application host', { status: 421 });
  }
  if (!isBackendPath(incoming.pathname)) {
    return new Response('Not found', { status: 404 });
  }

  const origin = new URL(env.PKI_ORIGIN_URL);
  if (origin.protocol !== 'https:' || origin.username || origin.password) {
    return new Response('Invalid origin configuration', { status: 500 });
  }

  const upstream = new URL(incoming.pathname + incoming.search, origin);
  const clientIP = request.headers.get('CF-Connecting-IP');
  const headers = new Headers(request.headers);

  // 丢弃客户端可伪造的内部头，再写入 Function 自己生成的值。
  for (const name of [
    'host',
    'content-length',
    'cf-access-authenticated-user-email',
    'cf-connecting-ip',
    'forwarded',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-pki-origin-secret',
    'x-pki-forwarded-host',
    'x-pki-client-ip',
    'x-pki-access-authenticated-user-email',
  ]) {
    headers.delete(name);
  }
  headers.set('X-PKI-Origin-Secret', env.PKI_ORIGIN_SHARED_SECRET);
  headers.set('X-PKI-Forwarded-Host', hostname);

  if (clientIP) headers.set('X-PKI-Client-IP', clientIP);

  // Console 请求保留 Access JWT 和应用会话 Cookie。Access 的保留邮箱头
  // 可能在子请求中被 Cloudflare 删除，因此使用受保护的内部头传递 JWT claim。
  // 公共域名不向 PKI 公共接口转发任何认证信息。
  if (hostname === publicHost) {
    headers.delete('authorization');
    headers.delete('cf-access-jwt-assertion');
    headers.delete('cookie');
  } else {
    const email = accessEmailClaim(headers.get('cf-access-jwt-assertion'));
    if (!email) return new Response('Cloudflare Access identity is unavailable', { status: 401 });
    headers.set('X-PKI-Access-Authenticated-User-Email', email);
  }

  const init: RequestInit = {
    method: request.method,
    headers,
    redirect: 'manual',
  };
  if (request.method !== 'GET' && request.method !== 'HEAD') init.body = request.body;

  let response: Response;
  try {
    response = await fetch(upstream, init);
  } catch {
    return new Response('PKI origin is unavailable', { status: 502 });
  }
  const responseHeaders = new Headers(response.headers);
  if (hostname === consoleHost) responseHeaders.set('Cache-Control', 'private, no-store');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
};
```

`accessEmailClaim` 只解析 payload 以便传输，不能判断 JWT 是否可信。Go 后端仍必须验证
签名、issuer、AUD、有效期以及 JWT、内部邮箱和 `ROOT_USER_EMAIL` 的一致性。Function
和 Go 网关都必须先删除客户端提供的同名内部头。不要把上述片段复制为新实现；修改时
直接维护仓库文件及其测试。

`web/public/_routes.json`：

```json
{
  "version": 1,
  "include": [
    "/api/*",
    "/pki/*",
    "/issuers/*",
    "/crl/*",
    "/ocsp/*",
    "/health/*"
  ],
  "exclude": []
}
```

`web/public/_redirects`，用于 React Router 深层链接回退：

```text
/* /index.html 200
```

`web/public/_headers`，用于保护 Pages 直接返回的静态文件：

```text
/*
  Content-Security-Policy: default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; upgrade-insecure-requests
  Referrer-Policy: no-referrer
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
  Strict-Transport-Security: max-age=31536000
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY

/index.html
  Cache-Control: no-cache

/assets/*
  Cache-Control: public, max-age=31536000, immutable
```

Vite 会把 `web/public` 中的三个配置文件复制到 `dist`。`_headers` 负责静态响应；Function 代理的 API 响应继续使用 Go 后端生成的安全头。构建后检查：

```sh
cd web
npm ci --no-audit --no-fund
npm run check
test -f dist/_routes.json
test -f dist/_redirects
test -f dist/_headers
cd ..
```

### 3.2 Wrangler 管理的 Pages 项目

Pages 项目名称固定为 `pki-web`。仓库中的 `web/wrangler.jsonc` 是非敏感 Pages 配置的 source of truth，包含兼容日期、构建目录和三个普通运行时变量。前端使用同源相对路径，不配置 `VITE_API_BASE_URL`。

首次或日常部署：

```sh
cd web
npx --no-install wrangler whoami
npm ci --no-audit --no-fund
npm run check
npx --no-install wrangler pages deploy dist --project-name pki-web --branch main
```

`functions/` 必须与 `dist/` 同级；从 `web` 目录执行部署时，Wrangler 会同时发布静态资源和 Pages Functions。

### 3.3 Pages Function 运行时变量

普通变量已经提交在 `web/wrangler.jsonc`：

| 名称 | 类型 | 示例 |
| --- | --- | --- |
| `PKI_ORIGIN_URL` | 普通变量 | `https://pki-origin.altasci.com` |
| `PKI_PUBLIC_HOST` | 普通变量 | `pki.altasci.com` |
| `PKI_CONSOLE_HOST` | 普通变量 | `pki-console.altasci.com` |
| `PKI_ORIGIN_SHARED_SECRET` | **加密 Secret** | 不写入 `wrangler.jsonc` |

生成 origin 共享密钥：

```sh
openssl rand -hex 32
```

使用 Wrangler 写入 Pages Production Secret：

```sh
npx --no-install wrangler pages secret put PKI_ORIGIN_SHARED_SECRET --project-name pki-web
```

同一个值必须写入生产服务器的 `/etc/pki-console/pki-console.env`。不要把它写入 Git、Wrangler 普通变量、命令行参数、构建日志或本文档。

Preview 环境必须使用独立的测试 origin 和独立密钥，或者完全不设置生产代理变量，使预览构建无法访问生产 CA。不要让 PR Preview 连接生产数据库和生产签发服务。

每次修改 Pages 的变量或 Secret 后重新部署一次，确保新绑定进入当前部署。

### 3.4 绑定两个自定义域名

在 Pages 项目的 **Custom domains** 中依次添加：

- `pki.altasci.com`
- `pki-console.altasci.com`

必须从 Pages 的 **Set up a domain** 流程添加，不要只手工创建指向 `*.pages.dev` 的 CNAME。

Cloudflare 当前不允许给已经存在 Access Policy 的域名直接绑定 Pages。如果 `pki-console.altasci.com` 已经启用 Access：

1. 先记录应用的 Policy、Session Duration 和 `AUD`。
2. 临时删除或停用该 hostname 上的 Access 应用。
3. 在 Pages 中添加域名并等待状态变为 Active。
4. 再为该自定义域名重新创建 Access 应用和策略。

给 `*.pki-web-bk6.pages.dev` Preview 域名配置 Access，避免从不可变预览 URL 访问界面。不要给 `pki-web-bk6.pages.dev` 本身增加 Access，因为 Pages 会把它继承到公共自定义域名；默认域名上的生产 API 由 Function host allowlist 返回 421。

### 3.5 配置 Cloudflare Access

只在 `pki-console.altasci.com` 上创建 **Self-hosted** Access 应用。`pki.altasci.com` 必须保持公开，否则证书中的 AIA、CRL 和 OCSP URL 将要求交互式登录，TLS 客户端无法完成校验。

建议设置：

- Public hostname：`pki-console.altasci.com`，Path 留空。
- Session Duration：不长于后端超级管理员最大会话时间；当前后端 root 会话最大为 4 小时。
- Allow Policy：允许实际使用 Console 的身份；对 root 邮箱启用强 MFA 的身份提供方策略。
- `ROOT_USER_EMAIL` 必须与 Access 身份中的邮箱一致。
- 从该应用详情复制 **Application Audience (AUD) Tag**，写入后端的 `CF_ACCESS_AUD`。
- Team Domain 写成 `https://<team>.cloudflareaccess.com`，不要写应用域名。

当前 Console 登录页面和 `/api/v1/auth/login` 是所有角色共用的。若对整个 Console hostname 启用 Access，运维人员和普通用户也会先经过 Cloudflare 的边缘登录页；Go 后端只对 `super_admin` 强制校验 Access JWT。若业务要求普通用户完全不经过 Access，需要后续拆分独立的 root 管理 hostname/登录入口，不能用一个全域 Bypass Policy 与 root 强认证同时可靠实现。

## 4. 构建和安装 Go 二进制

推荐在受控 CI 或构建机从已审核的 commit 构建，而不是在生产服务器临时拉取源码：

```sh
go test ./console/... ./cmd/pki-console
go vet ./console/... ./cmd/pki-console
make pki-console TARGETOS=linux TARGETARCH=amd64
sha256sum bin/pki-console
```

ARM64 服务器把 `TARGETARCH` 改为 `arm64`。该目标使用 `CGO_ENABLED=0`，生产运行时不需要 Go 工具链或 CFSSL CLI 二进制。

把二进制和校验值传到服务器，核对后安装：

```sh
sha256sum /tmp/pki-console
sudo install -o root -g root -m 0755 /tmp/pki-console /usr/local/bin/pki-console
```

创建专用系统账户和配置目录：

```sh
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin pki-console
sudo install -d -o root -g pki-console -m 0750 /etc/pki-console
sudo install -d -o root -g root -m 0755 /usr/local/share/doc/pki-console
```

如果系统的 `nologin` 位于 `/sbin/nologin`，按发行版调整。不要让服务以 root 身份运行。

## 5. 初始化本机 PostgreSQL

### 5.1 数据库版本和网络

使用 PostgreSQL 18+。Go 通过显式地址 `127.0.0.1:5432` 连接；这种同机链路允许使用 `sslmode=disable`。代码不会允许远程数据库在生产模式下关闭 TLS，也不会把 `localhost` 当作显式 loopback IP。当前实例由 1Panel 容器 `1Panel-postgresql-Ux15` 提供；可从 1Panel 终端或容器内进入 `psql`，不要因应用升级重建数据库容器。

在生产服务器上以数据库管理员身份连接默认数据库：

```sh
sudo -u postgres psql -d postgres
```

在 `psql` 内执行：

```sql
CREATE ROLE pki_console LOGIN;
ALTER ROLE pki_console NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password pki_console

CREATE DATABASE pki_console
  OWNER pki_console
  TEMPLATE template0
  ENCODING 'UTF8';

REVOKE ALL ON DATABASE pki_console FROM PUBLIC;
\connect pki_console
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO pki_console;
```

使用 `\password` 交互输入随机密码，避免密码进入 SQL 历史和数据库日志。数据库密码若含 `@`、`:`、`/`、`?`、`#` 或 `%`，写进 `DATABASE_URL` 前必须进行 URL percent-encoding。

当前应用在写审计事件时会按月调用 `pki_create_audit_partition` 创建分区，因此基线部署使用数据库 owner 角色同时执行迁移和运行服务。不要在未调整分区函数权限模型前移除该角色的 schema 创建能力。

### 5.2 验证 PostgreSQL 18 能力

使用应用角色通过 TCP loopback 连接并检查：

```sh
psql 'postgresql://pki_console@127.0.0.1:5432/pki_console?sslmode=disable' \
  -v ON_ERROR_STOP=1 \
  -c 'SHOW server_version;' \
  -c 'SELECT uuid_extract_version(uuidv7());'
```

最后一条查询应返回 `7`。如果提示 `uuidv7()` 不存在，不要修改迁移去模拟旧行为，应升级数据库到 PostgreSQL 18+。

### 5.3 本机数据库边界

检查 PostgreSQL 监听地址：

```sh
sudo -u postgres psql -Atqc 'SHOW listen_addresses; SHOW port;'
ss -ltnp 'sport = :5432'
```

应用连接目标必须保持 `127.0.0.1:5432`。当前 1Panel Docker proxy 曾观察为同时发布 `0.0.0.0:5432` 和 `[::]:5432`；项目负责人已接受当前阶段的该网络边界，具体风险和后续复核见 `operations-runbook.md`。若以后把数据库迁移到其他主机，必须改用 `sslmode=verify-full` 和受信任 CA。

## 6. 编写生产环境配置

应用只读取进程环境，不会自行解析 `.env` 文件。systemd 通过 `EnvironmentFile` 加载 `/etc/pki-console/pki-console.env`。

分别生成并安全保存以下值：

```sh
# root 密码：结果明显超过 32 个字符
openssl rand -base64 48

# TOTP：20 个随机字节、无 Base32 padding
openssl rand 20 | base32 | tr -d '=\n'

# AES-256-GCM KEK：正好 32 个随机字节，标准 Base64
openssl rand -base64 32 | tr -d '\n'
```

把 TOTP Secret 通过安全渠道导入超级管理员的验证器。参数必须为 `SHA256`、6 位、30 秒，例如：

```text
otpauth://totp/PKI-Console:root@example.com?secret=BASE32_SECRET&issuer=PKI-Console&algorithm=SHA256&digits=6&period=30
```

创建 `/etc/pki-console/pki-console.env`，不要写 `export`，也不要在值中引用其他变量：

```dotenv
DATABASE_URL='postgresql://pki_console:URL_ENCODED_PASSWORD@127.0.0.1:5432/pki_console?sslmode=disable'

PKI_LISTEN_ADDRESS='127.0.0.1:8080'
PKI_DEVELOPMENT_INSECURE='false'
PKI_ORIGIN_SHARED_SECRET='REPLACE_WITH_SAME_64_HEX_SECRET_AS_PAGES'

ROOT_USER_EMAIL='root@example.com'
ROOT_USER_PASSWORD='REPLACE_WITH_NEW_PRODUCTION_PASSWORD_AT_LEAST_32_CHARS'
ROOT_USER_TOTP_SECRET='REPLACE_WITH_UNPADDED_BASE32_SECRET'

CF_ACCESS_TEAM_DOMAIN='https://altasci.cloudflareaccess.com'
CF_ACCESS_AUD='fff53e279a32a88b89ae6af0eed22881b91668bbe6d62ce9dabede332d30ecf1'

PKI_MASTER_KEY_ACTIVE_ID='v1'
PKI_MASTER_KEYS='{"v1":"REPLACE_WITH_BASE64_OF_EXACTLY_32_BYTES"}'

PUBLIC_BASE_URL='https://pki.altasci.com'
CONSOLE_BASE_URL='https://pki-console.altasci.com'

TRUSTED_PROXY_CIDRS='127.0.0.1/32,::1/128'
```

注意：上面 `PKI_MASTER_KEYS` 的实际文件内容是合法 JSON，键和值外围是普通双引号；整段 JSON 外围使用单引号。不要在双引号前添加反斜杠。

锁定权限：

```sh
sudo chown root:pki-console /etc/pki-console/pki-console.env
sudo chmod 0640 /etc/pki-console/pki-console.env
sudo chmod 0750 /etc/pki-console
```

关键配置说明：

- `PKI_LISTEN_ADDRESS` 必须绑定 `127.0.0.1`，不要在公网监听 `:8080`。
- `PKI_DEVELOPMENT_INSECURE` 在生产必须为 `false`。
- `PUBLIC_BASE_URL` 会进入新签发证书的 AIA、CRL 和 OCSP URI，生产启用后不要随意更换。
- `ROOT_USER_EMAIL` 同时是 root 的登录名；每次服务启动会以环境配置同步 root 邮箱、密码和 active 状态。
- `ROOT_USER_PASSWORD` 至少 32 个字符。
- `ROOT_USER_TOTP_SECRET` 是至少 160 bit 的无 padding Base32。
- `PKI_MASTER_KEYS` 的每个值解码后必须恰好为 32 bytes；丢失旧 KEK 会导致对应 CA 私钥永久无法解密。
- `PKI_ORIGIN_SHARED_SECRET` 必须是 64 个十六进制字符，与 Pages Secret 完全一致。
- `TRUSTED_PROXY_CIDRS` 这里只信任本机 cloudflared。不要为了“获取真实 IP”直接信任 `0.0.0.0/0`。

数据库备份与 `PKI_MASTER_KEYS` 必须分别加密、分别保管：只备份数据库无法恢复 CA 私钥；数据库和 KEK 同时泄漏则 CA 私钥可能被解密。

## 7. 配置生产入口

Cloudflare Tunnel 直接连接 Go，不安装 Nginx。生产服务器无需开放 80、443 或 8080 入站端口。

### 7.1 创建 Published application

在 **Zero Trust > Networks > Tunnels** 中选择生产服务器使用的 Tunnel，添加：

| 项目 | 值 |
| --- | --- |
| Public hostname | `pki-origin.altasci.com` |
| Service type | HTTP |
| URL | `127.0.0.1:8080` |

如果使用本地管理的 Tunnel，对应 ingress 是：

```yaml
ingress:
  - hostname: pki-origin.altasci.com
    service: http://127.0.0.1:8080
  - service: http_status:404
```

Go 在进入业务路由前完成以下操作：

1. 确认 TCP 对端属于 `TRUSTED_PROXY_CIDRS`；
2. 恒定时间校验 `X-PKI-Origin-Secret`；
3. 仅允许 `pki.altasci.com` 或 `pki-console.altasci.com` 作为转发域名；
4. 恢复 Pages 记录的客户端 IP，读取后删除内部 `X-PKI-*` 请求头；
5. 仅对 Console hostname 把内部邮箱桥接值还原为 Access 邮箱头；
6. 保留 Access JWT，由后端重新验证签名、issuer、AUD、时间和邮箱一致性。

### 7.2 启动 cloudflared

生产服务器已运行远程管理 Tunnel `LD-S2`（ID `2fe5715e-451e-4a9d-9527-544434996390`）和 `cloudflared.service`。PKI 使用该现有 Connector，不安装第二个 cloudflared unit。检查：

```sh
sudo systemctl status cloudflared --no-pager
sudo journalctl -u cloudflared -n 100 --no-pager
```

远程 ingress 为：

```sh
pki-origin.altasci.com -> http://127.0.0.1:8080
catch-all              -> http_status:404
```

不要给 `pki-origin.altasci.com` 创建交互式 Access 应用，否则 Access 可能替换来自 Console 域名的用户 JWT。该辅助域名只能由 Pages Function 使用；无共享密钥的请求会被 Go 拒绝。共享密钥泄漏时，必须同时轮换 Pages Secret 和后端环境变量。

Go 必须绑定 `127.0.0.1:8080`。不要把 8080 暴露到公网，也不要把 `TRUSTED_PROXY_CIDRS` 配成全网段。

## 8. 运行迁移

迁移是显式部署步骤，服务启动不会自动改变 schema。先从生产服务器确认数据库备份点已经创建，然后以服务账户加载同一份环境文件：

```sh
sudo -u pki-console env -i /bin/sh -c \
  'set -a; . /etc/pki-console/pki-console.env; set +a; exec /usr/local/bin/pki-console migrate'
```

迁移成功后验证版本表和审计分区：

```sql
SELECT * FROM goose_db_version ORDER BY id DESC LIMIT 5;
SELECT inhrelid::regclass AS partition
FROM pg_inherits
WHERE inhparent = 'audit_events'::regclass
ORDER BY 1;
```

`migrate` 会完整加载并校验所有安全配置，不只是 `DATABASE_URL`。若命令报告缺少环境变量、密码长度不足、TOTP/Base64 格式错误、HTTP URL 或数据库禁用 TLS，必须修复配置后再继续。

## 9. 安装 systemd unit

仓库已经提供 `doc/pki-console/pki-console.service`：

```sh
sudo install -o root -g root -m 0644 doc/pki-console/pki-console.service \
  /etc/systemd/system/pki-console.service
sudo install -o root -g root -m 0644 doc/pki-console/README.md \
  /usr/local/share/doc/pki-console/README.md
sudo install -o root -g root -m 0644 doc/pki-console/production-deployment.md \
  /usr/local/share/doc/pki-console/production-deployment.md

sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/pki-console.service
```

unit 使用 `User=pki-console`、`EnvironmentFile=/etc/pki-console/pki-console.env` 和 `/usr/local/bin/pki-console serve`，并包含文件系统、capability、namespace、设备和内核访问限制。应用只写 PostgreSQL 和 stdout/stderr，因此不需要本地可写数据目录。

## 10. `systemctl start` 之前的完整检查清单

在第一次执行 `sudo systemctl start pki-console` 前，逐项确认：

- [ ] 生产 commit 已审核，后端测试、`go vet`、前端 `npm run check` 全部通过。
- [ ] Linux 架构与二进制匹配，SHA-256 与构建产物一致，binary 为 `root:root 0755`。
- [ ] 专用 `pki-console` 用户存在且不能交互登录。
- [ ] PostgreSQL 是 18+，应用角色可通过 `127.0.0.1:5432` 和 `sslmode=disable` 连接，`uuidv7()` 验证返回 7。
- [ ] 已确认 PostgreSQL 的实际 Docker 发布边界，并建立初始备份/PITR 恢复点。
- [ ] `/etc/pki-console/pki-console.env` 的所有者和权限正确。
- [ ] root 密码、TOTP、数据库密码、KEK、origin 共享密钥均为新的生产随机值，且相互不同。
- [ ] TOTP 已导入至少一个受控设备，服务器和设备时间同步。
- [ ] `PUBLIC_BASE_URL` 与 `CONSOLE_BASE_URL` 使用两个不同 HTTPS hostname。
- [ ] `pki.altasci.com` 没有 Access，能够被未登录客户端访问。
- [ ] Console Access 应用已启用，root Access 身份邮箱与 `ROOT_USER_EMAIL` 完全一致，Team Domain 和 `AUD` 正确。
- [ ] Pages 两个自定义域名均为 Active；Function、`_routes.json`、`_redirects` 和 `_headers` 已随最新部署发布。
- [ ] Pages Production 变量完整，`PKI_ORIGIN_SHARED_SECRET` 是加密 Secret；Preview 不连接生产 origin。
- [ ] Pages Secret 和后端 `PKI_ORIGIN_SHARED_SECRET` 完全一致。
- [ ] Go 配置为 `127.0.0.1:8080`，服务器防火墙没有开放 8080。
- [ ] 现有 `cloudflared.service` 和 LD-S2 Tunnel 为 Healthy，ingress 指向 `http://127.0.0.1:8080`。
- [ ] 未携带共享密钥直接访问 origin 返回 403。
- [ ] `pki-console migrate` 已成功，`goose_db_version` 和审计分区存在。
- [ ] systemd unit 已安装，`daemon-reload` 和 `systemd-analyze verify` 已通过。
- [ ] 数据库备份和 `PKI_MASTER_KEYS` 有相互独立、可恢复的加密副本。
- [ ] 已配置 journald 转储/集中日志、主机和数据库监控、证书/CRL/OCSP 可用性告警。

## 11. 首次启动和验收

先启动但暂不设置开机自启：

```sh
sudo systemctl start pki-console
sudo systemctl status pki-console --no-pager
sudo systemctl status cloudflared --no-pager
sudo journalctl -u pki-console -n 100 --no-pager
```

首次 `serve` 会创建或同步唯一超级管理员，root 登录名就是 `ROOT_USER_EMAIL`。日志应出现 `root account synchronized` 和监听地址，不应打印任何密钥。

加载环境并运行内置存活检查：

```sh
sudo -u pki-console env -i /bin/sh -c \
  'set -a; . /etc/pki-console/pki-console.env; set +a; exec /usr/local/bin/pki-console healthcheck'
```

从服务器直接验证两个路由。生产模式必须模拟 Pages Function 的内部请求头：

```sh
sudo -u pki-console env -i /bin/sh -c '
  set -a; . /etc/pki-console/pki-console.env; set +a
  curl --fail --silent --show-error \
    -H "X-PKI-Origin-Secret: $PKI_ORIGIN_SHARED_SECRET" \
    -H "X-PKI-Forwarded-Host: pki-console.altasci.com" \
    http://127.0.0.1:8080/api/v1/health/ready
  curl --fail --silent --show-error \
    -H "X-PKI-Origin-Secret: $PKI_ORIGIN_SHARED_SECRET" \
    -H "X-PKI-Forwarded-Host: pki.altasci.com" \
    http://127.0.0.1:8080/health/live
'
```

再从互联网验收：

```sh
curl --fail --silent --show-error https://pki.altasci.com/health/live
curl --fail --silent --show-error https://pki.altasci.com/pki/v1/authorities
curl --silent --show-error -o /dev/null -w '%{http_code}\n' \
  https://pki-origin.altasci.com/health/live
```

最后一条没有共享密钥的 origin 请求应返回 `403`。在浏览器打开 Console，先完成 Access 登录，再用 root 邮箱、root 密码和 SHA-256 TOTP 登录。创建一套非生产测试 CA/证书，检查申请、审批、签发、下载、吊销、CRL、OCSP 和审计事件全链路后，再创建正式根 CA。

全部通过后设置开机自启：

```sh
sudo systemctl enable pki-console
sudo systemctl is-enabled pki-console
```

## 12. 日常升级、备份和密钥管理

每次发布采用以下顺序：

1. 在构建机运行测试并生成带 commit/version 的二进制和校验值。
2. 创建数据库备份或可回滚恢复点。
3. 把新 binary 安装为临时文件，校验后原子替换 `/usr/local/bin/pki-console`。
4. 使用生产环境文件运行 `pki-console migrate`。
5. `systemctl restart pki-console`。
6. 执行内置 healthcheck、外部公开检查、Console 登录和关键 PKI 探针。
7. 观察 JSON 日志、HTTP 5xx、签发队列、数据库连接、CRL 与 OCSP 指标。

数据库至少启用加密备份、PITR 和定期恢复演练。恢复演练必须同时验证正确版本的 `PKI_MASTER_KEYS` 能解密 CA key envelope；不要只验证表能读取。

新增主密钥时，把新 ID 加入 `PKI_MASTER_KEYS` 并设为 `PKI_MASTER_KEY_ACTIVE_ID`。在确认所有仍需读取的 envelope 已完成相应迁移前，绝不能删除旧 key ID。root 密码、TOTP 或 Access 配置变更后需要重启服务，root 环境凭据会在启动时同步。

## 13. 常见故障

| 现象 | 优先检查 |
| --- | --- |
| Pages 页面能打开，但 API 返回 HTML 或 404 | `web/functions/[[path]].ts`、构建产物 `_routes.json`、Function 部署日志 |
| API 返回 421 `unknown_host` | Pages 的 `X-PKI-Forwarded-Host` 和两个 Base URL |
| origin 返回 403 | Pages Secret 与 Go 环境变量不一致、cloudflared 不在可信网段，或 Secret 修改后未重新部署 |
| Pages 返回 502/504 | cloudflared、Go 服务状态和本地 8080 连通性 |
| 迁移提示 `uuidv7()` 不存在 | PostgreSQL 低于 18 |
| 迁移提示 permission denied | `pki_console` 不是数据库/schema owner，或缺少 schema CREATE 权限 |
| 数据库 TLS 校验失败 | URL hostname 与证书 SAN、`sslrootcert` 路径/权限、CA 链 |
| root 登录统一提示认证失败 | 安全日志中的 JWT/email present/match 字段、Pages 内部邮箱桥接、Team Domain/AUD、密码、SHA-256 TOTP、NTP 时间 |
| root 登录后其他 API 立即 401 | Pages 是否在每个请求上保留 Access JWT 并重建内部邮箱头；Access session 是否过期 |
| 普通用户看到了 Access 登录页 | 整个 Console hostname 已受 Access 保护；如不允许，需要拆分 root 专用 hostname |
| 公共证书/CRL/OCSP 出现 Access 登录页 | 错误地给 `pki.altasci.com` 配置了 Access，必须移除 |
| Pages 自定义域名无法激活 | 先移除该 hostname 上既有 Access/Worker route，检查 CAA，再从 Pages UI 重新添加 |
| 审计中只有代理 IP | `TRUSTED_PROXY_CIDRS` 和 Function 的 `X-PKI-Client-IP` |

连续 5 次 root 登录失败会触发 15 分钟锁定。不要在不确认 Access/TOTP 配置时反复尝试同一个生产账户。

## 14. 官方参考

- [Cloudflare Pages 自定义域名](https://developers.cloudflare.com/pages/configuration/custom-domains/)
- [Cloudflare Pages 已知问题](https://developers.cloudflare.com/pages/platform/known-issues/)
- [Cloudflare Pages Functions](https://developers.cloudflare.com/pages/functions/)
- [Pages Functions 路由和 `_routes.json`](https://developers.cloudflare.com/pages/functions/routing/)
- [Pages 变量与加密 Secrets](https://developers.cloudflare.com/pages/functions/bindings/)
- [Pages 静态响应与自定义 Headers](https://developers.cloudflare.com/pages/configuration/serving-pages/)
- [Pages 构建镜像与 Node 版本](https://developers.cloudflare.com/pages/configuration/build-image/)
- [Cloudflare Access JWT 校验](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Linux 上以 systemd 运行 cloudflared](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/as-a-service/linux/)
- [PostgreSQL 18 UUID 函数](https://www.postgresql.org/docs/18/functions-uuid.html)

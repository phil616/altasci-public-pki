# 桌面客户端接入

当前版本直接调用管理域名的本地认证 API，无需 Cloudflare Managed OAuth、PKCE 或
外部浏览器授权。服务端 API 合约见 [openapi.yaml](openapi.yaml)。

## 登录与会话

向管理域名发送 HTTPS 请求：

```http
POST /api/v1/auth/login
Content-Type: application/json

{"login":"alice@example.com","password":"local-password"}
```

超级管理员必须额外提供 `totp`，使用 SHA-256、6 位、30 秒的动态验证码。
已成功使用的验证码不能重放，也不能再次用于私钥导出。

成功返回用户信息、`csrf_token`、`expires_at`，并设置
`__Host-pki_session`（Secure、HttpOnly、SameSite=Strict、Path=/，无 Domain）。
客户端应使用独立的 Cookie jar，后续管理 API 请求自动携带该 Cookie。
不要把密码或验证码放入 URL、日志或长期存储中。需要跨重启保留登录时使用平台安全存储
保存会话 Cookie 与 CSRF token。

```http
GET /api/v1/auth/session
Cookie: __Host-pki_session=<session-token>
```

写操作（包括退出、POST 下载、PUT、PATCH、DELETE）同时发送登录结果中的 CSRF token：

```http
POST /api/v1/auth/logout
Cookie: __Host-pki_session=<session-token>
X-CSRF-Token: <csrf-token>
```

退出成功返回 204、撤销服务端会话并清除 Cookie。客户端也应清空 Cookie jar 和 CSRF token。
401 表示登录、会话或 CSRF 校验失败，需要重新建立会话；403 表示权限不足或敏感操作
二次验证失败。429 按 `Retry-After` 等待后重试。所有响应都应正确处理非 JSON 网络错误。

## 幂等、下载与公开接口

需要重试的关键写操作使用 8–128 字符的 `Idempotency-Key`。同一次操作重试保持原 key
和内容；不同内容使用新 key。响应中的 `Idempotency-Replayed` 表示是否复用了结果。

CA 私钥导出仍要求在 JSON 中提供新密码和 TOTP；服务器生成的叶私钥仍为一次性下载，
成功下载后不能重新获取。

公开域名上的 `/pki/v1/*`、`/issuers/*`、`/crl/*`、`/ocsp/*`、`/tsa/*` 不需要本地会话。
公开域名不提供管理 API；两个 origin 不能互换。

## 从旧客户端迁移

移除 Cloudflare OAuth 元数据发现、浏览器授权、token 刷新和 `Authorization: Bearer`
注入流程，保留本地登录、Cookie jar、CSRF、幂等与下载处理。
不发送 `Cf-Access-*`、旧 `X-PKI-*` 或代理地址头。应用不再信任这些头来确定身份。
若通用 HTTP 层原本在收到任何 401 时触发外部浏览器登录，应改为提示本地重新登录。

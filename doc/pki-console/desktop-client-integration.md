# 桌面客户端接入

状态：当前指南；核对日期：2026-11-15。

当前版本直接调用管理域名的本地认证 API，无需 Cloudflare Managed OAuth、PKCE 或
外部浏览器授权。服务端 API 合约见 [openapi.yaml](openapi.yaml)。

## 登录与会话

向管理域名发送 HTTPS 请求：

```http
POST /api/v1/auth/login
Content-Type: application/json

{"login":"alice@example.com","password":"replace-with-account-password"}
```

超级管理员必须额外提供 `totp`，使用 SHA-256、6 位、30 秒的动态验证码。
已成功使用的验证码不能重放，也不能再次用于私钥导出。
密码正确但未提供 TOTP 时返回 401 `second_factor_required`，客户端应提示补充验证码；
该情况不累计账户失败次数，IP 限流仍生效。错误密码、无效或重放的验证码继续累计失败次数。

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
401 表示凭据错误、需要补充 TOTP 或会话无效，应按错误码处理；会话无效时重新登录。
403 `csrf_failed` 表示 CSRF 不匹配，其他 403 可能是权限不足或敏感操作二次验证失败。
429 按 `Retry-After` 等待后重试。所有响应都应正确处理非 JSON 网络错误。

普通会话空闲 8 小时、绝对 24 小时；超级管理员空闲 30 分钟、绝对 4 小时。
`/auth/session` 只返回用户信息，不补发 CSRF token。账户禁用或密码变更也会使会话失效。
根账户的敏感导出二次验证失败或每分钟 5 次限额用尽返回 403；不要将全部 403 当作可立即重试。
503 `authentication_unavailable` 表示认证存储暂不可用，不应标记密码错误或清除既有凭据；
其他 503 也可能表示审计不可用，操作未进入业务处理。

## 幂等、下载与公开接口

仅对 OpenAPI 标明支持的写操作，可选使用 8–128 字节的 `Idempotency-Key`。
同一次操作重试保持原 key
和内容；不同内容使用新 key。服务端保存结果 24 小时，不缓存 5xx，
同 key 内容不同返回 409；重放仍需会话和 CSRF 验证，但不重新执行业务处理函数。
响应中的 `Idempotency-Replayed` 表示是否复用了结果。

CA 私钥导出要求在 JSON 中重新输入当前密码及未使用的 TOTP，不是设置新密码。
服务器生成的叶私钥只供申请者在 24 小时内一次性领取；服务端在发送响应前提交擦除，
网络中断或保存失败也可能无法重取。该接口和 CA 私钥导出不支持幂等重放。

公开域名上的 `/pki/v1/*`、`/issuers/*`、`/crl/*`、`/ocsp/*`、`/tsa/*` 不需要本地会话。
公开域名不提供管理 API；两个 origin 不能互换。

## 从旧客户端迁移

移除 Cloudflare OAuth 元数据发现、浏览器授权、token 刷新和 `Authorization: Bearer`
注入流程，保留本地登录、Cookie jar、CSRF、幂等与下载处理。
不发送 `Cf-Access-*`、旧 `X-PKI-*` 或代理地址头。应用不再信任这些头来确定身份。
若通用 HTTP 层原本在收到任何 401 时触发外部浏览器登录，应改为提示本地重新登录。

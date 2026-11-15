# 用户名密码认证

状态：当前指南；核对日期：2026-11-16。管理员、运维人员和普通用户使用相同的密码登录协议。

## 登录与权限

向管理域名发送：

```http
POST /api/v1/auth/login
Content-Type: application/json

{"login":"alice@example.com","password":"replace-with-account-password"}
```

请求只包含 `login` 和 `password`。登录标识可为用户名或邮箱，比较时忽略大小写；
密码使用原始字节校验，不裁剪首尾空格。管理员登录名沿用 `ROOT_USER_EMAIL`，
密码沿用 `ROOT_USER_PASSWORD`，32–1024 字节；普通账户密码为 15–128 字节。
环境参数以 [.env.example](../../.env.example) 的 11 项为准，移除旧验证器密钥配置。
程序不自动加载环境文件，修改 systemd EnvironmentFile 后必须重启服务。

密码以 Argon2id 存储。成功登录返回用户信息、CSRF token 和到期时间，设置
Secure、HttpOnly、SameSite=Strict 的会话 Cookie。后续请求使用 Cookie，写请求加
`X-CSRF-Token`。同一用户名和密码可以重复登录，不存在一次性密码或时间步限制。
会话、角色权限、CA 授权、审计、限流、账户禁用和密码失败锁定仍然生效。

管理员通过环境配置初始化；普通用户和运维账户由管理员创建。
CA 私钥导出仅限管理员，并在 JSON 中确认当前密码：`{"password":"current-password"}`。
密码确认失败或每分钟 5 次额度耗尽时返回 403 `password_verification_failed`。
API 字段及客户端行为见 [OpenAPI](openapi.yaml) 与 [桌面客户端接入](desktop-client-integration.md)。

## 安装与账户初始化

使用 [单一初始化 SQL](schema-initialization.md) 准备 PostgreSQL 18+ 空库后启动 `serve`。
管理员根据环境变量创建；后续启动同步管理员邮箱与密码。管理员密码实际改变时会清除
临时锁定并撤销其旧会话，未改变时保留现有锁定。`worker` 不同步管理员凭据。

首个正式版不支持预发布数据库原地升级，不包含旧认证字段清理或升级时重置账户的逻辑。
对本基线重复执行初始化命令不会改动密码、锁定或会话。
完整安装步骤见 [部署指南](production-deployment.md)。

## 登录失败排查

- `401 invalid_credentials`：核对用户名/邮箱、服务实际加载的环境密码或账户是否已禁用。
- `401 account_locked`：密码已通过，但锁定尚未到期；按 `Retry-After` 等待。
- `503 authentication_unavailable`：检查数据库、schema 和权限，不能当作密码错误。
- `403 csrf_failed`：检查当前会话的 CSRF token；生产 Cookie 必须通过 HTTPS 管理域名使用。

密码失败累计 5 次锁定 15 分钟；锁定期内重试不延长截止时间，锁定到期后重新计数。
需要管理员凭据恢复时，受控修改环境密码后重启服务。普通账户密码重置与禁用会撤销旧会话。
日志只需提供请求编号、状态码和验证阶段，不提供密码或原始环境文件。

## 验证范围

认证测试覆盖三种角色的密码登录、重复登录、密码轮换、密码确认私钥导出，
以及会话、Cookie/CSRF 和角色权限。数据库初始化检查覆盖重复执行与拒绝未知非空库。
检查命令与发布要求见 [发布指南](release.md)；历史验证报告不代表线上服务状态。

# 本地身份认证检查记录

状态：2026-11-15 的源码及隔离测试快照；不代表线上环境已经更新或已核验其凭据。
范围：启动配置、root 初始化、密码、TOTP、账户锁定、会话、CSRF、浏览器登录和代理边界。
当前排障步骤见 [运维指南](operations-runbook.md)，升级见 [部署指南](production-deployment.md)。

## 结论与复现

当前登录不调用 Cloudflare Access、OAuth 或共享网关凭证。Go module 中的
`github.com/cloudflare/cfssl` 是上游代码路径，历史审计的 `cf_access_sub` 是兼容字段，均不构成外部认证依赖。
请求没有 Cloudflare 头也可以完成本地密码、TOTP、Cookie 和 CSRF 流程；伪造这些头不能获得会话。

在临时 PostgreSQL 18.6 数据库上，修复前新增回归测试实际复现：

- root 密码正确、TOTP 留空，连续提交六次后失败计数为 5、账户被锁定。
  旧页面默认不勾选“超级管理员登录”，因此不会显示或发送 TOTP。
- 锁定 root 后更新环境密码并重新初始化，正确的新密码和 TOTP 仍得到 `account_state` 拒绝，
  因为原 `locked_until` 没有清除。

以上缺陷能造成“密码无论如何都不对”的症状；没有读取或更改线上凭据，不能据此认定
线上唯一原因。验证器算法、时钟、实际进程环境和部署版本仍需按运维指南核实。

## 修复

| 问题 | 当前行为 | 主要源码 |
| --- | --- | --- |
| 客户端角色开关隐藏并丢弃 TOTP | 字段始终显示，由服务器角色决定必填 | [LoginPage](../../web/src/pages/LoginPage.tsx) |
| 缺少第二因素也累计锁定 | 仅在密码验证成功后返回 second_factor_required，不发会话、不消费验证码、不增加失败次数；IP 限流仍生效 | [auth](../../console/auth/service.go) |
| root 密码轮换保留旧锁定 | 更换密码同步时清理失败计数与锁定；相同凭据重启保留锁定和重放状态 | [store](../../console/store/store.go) |
| TOTP 轮换保留旧会话和时间步 | 保存密钥指纹，轮换与撤销会话、重置时间步在同一事务；会话创建及敏感操作核对指纹快照 | [迁移 00005](../../console/store/migrations/00005_root_totp_state.sql) |
| 数据库异常伪装成密码/会话错误 | 存储故障返回 503 authentication_unavailable，凭据错误仍为 401 | [认证处理](../../console/httpapi/handlers_auth.go) |
| CSRF 失败导致前端误认为会话过期 | 403 csrf_failed；不触发 401 的全局退出处理 | [middleware](../../console/httpapi/server.go) |
| 旧会话查询覆盖新登录、Cookie 被拒绝仍进入控制台 | 登录前取消旧查询，登录后用 Cookie 确认会话，再更新界面；清理其他账户的查询缓存 | [AuthProvider](../../web/src/auth.tsx) |
| 浏览器存储异常中断登录 | CSRF 退回内存，主题设置失败不阻断应用；刷新后需重新登录 | [API 客户端](../../web/src/lib/api.ts) |
| 接受了无法用于登录的 root 配置 | 密码限制统一为 32–1024 字节，邮箱为不带显示名的纯地址且最多 254 字节；默认 origin 端口归一化 | [config](../../console/config/config.go) |
| 用户名与其他账户邮箱交叉重复，LIMIT 1 任选身份 | 创建时串行核对共享标识；历史歧义数据拒绝认证，不能任选账户 | [store](../../console/store/store.go) |

密码保留原始字节，不以裁剪空格或改变大小写处理密码错误。root 继续强制 TOTP，
没有允许 SHA-1 作为回退、跳过验证码或关闭生产 Secure Cookie。
TOTP 的算法行为使用 [RFC 6238 附录 B](https://www.rfc-editor.org/rfc/rfc6238.html#appendix-B)
的 SHA-256 测试向量核对，并继续拒绝重放及非 ASCII 数字。

## 验证与限制

本次结果：真实 PostgreSQL 18.6 上的全部 Console Go 测试及 `-race`、`go vet` 通过；
前端 lint、类型检查、12 个单元测试、生产构建和 34 个桌面/手机浏览器用例通过；
4 个 Python 客户端测试及文档/OpenAPI 一致性检查通过。
另外使用实际编译的单体程序、独立 HTTPS 测试代理和 Chrome，验证了生产模式下缺失 TOTP 提示、
真实密码/TOTP 登录、Secure HttpOnly Cookie、刷新、错误 CSRF 返回 403 但保留会话、退出后返回 401。
该链路连接临时 PostgreSQL，没有发送 Cloudflare 身份头；HTTPS 代理是测试实现，不是对线上 Nginx 的验收。

回归测试入口：

```sh
# PKI_TEST_DATABASE_URL 必须指向可清空的临时 PostgreSQL 18+ 数据库。
# 先完成前端构建，再执行嵌入该目录的 Go 检查，不能并行重建 web/dist。
cd web && npm run check && npm run test:e2e
# 回到仓库根目录后执行：
go test -count=1 -race -p 1 ./console/... ./cmd/pki-console ./web
go vet ./console/... ./cmd/pki-console ./web
make pki-console-docs PYTHON=/path/to/docs-venv/bin/python
```

[生命周期测试](../../console/auth/login_integration_test.go) 覆盖缺失 TOTP、锁定恢复、相同配置重启、
TOTP 轮换、旧会话和过期验证快照、普通账户登录及标识冲突。
[HTTP 测试](../../console/httpapi/integration_test.go) 覆盖无 Cloudflare 头的生产 root 登录、
Secure Cookie、会话、重放、CSRF、退出和数据库不可用时的错误码。
[浏览器测试](../../web/e2e/auth.spec.ts) 覆盖桌面/手机、TOTP 提交及补全、Cookie 无法确认、
存储不可用、刷新会话和认证服务故障提示；这些浏览器用例模拟 API，不代替上述真实数据库测试。

升级需先执行 `migrate`，再重启新二进制。首次登记 TOTP 指纹保留旧重放计数并撤销 root 旧会话。
已经锁定的账户不会因无配置变更的重启被解锁；等待锁定期，或受控更换 root 环境密码后重启。
本记录不表示已连接生产 Nginx、验证线上时钟或取得线上请求日志。

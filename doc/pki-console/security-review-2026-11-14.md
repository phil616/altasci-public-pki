# PKI-Console 安全检查与修复记录（2026-11-14）

> 状态：2026-11-14 检查快照。文中“当前”指当次检查状态，后续版本需重新验证。
> 当前操作入口见 [README](README.md)。

本次检查对象是当前工作区中的单体 `cmd/pki-console`、`console/`、内嵌 Web 前端、
实际使用的 CFSSL bundler 代码、依赖锁定文件和 Nginx 示例。前两次单体化及 CA 导入修改
包含在检查范围内。检查采用源码审查、依赖数据库扫描、可重复的安全回归测试和临时
PostgreSQL 18 集成测试；没有连接生产数据库或切换线上服务。

下列严重程度是针对本项目入口和攻击前提的工程判断，不是正式 CVSS 评分。
“已修复”表示当前源码已有修复和相应用例，不表示系统可以保证不存在未知漏洞。

## 确认的问题与修复

| 编号 | 程度 | 问题及触发条件 | 当前处理 |
| --- | --- | --- | --- |
| S01 | 高 | 任意已登录用户可在打包工具提交带任意 AIA URL 的证书，引发服务端访问内网；原 HTTP 抓取还缺少响应大小和超时保护 | Console 打包使用 `WithoutAIAFetching()`，只使用提供的证书和信任池；本地 HTTP 捕获服务证明不会收到请求。旧 CFSSL CLI 的显式联网模式保持独立 |
| S02 | 高 | 登录失败计数 SQL 的 `$2 + interval` 存在参数类型歧义，导致计数/锁定写入失败；并发失败还可能把已禁用账户改成 locked | 显式使用 timestamptz，禁止修改 disabled 账户；验证连续 5 次失败确实锁定，错误计数写入失败会进入安全日志 |
| S03 | 高 | 密码校验与会话创建分离，密码重置/禁用可插入其间；环境 root 密码更新后旧会话仍可能有效 | 账户状态、密码 hash 快照、TOTP 消费和会话创建放在同一行锁事务；禁用与会话撤销原子化；会话查询检查 password_changed_at |
| S04 | 高 | 导入 CA 后，后续签发仅验证签名，可能生成违反祖先名称约束或 EKU 约束的证书；子证书也可能晚于祖先失效 | 新签发的中间 CA、叶证书、OCSP 响应者和 TSU 均验证完整配置链与每个显式 EKU，有效期受所有祖先限制；OCSP/TSA 使用时重新验证链 |
| S05 | 高 | 并发 CRL 生成先读快照、后单独保存，旧快照可能覆盖包含更新吊销记录的新 CRL；原生成逻辑未保留吊销原因和 CRL 编号 | PostgreSQL 按 CA 的事务 advisory lock 覆盖读快照、签名、计数和发布；使用标准 X.509 CRL 编码，包含递增编号及原因码 |
| S06 | 中 | 一次性私钥先擦除再解密，缺少 KEK、密文损坏等错误会造成永久丢失 | 在锁定事务内先解密并验证 PKCS#8，再擦除和提交；缺少 KEK 后恢复正确 KEK 可以成功重试，成功后仍禁止重复下载 |
| S07 | 中 | worker 中断后 running 任务永远不再领取；迟到 worker 的失败回写可能覆盖新状态 | 单任务上下文上限 2 分钟，5 分钟过期租约可恢复；每次领取使用唯一归属 token，完成/失败回写验证归属；提交前检查申请者仍为 active |
| S08 | 高 | CSR 工具允许任意大的 RSA 位数；昂贵密码计算、密钥生成缺少总并发上限；限流 map 和任意 HTTP 方法指标可持续膨胀 | RSA 生成为 3072/4096，提交 CSR 的 RSA 公钥为 2048–8192 位且先限大小后验签；昂贵 HTTP 操作共享 4 个槽，饱和返回 429；限流状态最多 4096 项，方法标签有固定集合；二次验证每用户每分钟最多 5 次 |
| S09 | 中 | 信任 X-Forwarded-For 最左值，常见追加式 Nginx 配置可保留攻击者伪造前缀 | 从直接代理向左逐跳剥离可信代理，取最近的不可信地址；Nginx 示例仍直接覆盖 XFF。Cf-* 和 X-PKI-* 不参与身份认证 |
| S10 | 中 | duration 乘法可先溢出再验证，导致巨大有效期参数变成较小有效期 | 秒值在转换/接受前验证范围，签发 worker 再检查当前模板上限，覆盖模板变更后的已批准请求 |
| S11 | 中 | 审计写入失败仍可登录或执行写操作、输出 CA 私钥；私有 API 未统一声明禁止缓存 | 登录审计失败不发送会话 Cookie；认证写请求先持久化身份认证通过记录，失败返回 503；CA 私钥导出还要求成功结果审计。私有响应默认 no-store，CRL/OCSP 缓存寿命不超过签名数据的 NextUpdate |
| S12 | 中 | 生产远程 PostgreSQL 的 prefer/allow 等模式可回落到明文；样例零密钥和样例 root 密码能够启动 | 非回环的生产数据库必须显式使用 sslmode=verify-full；拒绝公开样例密码、全零 TOTP 和全零主密钥；业务域名规范化后检查隔离 |
| S13 | 低 | 退出失败时前端仍清空认证状态，造成用户误认为服务端会话已撤销；取消导入后异步文件读取可能重新填入私钥字段 | 退出失败保留状态并显示错误；取消/成功导入使旧文件读取失效 |
| S14 | 中 | bundler 只比较 RSA 的 N 或 ECDSA 的 X，可能接受不匹配密钥；直接空数组调用还会先索引后检查 | 比较完整 PKIX 公钥编码；空输入返回错误；覆盖同 X、相反 Y 的有效 ECDSA 密钥反例 |

相关源码：
[认证](../../console/auth/service.go)、[账户事务](../../console/store/store.go)、
[签发与 CRL](../../console/pki/service.go)、[队列/私钥/CRL 事务](../../console/store/pki.go)、
[证书链验证](../../console/security/chain.go)、[HTTP 边界](../../console/httpapi/server.go)、
[离线打包](../../bundler/bundler.go)。

SSRF 处理采用禁止不必要出站请求的方式，符合
[OWASP SSRF 防护建议](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)。
证书验证依据 [Go X.509 验证接口](https://pkg.go.dev/crypto/x509#Certificate.Verify)。

## 依赖扫描

- 构建工具链从 Go 1.27.0 更新至 **1.27.4**，消除扫描发现的旧标准库问题，包括
  GO-2026-6859。版本以 [Go 官方发布信息](https://go.dev/dl/?mode=json) 核对。
- `golang.org/x/crypto` 更新至 **v0.59.0**、`x/net` 至 **v0.62.0**，以及所需的
  x/sys、x/text、x/sync；同步更新 go.sum 与 vendor。
- `react-router-dom` 更新至 **7.18.5**、Vite 至 **8.3.8**、Vitest 至 **4.1.12**、
  ESLint 至 **10.15.0**、typescript-eslint 至 **8.72.2**。
  minimatch 固定为 **11.0.1**，覆盖上游依赖范围内尚未修补的版本。
- 更新前 npm audit 报告 17 个受影响依赖节点（6 high、11 moderate），不是 17 个
  独立可利用入口。其中 React Router 告警针对 RSC 模式，本项目为浏览器 SPA，
  不应把该告警直接等同于本项目存在 RSC CSRF 漏洞。参考
  [上游公告](https://github.com/advisories/GHSA-qwww-vcr4-c8h2)。
- 更新后 `npm audit` 报告 **0**；govulncheck v1.9.0 对 `./cmd/pki-console` 的扫描
  finding 数为 **0**。这是本次扫描时刻的依赖数据库结果，不覆盖未来公告。

项目原有 timestamp vendor 包带有大 OID 和解析器修复，直接 `go mod vendor` 会丢失
这些本地补丁。已保留原有修改，并添加 `vendor-patches/timestamp-oid.patch`；后续使用
`make vendor` 重新生成，补丁应用失败时命令会报错，避免静默丢失修复。

## 验证结果与可复现命令

使用独立的 PostgreSQL 18 测试实例，运行：

```sh
PKI_TEST_DATABASE_URL='postgresql://.../pki_test?sslmode=disable' \
  go test -race -p 1 ./console/... ./cmd/pki-console ./web

go vet ./console/... ./cmd/pki-console ./web
go test ./bundler -run '^TestWithoutAIAFetching$'
cd web && npm run check && npm run test:e2e
```

认证、PostgreSQL 签发生命周期与安全回归通过，race detector 未报告数据竞态。
安全回归覆盖锁定 SQL、密码重置竞态、禁用与重新启用、并发 TOTP 消费、SSRF 捕获、
昂贵请求并发上限、限流状态上限、XFF 前缀伪造、有效期溢出、CA 名称/EKU 约束、
祖先失效时间、CRL 并发编号/原因、过期 worker 恢复、旧 worker 归属失效、
一次性私钥解密失败重试，以及审计故障下禁止写操作和发 Cookie。
前端质量检查通过，桌面/移动端 **22 项 Playwright 测试通过**，含退出失败状态处理。

持续依赖检查可使用 `make pki-console-security`。构建机需提供兼容 Go 1.27 的
`govulncheck`（本次为 v1.9.0），也可用 `GOVULNCHECK=/absolute/path/govulncheck`
指定命令。该命令查询漏洞数据库，需要网络。

使用 gosec v2.30.0 检查 `console/...` 和 `cmd/pki-console`，没有包加载错误。
剩余 6 条告警经人工核对：

- 2 条 G124 针对 Cookie 的条件式 Secure 设置。生产模式 Secure=true，HttpOnly=true、
  SameSite=Strict；仅显式开发模式允许非 Secure Cookie，生产 Cookie 已有真实 API 用例验证。
- 4 条 G705 针对 PEM/OCSP/TSA 二进制 Write。相关响应明确设置下载/二进制媒体类型，
  并统一使用 nosniff 和限制脚本执行的 CSP，未发现这些输出构成 HTML 注入路径。
- 有一处 G115 显式标注安全理由：Argon2 输出长度在转换前限定为 16–64。

**完整旧 bundler 测试集没有全部通过**：现有证书资料触发格式/SHA-1 验证失败，
部分测试继续解引用失败结果而 panic。`TestNewBundler` 在原 Go 1.27.0 下也可复现失败。
本次变更由新生成现代证书的离线打包/密钥匹配回归覆盖；历史测试资料需要单独更新。

## 部署影响与边界

1. 重新构建并替换二进制；原有 CA 导入迁移仍应按部署流程执行。本次安全修复没有新增
   数据库 schema 版本，使用既有账户、任务和 CRL 表。
2. 远程数据库 URL 必须改成 verify-full，并配置有效 CA/主机名。已使用公开样例密钥的
   数据库需受控重加密迁移；直接删除旧 KEK 会丢失已有私钥解密能力。
3. 缺失中间证书时，打包接口现在需要调用方提供完整材料；不自动访问证书中的 URL。
   并发饱和或限流返回 429，客户端遵循 Retry-After；审计不可用时写请求和登录返回 503。
4. 故障任务最长可能等待 5 分钟租约过期后重新领取。历史已处于 failed 的任务不会被
   自动当作未完成任务重新签发。
5. 身份认证通过记录在业务操作之前持久化；业务结果审计与业务提交仍是不同事务。
   极端故障下可能留下认证/尝试记录和错误日志，而缺少结果事件。数据库所有者也可
   修改触发器或哈希链，跨数据库管理员的防篡改需要外部锚定或独立存储。
6. 这是源码和隔离环境检查，没有验证线上 Nginx、TLS 证书、数据库权限、备份或主机
   入侵防护。私钥仍在受信任进程中解密，未增加 HSM；也未进行互联网规模的容量或 DDoS 测试。

# 独立 CSR 自动签发服务

状态：当前实现；核对日期：2026-11-16；策略版本 1。此功能采用自定义 HTTPS JSON API，不是标准 ACME，
Certbot/acme.sh 不能直接对接。客户端持有凭据并提交符合策略的 CSR 即可自动签发，
不执行 DNS/HTTP 域名控制权验证。CA 所有者负责授予名称范围与用途。

## 隔离原则

所有活跃账户均可创建自己的实例，管理权限仅属于创建者，超级管理员没有隐式代管权限。
用户上传独立签发 CA、未加密私钥和完整上级链；只引用用户，不引用系统 CA、模板、审批、
证书或授权表。同一 CA 可重复导入不同实例，也可与系统 CA 相同，不去重、不覆盖。
CA 材料不可原地替换；更换 CA 创建新实例。实例只支持启用/停用，不删除签发历史或私钥。

端点使用稳定 UUID：`PUBLIC_BASE_URL/signing/{instance_id}/issue`。名称仅用于展示。
实例策略可修改，下次新申请立即重新检查；凭据策略创建后固定，调整时另建凭据并撤销旧凭据；停用实例阻止新签发，仍允许查询、
撤销和发布 CRL。账户非 active（含禁用/锁定）、凭据撤销或到期会拒绝凭据访问；所有者恢复登录后可管理历史证书。

## 凭据与权限

凭据由 256 位随机秘密构成，明文仅创建响应展示一次，不进入幂等缓存、日志或审计。
数据库仅保存 SHA-256 摘要，验证采用固定时间比较。每个可信方分配不同凭据。
权限分别为 `issue`、`read`、`revoke`；read/revoke 仅能操作这枚凭据签发的证书。
实例所有者可管理该实例全部证书。多人共享凭据时，审计无法区分实际使用者。
密码重置和浏览器退出不自动撤销独立凭据；泄露处置需单独撤销相关凭据。
账户锁定会影响工具访问；锁定期届满后需成功登录恢复 active 状态。

有效期 1 小时至 90 天，默认 30 天；总签发额度 1–1,000,000，默认 1,000；
每个数据库保存的 60 秒窗口内成功签发额度 1–120，默认 10（非滑动窗口，窗口边界允许突发）。一次性凭据设置总额度 1。
失败与幂等重放不扣签发额度。轮换通过创建新凭据、迁移客户端、撤销旧凭据完成。
每账户最多 50 个实例，每实例最多 1,000 枚凭据（含已撤销）、50,000 张历史证书。

## 策略结构

策略必须显式指定身份白名单和用途，未列出的身份类型拒绝，空白名单不表示无限制。
可选身份白名单传入 null 时按空列表拒绝处理；返回策略统一规范化为数组。

```json
{
  "version": 1,
  "allowed_dns_names": ["example.com", "*.example.com"],
  "allowed_ip_ranges": ["10.20.0.0/16"],
  "allowed_email_domains": [],
  "allowed_uri_prefixes": ["spiffe://example.com/workloads/"],
  "allow_wildcards": false,
  "extended_key_usages": ["server_auth"],
  "default_validity_seconds": 2592000,
  "max_validity_seconds": 7776000,
  "max_sans": 32
}
```

- DNS 规范化为 IDNA ASCII 小写，不允许 IP 冒充 DNS。精确项只匹配自身，`*.example.com`
  仅匹配其下一级名称，不匹配 apex 或更深层名称。签发通配符需显式开启且白名单覆盖。
- IP 使用 CIDR 包含关系，IPv4-mapped IPv6 按 IPv4 处理。
- 邮箱仅接受无显示名的地址，按规范化后完整域名白名单匹配；不默认包含子域。
- URI 支持 https/spiffe，要求规范 host，无用户信息、查询、片段、百分号转义或反斜杠；
  路径只接受 RFC 3986 的不经转义 ASCII 路径字符；前缀按路径边界匹配，避免 `workloads-evil` 绕过 `workloads`。
- CSR 至少 1 个 SAN，最多 max_sans（1–100）。CN 可空；非空时必须等于某个允许的
  DNS/IP/email/URI SAN。Subject 仅接受 CN/C/ST/L/O/OU，字段长度限制 128 字节，
  C 为两位大写字母；Subject 是申请者声明，不代表经过组织身份审核。
- 用途只允许 server_auth/client_auth。只能签发非 CA 叶证书，Key Usage 由服务端生成。
- CSR 只接受 SAN 请求扩展；其余扩展（含 Basic Constraints、KU、EKU）拒绝，防止隐式提权。
  不使用 CSR 携带的 URL，不联网下载链，不接收叶私钥。
- 密钥接受 RSA-2048/3072/4096（公钥指数至少 65537）或 ECDSA-P256/P384；CSR 签名只接受相应 SHA-256/384/512。
- 默认/最大有效期为 60 秒至 397 天；申请不得超过策略上限，最终还会裁剪到整条 CA 链
  的最早失效时间。验证完整签发路径、祖先路径深度、名称约束和每个最终 EKU，
  不接受验证器跳过配置 CA 的路径，也不能用 Any EKU 绕过限制。
- 凭据可附加完整策略；请求必须同时满足实例和凭据策略，EKU 取交集，有效期与 SAN
  上限取更严格值。凭据策略不能扩大实例权限。

## 一致性、审计与重试

独立签发 JSON 请求使用大小写严格的字段名，拒绝重复键、未知字段、顶层 null 和
不允许为空的字段值；可选凭据 policy 允许 null，可选身份白名单 null 按空名单处理。

签发必须提供 8–128 字节可打印 ASCII 的 `Idempotency-Key`。同一凭据、同 key、同请求
返回原证书及其当前状态，不重新检查新策略、不签新证书、不重复扣额度；内容变化返回 409。记录与证书一并长期保存，不自动过期。
客户端将请求 key 与原 JSON 一起持久化（附带客户端可重复计算的摘要也可），超时后原样重试。凭据到期/撤销后即使重放也拒绝。

事务按所有者、实例、凭据顺序锁定，检查状态、策略、额度，生成并验证证书，原子保存
证书、摘要、额度和审计，再返回。变更策略和撤销凭据使用相同锁顺序；进行中的事务可先
完成，撤销事务提交后不得开始新的授权签发。每个实例串行签发，防止配额竞态。
公开接口按每客户端 IP 每进程每分钟 60 次限制，密码运算共享现有 4 个并发槽；请求体最多 1 MiB，CSR 最多 64 KiB。
创建凭据与导入实例不支持幂等缓存：响应丢失时检查实例/凭据列表；凭据无法找回，需要撤销后重建。
公开入口在读取请求体、占用运算槽之前校验真实凭据、权限及账户状态；执行业务时仍在
事务锁下重新检查，避免预检查与凭据撤销之间的竞态。认证头不进入 URL/日志。
生产 HTTPS 由外部 Nginx 提供，后端只监听回环地址；开发模式例外。

## 重复 CA、吊销与备份边界

数据库和业务隔离不改变相同 CA 私钥的信任关系。序列号为不超过 159 位的正随机整数，实例内
唯一约束防重复，但不知道其它副本的全部历史时无法保证跨副本绝对不碰撞。
同一私钥泄露仍影响该 CA 的其它使用方，建议只导入预先准备的专用中间 CA。

新叶证书仅写入本实例的 issuer/CRL 地址，不复制 CA 原有的发布 URL，也不使用系统
CRL/OCSP。CRL 使用 critical Issuing Distribution Point，限定本实例 URI 和用户证书，
只列本实例吊销记录；客户端必须支持并正确验证作用域。首版不提供 OCSP。
上传 CA 证书最大 64 KiB、未加密私钥最大 32 KiB、上级链最大 256 KiB，整链最多 8 张，
CA 必须具备 certSign/crlSign、SKI、合法完整链；签名 CA 和所有祖先必须在有效期内。
CRL 在读取时按需生成并缓存，吊销后失效；临近 NextUpdate 一分钟时刷新。编号按实例单调递增，最长 24 小时并受链有效期限制，响应 no-store。
必须保持 PUBLIC_BASE_URL 及既有发布 URL 可达，不能通过修改配置追溯更改已签发证书。
撤销不可逆，原因码 0–10 排除 7 和 8（8 仅适用于解除吊销/增量 CRL）；重复同原因撤销幂等，改原因返回冲突。

备份必须包含独立签发表和全部 KEK。凭据撤销不会自动吊销此前证书；恢复旧备份可能
丢失撤销、额度与幂等记录，恢复前需处理数据缺口，避免多个恢复分支同时签发。
标准依据：[CSR](https://www.rfc-editor.org/rfc/rfc2986.html)、
[Bearer](https://www.rfc-editor.org/rfc/rfc6750.html)、
[X.509/CRL](https://www.rfc-editor.org/rfc/rfc5280.html)。

## 部署与 Web 使用

独立签发所需表已包含在唯一的 [schema.sql](../../console/store/schema.sql) 中。
新部署按 [初始化指南](schema-initialization.md) 准备空库并运行单体程序。
完整备份必须包含独立 CA、凭据摘要、额度和签发历史。
无需新环境变量、端口、Cloudflare 或额外后台程序；现有 Nginx 的 `location /` 可直接转发。

登录后进入“独立签发”（`/tools/signing`），创建实例并上传材料，填写白名单，
为可信方创建凭据。凭据专属策略与实例策略同时生效，额度 1 可用于一次性签发。
完整凭据只在创建后弹窗展示，关闭后不能找回。CA 私钥不提供导出，证书链可随时下载。
实例页支持查看凭据限制、撤销凭据、修改实例策略/启用状态、分页下载和吊销证书。

管理 API 在 Console 的 `/api/v1/signing-instances` 下，使用现有 Cookie 与 CSRF。
可信方 API 在公开域名 `/signing/{id}` 下，只接受独立 Bearer 凭据，不能用浏览器会话替代。
凭据 read/revoke 只授权该枚凭据自身的签发记录，轮换后的新凭据不接管旧记录。
细节和完整 Schema 见 [openapi.yaml](openapi.yaml)。

| 方法与路径（相对公开实例前缀） | 用途 |
| --- | --- |
| `POST /issue` | issue 权限，JSON CSR + 可选 validity_seconds，必须带 Idempotency-Key |
| `GET /certificates/{certificate_id}` | read 权限，查询自身签发记录与完整链 |
| `POST /certificates/{certificate_id}/revoke` | revoke 权限，JSON reason；同原因可安全重试 |
| `GET /issuer.cer` | 无需认证，下载 DER 签发者证书 |
| `GET /crl` | 无需认证，获取本实例作用域 DER CRL |

签发返回 201，包含 id、serial、certificate_pem、chain_pem、fingerprint_sha256、有效期和状态。
`Idempotency-Replayed: true` 表示返回已有记录。400 为 JSON/key 错误，401 为凭据/权限/账户
状态错误，403 为实例停用或总额度用尽，404 为资源不可见，409 为重试内容或吊销原因冲突，
422 为材料/策略/链或实例数量上限拒绝，429 为速率/并发限制，500 为内部失败，管理写入
还可能因审计门禁不可用返回 503。未知或代理错误可能不是 JSON，应先检查 HTTP 状态。
失败日志只记录错误码/请求号，不包含凭据、CSR 或私钥；成功的关键变更原子写入审计。

## 客户端与自动续期

提供不依赖第三方包的 [Python 3 客户端](../../scripts/signing-client.py)。生产服务仍只有
Go 单体；Python 仅为可信方调用工具。先在客户端本地生成 CSR（示例使用 OpenSSL 3）：

```sh
umask 077
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -sha256 \
  -config /dev/null -subj /CN=www.example.com \
  -addext subjectAltName=DNS:www.example.com -keyout service.key -out service.csr
chmod 600 credential.txt
python3 scripts/signing-client.py issue \
  --endpoint https://pki.example.com/signing/INSTANCE_UUID/issue \
  --token-file credential.txt --csr service.csr \
  --state request-001.json --output service.chain.pem
```

`credential.txt` 由安全渠道获得，示例命令不包含真实凭据。也可通过客户端环境变量
`SIGNING_TOKEN` 提供。接口自身 HTTPS 使用私有 CA 时，加 `--ca-file transport-root.pem`，
不会跳过 TLS 校验，不跟随携带凭据的 HTTP 重定向。

客户端在发送前持久化 operation key，绑定端点、凭据摘要和请求内容。超时后原样重跑，
不要删除 state；输入、state 和输出文件必须分别指定，客户端拒绝同路径或硬链接别名，
避免覆盖凭据、CSR、TLS CA 或重试状态。输出文件通过临时文件原子替换。输出的 JSON 包含证书 id、序列号、状态和到期时间。
每次续期使用新的 state 文件及新 CSR/密钥（可按组织策略复用叶密钥）；通过 cron/systemd timer
在到期前运行并验证部署结果。凭据有独立有效期，需提前轮换；总额度会累计，不随续期重置。
客户端拒绝把历史已过期/吊销签发结果当作新的签发成功安装。

查询与撤销示例：

```sh
python3 scripts/signing-client.py read --endpoint https://pki.example.com/signing/INSTANCE_UUID/issue \
  --token-file credential.txt --certificate-id CERTIFICATE_UUID --output downloaded.chain.pem
python3 scripts/signing-client.py revoke --endpoint https://pki.example.com/signing/INSTANCE_UUID/issue \
  --token-file credential.txt --certificate-id CERTIFICATE_UUID --reason 1
```

## 验证与维护

`make pki-console-check` 包含 Go 单元测试、vet、Python 客户端状态测试和前端质量检查，
构建机需 Python 3。`make pki-console-e2e` 覆盖桌面与移动端的导入、凭据创建和一次展示，
浏览器 API 为模拟。真实数据库集成测试使用独立 PostgreSQL 18+，会清空测试库：

```sh
PKI_TEST_DATABASE_URL='postgresql://postgres:test@127.0.0.1:5432/pki_test?sslmode=disable' \
  go test -p 1 ./console/... ./cmd/pki-console ./web
```

测试覆盖重复系统 CA、跨实例/所有者/凭据越权、并发单次额度、幂等与重启、审计回滚、
策略收紧、过期/撤销/停用、作用域 CRL/OpenSSL 校验、HTTPS 客户端与重定向拒绝、初始化重复执行与非空库拒绝。
文档一致性另运行 `make pki-console-docs`，工具配置见 [维护规范](documentation-maintenance.md)。

本次验证范围与结果见 [2026-11-15 实现检查记录](independent-signing-review-2026-11-15.md)。

后续安全硬化和文档合约复核见 [安全性与文档复核记录](security-docs-review-2026-11-15.md)。

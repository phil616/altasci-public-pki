> 状态：历史归档。以下内容保留旧版本的部署与操作记录，不能作为当前环境状态或当前版本操作依据。
> 当前入口：[项目文档](../../README.md)、[部署指南](../../production-deployment.md)。

# 使用 PKI-Console Web 建立企业 PKI

本文说明如何在已经创建根 CA 的前提下，通过 PKI-Console Web 建立一套两级企业 PKI：
根 CA 下面设置两个并列的中间 CA，不允许第三级 CA；一个中间 CA 专门签发 HTTPS/TLS
服务器证书，另一个中间 CA 承担企业通用终端证书签发。

本文只描述 Web 操作和 PKI 策略，不执行部署、数据库或 Cloudflare 配置变更。日常运行、
备份、恢复和事故处置见 [operations-runbook.md](operations-runbook.md)。

## 1. 最终信任结构

```text
企业根 CA（最大下级 CA 深度：1）
├── HTTPS/TLS 中间 CA（最大下级 CA 深度：0）
│   └── TLS 服务器终端证书
└── 通用中间 CA（最大下级 CA 深度：0）
    ├── mTLS 客户端证书
    ├── 企业代码签名证书
    ├── 邮件保护证书
    └── 其他经过明确策略批准的终端证书
```

这里的“最大下级 CA 深度”是 X.509 `pathLenConstraint`，表示一条有效证书链中此 CA
之后最多还能出现多少层非自签名中间 CA，不是允许创建多少个子 CA。根 CA 设置为 `1`
可以同时拥有任意数量的并列中间 CA；两个中间 CA 设置为 `0` 后，只能签发终端证书，
不能继续签发下级 CA。[RFC 5280 第 4.2.1.9 节](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.9)
定义了这一行为。

## 2. 开始前必须确认的事项

使用超级管理员登录 `https://pki-console.altasci.com`，进入左侧“证书机构”，打开已经
创建的根 CA，在“概览”中检查：

| 检查项 | 正确状态 |
| --- | --- |
| 类型 | 根 CA |
| 状态 | 有效/active |
| 最大下级深度 | `1` |
| 上级 CA | 自签名信任根 |
| 到期时间 | 覆盖两个中间 CA 的计划使用周期 |
| Issuer、CRL、OCSP | 均显示 `pki.altasci.com` 下的 HTTPS 地址 |

如果根 CA 的最大下级深度是 `0`，Web 不会把它列为可签发中间 CA 的上级，而且该根
证书本身也不允许后续中间 CA。这个值属于已经签名的证书扩展，不能通过编辑页面安全
修改；如果根尚未分发或用于正式签发，应重新创建一个深度为 `1` 的根 CA。

如果根 CA 的深度大于 `1`，系统仍可建立本文结构，但根证书在密码学上允许更深的链。
如果“绝不允许第三级 CA”是正式安全要求，最好在正式分发信任锚前使用深度为 `1` 的根。

还应确认：

- 服务器和管理终端时间同步正常；
- `pki.altasci.com` 可匿名访问，不能出现 Cloudflare Access 登录页；
- 已经安全备份数据库和全部 `PKI_MASTER_KEYS`；
- 根 CA 私钥没有被下载到普通运维终端；
- 企业法定名称、部门名称、证书命名规则和允许使用的 DNS/IP 范围已经确定。

## 3. 建议的命名规范

以下名称可以直接作为模板，组织名称应替换为真实法定主体：

| 对象 | 显示名称示例 | 公开标识示例 |
| --- | --- | --- |
| 根 CA | `Altasci Enterprise Root CA 01` | `altasci-enterprise-root-01` |
| TLS 中间 CA | `Altasci TLS Issuing CA 01` | `altasci-tls-issuing-01` |
| 通用中间 CA | `Altasci General Issuing CA 01` | `altasci-general-issuing-01` |

公开标识 `slug` 会进入 Issuer、CRL 和 OCSP URL，应视为创建后永久不变的技术标识。
只使用小写字母、数字和连字符，不要包含人员姓名、临时项目名或可能很快变化的部门名。

显示名称和 Subject CN 建议包含：组织、环境、用途、层级和序号。生产与测试 PKI 必须
使用不同的根和不同的名称，不能只依靠一个 `test` 标签区分终端证书。

## 4. 创建 HTTPS/TLS 中间 CA

进入“证书机构”，单击右上角“创建 CA”。按下表填写：

| Web 字段 | 推荐值 | 说明 |
| --- | --- | --- |
| 机构类型 | `中间 CA` | 不要再创建根 CA |
| 上级 CA | 已有企业根 CA | 只能选择有效且允许下级 CA 的根 |
| 显示名称 | `Altasci TLS Issuing CA 01` | 明确表示只服务 TLS |
| 公开标识 | `altasci-tls-issuing-01` | 会进入公开发布 URL |
| 最大下级 CA 深度 | `0` | 禁止该 CA 继续签发 CA |
| 通用名称（CN） | `Altasci TLS Issuing CA 01` | 建议与显示名称一致 |
| 组织（O） | 企业真实法定名称 | 不要使用域名代替法定主体，除非正式策略如此规定 |
| 组织单位（OU） | `Security Engineering` 或实际 PKI 团队 | 表示负责团队 |
| 国家（C） | 真实两位代码，例如 `CN` | ISO 3166-1 两位代码 |
| 省/州、城市 | 真实注册或运营所在地 | 按企业证书策略统一填写 |

单击“创建并生成密钥”。当前系统会自动完成以下工作：

- 生成 RSA-3072 中间 CA 私钥；
- 使用根 CA 签发有效期约 3 年的中间 CA 证书；
- 写入 `CA=true`、`pathLenConstraint=0`、`keyCertSign` 和 `cRLSign`；
- 创建 Issuer、CRL 和 OCSP 公共地址；
- 创建独立的委派 OCSP responder 证书和加密私钥；
- 创建初始 CRL；
- 创建一个名为 `default` 的初始叶证书签发策略；
- 使用 AES-256-GCM envelope 加密 CA 和 OCSP 私钥后保存到 PostgreSQL。

创建完成后进入该 CA，检查“概览”和“CA 证书”：

- 类型为中间 CA，状态为 active；
- 最大下级深度为 `0`；
- 上级 CA 指向正确的根；
- Issuer、CRL、OCSP 均不是“未配置”；
- CA chain 包含中间 CA 和根 CA，且顺序正确；
- 到期时间不晚于根 CA。

## 5. 配置 HTTPS/TLS 签发策略

打开 TLS 中间 CA 的“签发策略”标签。系统已经创建名为 `default` 的策略。

### 5.1 正确处理 default 策略

不要删除或改名 `default`。Web 表单虽然允许修改名称，但后端在申请人未明确选择策略时，
会按名称查找启用的 `default`。改名会导致“使用默认策略”的申请失败。

单击 `default` 右侧“编辑”，建议填写：

| Web 字段 | 推荐值 |
| --- | --- |
| 策略名称 | 保持 `default` |
| 说明 | `仅用于受管企业 HTTPS/TLS 服务器证书` |
| 默认有效期 | `90` 天 |
| 最大有效期 | `90` 天 |
| 密钥用途 | `digital signature`、`key encipherment` |
| 扩展密钥用途 | 只选择 `server auth` |
| 允许的 DNS 模式 | 填写实际受控命名空间，不能留空 |
| 允许的 IP 网段 | 填写实际批准的网段 |
| 允许 Email SAN | 关闭 |
| 允许 URI SAN | 关闭 |
| 扩展策略 JSON | `{}` |
| 允许签发 | 开启 |

`server auth` 是 RFC 5280 定义的 TLS 服务器 EKU。如果 Key Usage 和 Extended Key
Usage 同时存在，验证方必须同时处理两者，因此不要顺便加入 `client auth`、
`code signing` 或 `email protection`。[RFC 5280 第 4.2.1.12 节](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12)
列出了这些用途。

### 5.2 DNS 和 IP 限制的关键含义

当前系统中，“允许的 DNS 模式”为空表示不限制任何 DNS SAN，而不是禁止 DNS；
“允许的 IP 网段”为空同样表示不限制任何 IP SAN。因此生产 TLS 策略不能依赖空列表。

例如只允许企业管理的 `altasci.com` 命名空间时，可根据实际需要加入：

```text
altasci.com
*.altasci.com
```

不要填写单独的 `*`。如果生产服务只位于更窄的区域，应使用更窄的命名空间，例如：

```text
*.prod.altasci.com
*.services.altasci.com
```

当前 DNS 匹配是 glob 模式，不是 X.509 Name Constraints；`*.altasci.com` 可能比预想的
“单层子域”更宽。高价值系统应使用多个更具体的模式，并在审批时再次核对完整 SAN。

当前 Web 没有“完全禁止 IP SAN”的独立开关。填写网段会把 IP SAN 限制在这些网段；
留空则允许任何 IP。若企业策略要求绝对禁止 IP SAN，需要把它列为审批硬规则，并将
“显式拒绝所有 IP SAN”作为后续产品能力补充项。

### 5.3 为什么建议 90 天

PKI-Console 当前允许最多 397 天，但不建议把可配置上限当作安全推荐值。90 天可以降低
密钥泄漏后的长期影响，并迫使证书更新自动化成熟。

截至 2026-08-24，CA/Browser Forum 对公开信任 TLS 证书规定的最大有效期已经降为
200 天，2027-03-15 将降为 100 天，2029-03-15 将降为 47 天。
[Ballot SC-081](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/)
只直接约束公开信任 WebPKI，不直接约束企业私有根，但采用 90 天可以提前满足更短周期
运维模式。

### 5.4 RSA 与 ECDSA

服务端生成密钥时，当前系统固定生成 RSA-3072，因此上述 Key Usage 可以直接使用。
客户端 CSR 允许 RSA（至少 2048 位）以及 ECDSA P-256/P-384。ECDSA TLS 证书通常只需
`digital signature`；如果企业要正式使用 ECDSA，可新建 `tls-ecdsa` 策略，只选择：

```text
Key Usage: digital signature
Extended Key Usage: server auth
```

当前策略不能强制 CSR 必须是 ECDSA，因此审批人员还必须检查 CSR 公钥算法，不能只看
申请人选择的策略名称。

## 6. 创建通用中间 CA

返回“证书机构”，再次单击“创建 CA”，填写：

| Web 字段 | 推荐值 |
| --- | --- |
| 机构类型 | `中间 CA` |
| 上级 CA | 与 TLS CA 相同的企业根 CA |
| 显示名称 | `Altasci General Issuing CA 01` |
| 公开标识 | `altasci-general-issuing-01` |
| 最大下级 CA 深度 | `0` |
| 通用名称（CN） | `Altasci General Issuing CA 01` |
| O、OU、C、ST、L | 与企业 PKI 命名规范一致 |

创建后按 TLS CA 相同方式检查上级、深度、chain、Issuer、CRL 和 OCSP。

“通用 CA”不应理解为一张证书同时拥有全部用途，也不应理解为可以继续签发 CA。
它是一个可以承载多个用途明确、彼此隔离的终端证书策略的中间 CA。RFC 5280 要求
Key Usage 与 EKU 共同限制证书用途；把所有 EKU 放在一个策略里会扩大错误签发和密钥
泄漏的影响。

## 7. 配置通用 CA 的策略集合

### 7.1 禁用通用 CA 的无意默认签发

打开通用 CA 的“签发策略”，编辑 `default`：

| Web 字段 | 推荐值 |
| --- | --- |
| 策略名称 | 保持 `default`，不要改名 |
| 说明 | `禁用的兜底策略；所有申请必须显式选择用途` |
| 默认/最大有效期 | `90 / 90` 天 |
| 密钥用途 | `digital signature` |
| 扩展密钥用途 | `client auth` |
| 扩展策略 JSON | `{}` |
| 允许签发 | **关闭** |

关闭后，申请人在通用 CA 上不选择具体策略时，申请会失败。这是有意的 fail-closed
行为，可以防止一个宽泛默认策略绕过用途选择。需要在用户培训中明确：“通用 CA 必须
显式选择策略”。

### 7.2 新建 mTLS 客户端策略

单击“新建策略”：

| Web 字段 | 推荐值 |
| --- | --- |
| 策略名称 | `mtls-client` |
| 说明 | `企业用户、设备或应用的 mTLS 客户端认证` |
| 默认/最大有效期 | `90 / 90` 天 |
| 密钥用途 | `digital signature` |
| 扩展密钥用途 | `client auth` |
| DNS/IP 模式 | 按身份设计填写；不使用时审批必须确认 SAN 为空 |
| 允许 Email SAN | 关闭 |
| 允许 URI SAN | 关闭 |
| 扩展策略 JSON | `{}` |
| 允许签发 | 开启 |

如果工作负载使用 URI 身份，可以另建 `workload-uri-client`，开启 URI SAN，并采用更短
有效期，例如默认 1 天、最大 30 天。当前系统只能允许或禁止 URI SAN，不能限制 URI
前缀，因此在没有外部身份规则和严格审批前，不要直接开启。

### 7.3 新建企业代码签名策略

| Web 字段 | 推荐值 |
| --- | --- |
| 策略名称 | `code-signing` |
| 说明 | `仅用于企业内部软件和脚本签名` |
| 默认/最大有效期 | `90 / 180` 天 |
| 密钥用途 | `digital signature`、`content commitment` |
| 扩展密钥用途 | 只选择 `code signing` |
| DNS/IP 模式 | 不使用；审批时要求 SAN 为空 |
| Email/URI SAN | 均关闭 |
| 扩展策略 JSON | `{}` |
| 允许签发 | 开启 |

私有代码签名证书只会被安装了企业根并配置相应信任策略的设备接受，不会自动获得
Windows、macOS、浏览器或公共软件生态的公开代码签名信任。

### 7.4 新建邮件保护策略

只有企业确实部署 S/MIME 或等价邮件加密/签名体系时才创建：

| Web 字段 | 推荐值 |
| --- | --- |
| 策略名称 | `email-protection` |
| 说明 | `企业 S/MIME 邮件签名和加密` |
| 默认/最大有效期 | `90 / 180` 天 |
| 密钥用途 | `digital signature`、`content commitment`、`key encipherment` |
| 扩展密钥用途 | 只选择 `email protection` |
| 允许 Email SAN | 开启 |
| 允许 URI SAN | 关闭 |
| 扩展策略 JSON | `{}` |
| 允许签发 | 开启 |

当前开关只表示允许 Email SAN，不会限制邮箱域名。审批人员必须检查邮箱属于企业允许的
域；需要自动化域名限制时，应作为产品策略能力补充。

### 7.5 不建议直接创建 timestamping 策略

Web 可以选择 `timestamping` EKU，但 PKI-Console 当前只签发证书，不提供 RFC 3161
时间戳服务。只有已经存在受控 TSA 服务、专用密钥保护和单独审计流程时，才应创建
timestamping 证书；不能把普通代码签名服务当作 TSA。

### 7.6 不要在通用 CA 上再建 server auth

HTTPS/TLS 已经有独立中间 CA。继续在通用 CA 上创建 `server auth` 会破坏隔离目标，
导致 TLS 签发权限扩散到通用证书运维人员。确有例外时，应作为单独风险批准，而不是
把它放入 default 或“全用途”策略。

## 8. 创建人员并进行 CA 级授权

进入“用户管理”。建议至少建立以下互不共用的账户：

| 账户类型 | 建议职责 |
| --- | --- |
| 超级管理员 | 建立 CA、维护策略和授权；不承担日常普通申请 |
| TLS 运维人员 | 只处理 TLS 中间 CA 的申请、签发和吊销 |
| 通用证书运维人员 | 只处理通用 CA 的明确用途申请 |
| 普通用户/服务负责人 | 提交申请、查看和下载自己的证书 |

创建运维人员时选择角色“运维人员”；创建申请人时选择“普通用户”。普通账户密码当前
要求 15–128 个字符。不要把超级管理员账号作为普通证书申请人，因为申请人不能审批
自己的申请，职责分离也会失效。

打开某个中间 CA，进入“运维授权”，单击“添加授权”。每次只能添加一项权限，需要
按职责重复操作：

| 权限 | 含义 | 建议 |
| --- | --- | --- |
| `view_requests` | 查看当前 CA 的申请和证书 | 所有负责该 CA 的运维人员 |
| `approve` | 批准或拒绝申请 | 审批人员 |
| `issue` | 执行签发权限语义 | 完整负责该 CA 的签发人员 |
| `revoke` | 吊销当前 CA 签发的证书 | 仅事故/生命周期负责人 |

最简单的全生命周期运维角色可以在自己的 CA 上拥有四项权限，但不要把同一个运维人员
同时授权到两个中间 CA，除非职责确实需要。更严格的设计可以把审批和吊销分给不同人。

当前工作流在申请获批后由后台 worker 自动签发，没有第二个“手工执行签发”按钮。
因此企业流程中的双人复核需要通过人员分工、工单和审批意见实现；当前系统本身没有
两名审批人共同批准一张证书的机制。

根 CA 权限不能委派给运维人员，只有超级管理员能够创建根/中间 CA 和导出 CA 私钥。

## 9. 普通用户申请证书

用户登录后进入“证书申请”，单击“申请证书”。

### HTTPS/TLS 证书

| Web 字段 | 操作 |
| --- | --- |
| 签发机构 | 选择 TLS 中间 CA |
| 签发策略 | 选择 `default`；ECDSA 时选择受控的 `tls-ecdsa` |
| 密钥生成方式 | 生产建议“提交 CSR” |
| CSR | 粘贴一份完整、签名有效的 PKCS#10 PEM CSR |
| 申请有效期 | 留空使用策略默认 90 天，或填写不超过策略上限的秒数 |

生产服务器通常应在密钥最终使用位置生成私钥和 CSR，私钥不离开服务器、负载均衡器或
密钥管理设备。CSR 中必须包含实际访问使用的 DNS/IP SAN；现代 TLS 验证不能只依赖 CN。

若使用“服务端生成”，填写 CN、组织、OU 和 SAN。系统会生成 RSA-3072 私钥；证书签发
后私钥只允许所有者下载一次，24 小时后过期，成功下载后服务端擦除密文。它适合测试或
确实不能本地生成密钥的系统，不适合作为企业私钥分发的默认方式。

### 通用证书

选择通用中间 CA后，必须显式选择 `mtls-client`、`code-signing`、
`email-protection` 或其他经过批准的具名策略。不要留空，也不要要求重新启用宽泛的
default。

提交后申请会立即出现在“证书申请”和“证书库”的“待签发”筛选中，状态为 pending。

## 10. 审批和签发

由具备当前 CA `approve` 权限且不是申请人的运维人员打开“证书申请”：

1. 打开 pending 申请；
2. 核对签发 CA 和策略；
3. 核对 CSR 签名、公钥算法与强度；
4. 核对 Subject、CN、全部 SAN、有效期和实际资产所有权；
5. 核对策略是否与用途匹配；
6. 在审批意见中记录工单号、资产号或验证依据；
7. 单击“批准”或“拒绝”。

批准后状态会依次变为 approved、issuing、issued。后台 worker 自动完成签发，Web 会
轮询显示结果。失败时不要反复新建申请，先查看错误代码、审计和运维日志。

签发完成后：

- 申请人在“证书库”的“已签发”中查看并下载证书链；
- 服务端生成密钥的申请人立即完成一次性私钥下载；
- 运维人员只能看到自己有 CA 权限的证书和拒绝记录；
- 超级管理员可以查看全部 CA 的 pending、issued、rejected 和 failed 记录。

## 11. 建立企业信任分发

PKI-Console 创建的是私有企业 PKI。它签发的 HTTPS 证书不会被互联网浏览器、手机或
第三方客户自动信任。必须把根 CA 证书安全分发到所有依赖方的信任存储，例如企业
MDM、Windows GPO、Linux 系统镜像、容器基础镜像、Java truststore 或设备管理平台。

分发原则：

- 只把根 CA 设置为 trust anchor；
- 中间 CA 随服务器证书链提供，不应作为独立信任根安装；
- TLS 服务器发送“叶证书 + TLS 中间 CA”，通常不发送根 CA；
- 通用中间 CA 不应出现在 TLS 服务链中；
- 不把根或中间 CA 私钥分发到任何客户端；
- 对互联网公众访问的站点继续使用公开信任 CA，不能用本企业私有根替代。

## 12. Web 验收流程

正式签发前，创建独立测试用户和测试运维人员，完成以下验收。

### 信任结构验收

- [ ] 系统中只有一个计划使用的生产根 CA；
- [ ] 根 CA 最大下级深度为 `1`；
- [ ] 两个中间 CA 都直接指向该根；
- [ ] 两个中间 CA 最大下级深度均为 `0`；
- [ ] TLS 和通用 CA 的 slug、Subject 与用途明确不同；
- [ ] 两个中间 CA 的 Issuer、CRL、OCSP 地址可从互联网匿名访问；
- [ ] 根和中间 CA 证书、chain 与到期时间正确。

### TLS 全链路验收

1. 普通用户向 TLS CA 提交带测试 DNS SAN 的 CSR；
2. TLS 运维人员核对并批准；
3. 在证书库下载 chain；
4. 确认证书只有 `server auth`，不含 client/code/email EKU；
5. 确认 SAN、有效期和 Key Usage 符合策略；
6. 安装到测试 HTTPS 服务，从受管客户端验证信任链；
7. 吊销测试证书，验证 Web 状态、CRL 和 OCSP 更新。

### 通用 CA 验收

- [ ] 未选择策略的申请被拒绝；
- [ ] `mtls-client` 证书只包含 `client auth`；
- [ ] `code-signing` 证书只包含 `code signing`；
- [ ] Email SAN 只在邮件策略中允许；
- [ ] TLS 运维人员无法审批通用 CA 申请，反向也一样；
- [ ] 申请人无法批准自己的申请；
- [ ] 拒绝原因、批准、签发、下载和吊销均出现在审计页面。

## 13. 生命周期管理

当前系统自动创建的根 CA 有效期约 10 年，中间 CA 约 3 年，这些时间目前不能在 Web
创建表单中自定义。建议：

- 根 CA 到期前至少 24 个月制定替换计划；
- 中间 CA 到期前至少 6 个月创建新一代中间 CA；
- 新旧中间 CA 并行期间，新申请切到新 CA，旧 CA 保留 CRL/OCSP 到最后一张证书到期；
- 叶证书采用自动续期，90 天证书建议在剩余 30 天前更新；
- 定期检查 CRL/OCSP `next_update`、中间 CA 有效期和签发队列；
- 不删除仍在验证历史证书的旧 CA、KEK 或公开吊销信息。

根 CA 私钥不用于日常叶证书签发，不应日常导出。Web 的“导出私钥”要求超级管理员
密码、新 TOTP 和 Cloudflare Access，并会写入审计，但这些控制不能替代离线根、HSM
或正式密钥仪式。

## 14. 当前系统的企业级边界

本文配置可以建立清晰的两级私有 PKI，但严格企业级或受监管 PKI 还应评估以下差距：

| 当前边界 | 影响 |
| --- | --- |
| 根 CA 私钥加密存于在线 PostgreSQL，由环境 KEK 解密 | 不等同于离线根或 HSM 中不可导出密钥 |
| 系统只有一个超级管理员 | 没有内建多人 root 管理或 quorum |
| CA 创建/私钥导出只需一个 root 完成 step-up | 没有双人密钥仪式审批 |
| 一个申请只需要一次批准 | 没有高风险证书双人审批 |
| DNS glob 不是 X.509 Name Constraints | 约束依赖申请策略和审批，不能限制被盗中间 CA 的链外行为 |
| 空 DNS/IP 列表表示不限制 | 容易因误解产生过宽策略 |
| 没有 IP SAN deny-all 开关和 Email/URI 前缀约束 | 某些严格命名规则只能靠审批执行 |
| 策略不能强制 CSR 是 RSA 或 ECDSA | 审批人必须核对公钥算法 |
| Web 可以选择 timestamping EKU，但没有 TSA 服务 | 不能因此宣称提供可信时间戳能力 |
| 私有根不受公共客户端默认信任 | 必须建立企业 trust anchor 分发体系 |

如果目标是高等级金融、政企或公开信任 CA，应进一步建设离线根/HSM、双人控制、
Name Constraints、独立密钥仪式、CP/CPS、证书策略 OID、自动化资产验证、合规审计和
灾难恢复演练，再把系统定义为相应等级的企业 PKI。

## 15. 必须形成的管理制度

Web 配置只是技术实现。正式运行前至少形成以下制度文档：

- Certificate Policy（CP）和 Certification Practice Statement（CPS）；
- 根 CA、中间 CA、叶证书的用途和命名标准；
- 各策略的 Subject/SAN、算法、有效期和审批证据要求；
- root、TLS 运维、通用证书运维和申请人的职责分离；
- 私钥生成、保存、备份、下载和销毁规则；
- 证书更新、吊销原因、CRL/OCSP 和密钥泄漏处理流程；
- CA 更新、信任锚分发、旧 CA 退役和依赖方通知流程；
- 日志、审计、备份、PITR、恢复演练和事件响应要求。

可以使用 [operations-record-templates.md](operations-record-templates.md) 记录巡检、
生产变更、恢复、轮换和安全事件。

## 16. 推荐的最终配置摘要

| 对象 | 最终配置 |
| --- | --- |
| 根 CA | path length `1`，只签发两个中间 CA |
| TLS 中间 CA | path length `0`，只启用 server auth 策略 |
| TLS default | 90/90 天，digital signature + key encipherment，server auth，受限 DNS/IP |
| 通用中间 CA | path length `0`，不承担 server auth |
| 通用 default | 保持名称 `default`，关闭签发 |
| mTLS | 独立 `mtls-client`，只含 client auth |
| 代码签名 | 独立 `code-signing`，只含 code signing |
| 邮件 | 需要时独立 `email-protection`，显式允许 Email SAN |
| TSA | 没有独立 TSA 服务时不创建 timestamping 策略 |
| 运维授权 | 两个 CA 使用不同人员，按 view/approve/issue/revoke 分别授权 |
| 私钥 | 生产优先客户端 CSR；服务端生成仅一次下载且 24 小时过期 |
| 信任 | 根通过企业设备管理分发；服务器发送叶证书和对应中间链 |

完成上述配置和验收后，再开始签发正式业务证书。

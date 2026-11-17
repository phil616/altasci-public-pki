# 人工验收操作手册

状态：当前操作手册；核对日期：2026-11-17。依据同提交的页面、API 和签发代码编写。
本文是一份待执行的验收计划，不代表被验收环境已经通过。

验收员按顺序操作浏览器与终端：先按固定字段创建或导入 CA，再申请、审批、下载和
吊销测试证书，用 OpenSSL 与接口断言核验真实结果。页面操作不由脚本代做。
随附的 [命令辅助库](../../scripts/manual-acceptance-lib.sh) 只负责发起单次 HTTP 请求、
核对状态码和保留命令结果，不会自动推进流程，也不会连接或清空数据库。

## 1. 验收规则和准备

### 1.1 环境与记录

使用独立验收部署、专用空数据库和测试密钥，按 [部署指南](production-deployment.md)
安装。本文会创建账户、CA、授权和证书，执行不可逆吊销、密码重置、禁用与重启。
不要在生产部署照做，也不要导入生产 CA 私钥。不要运行会清空数据库的 Go 集成测试
来代替本文的验收步骤。

准备 Linux/Bash 终端、OpenSSL 3.x、curl、jq、Python 3、浏览器，以及同版本源码。
HTTPS 证书必须受验收机信任；禁止使用 `curl -k` 或 `openssl ... -noverify`。
使用内部 HTTPS CA 时，给 curl 配置 `CURL_CA_BUNDLE`，给 Python 客户端配置
`--ca-file`；它们用于验证网站 HTTPS，与下面用于验收的 PKI 根证书是两套概念。

浏览器建议使用四个独立配置目录，分别登录管理员、运维、用户 A、用户 B，避免混用会话。
测试名称固定，重跑整套计划时准备新的验收部署；单步失败不要直接反复创建同名对象。

先在源码根目录执行，随后保持同一 Bash 会话和工作目录：

```bash
export REPO="$PWD"
export CONSOLE='https://pki-console.example.com'
export PUBLIC='https://pki.example.com'
# 替换为实际配置的管理员邮箱；两个 origin 不带结尾 /。
export ROOT_LOGIN='alice@example.com'
umask 077
export WORK=$(mktemp -d "${TMPDIR:-/tmp}/pki-acceptance.XXXXXX")
cd "$WORK"
mkdir .secrets evidence fixtures downloads
source "$REPO/scripts/manual-acceptance-lib.sh"
openssl version
curl --version
jq --version
python3 --version
printf 'Acceptance directory: %s\n' "$WORK"
```

将 `WORK` 路径单独记录。更换终端时恢复以上变量，`cd "$WORK"` 并重新 source 辅助库；
后文设置的对象 ID 变量也需恢复。不要重新创建工作目录再接着执行一半的流程。

创建 `evidence/acceptance-record.md`，记录环境、源码提交、二进制版本、执行人、时间，
每个用例的 PASS/FAIL/BLOCKED、预期与实际结果、证书指纹、申请/证书 ID、请求编号、
截图或日志文件。密码、Cookie、CSRF、Bearer token、私钥不写入验收记录。
详细记录模板在第 15 节。

### 1.2 终端命令的判定方式

- `qa_http 角色 方法 路径 预期状态 输出文件 [JSON请求文件] [幂等键]`：保存响应与
  `输出文件.headers`，状态不符返回非零。`anonymous` 表示未登录的管理端，`public`
  表示未登录公开端；`admin/op/a/b` 是本机保存的登录别名，`token-main` 等表示 Bearer。
- `qa_check 用例名 命令...`：命令退出码为零才 PASS，输出保存在 `evidence/用例名.log`。
- `qa_reject 用例名 必须出现的错误文字 命令...`：命令必须失败，且错误文字匹配才 PASS。
  因网络故障或缺文件失败不算预期拒绝。
- HTTP 200、页面“已批准”和命令退出码都不能单独证明证书可信或已吊销；按每节的
  JSON 字段、签名、链、SAN 和吊销状态继续断言。`jq -e` 返回非零就是失败。
- 遇到任意 FAIL 先停止该路径，记录原因并修复后重测。依赖它的后续项标 BLOCKED，
  不能跳过后把整套验收标为通过。不要把 429、代理 502 或空响应视为预期业务拒绝。
- 长时间操作后会话可能正常超时；先用 `qa_login` 重新登录。写请求失败时先查看记录，
  用原幂等键重试，不能因会话或网络问题反复创建同名对象。

## 2. 部署、登录和初始账户

**ENV-01**：浏览器打开两个域名；管理端显示登录页面，公开端显示公开 PKI 页面。
刷新 `/login` 和一个详情页不出现 404/空白；桌面和手机窄屏的导航、表单与下载可用。
终端检查：

```bash
qa_http anonymous GET /api/v1/health/live 200 evidence/console-live.json
qa_http anonymous GET /api/v1/health/ready 200 evidence/ready.json
qa_http anonymous GET /api/v1/version 200 evidence/version.json
qa_http public GET /health/live 200 evidence/public-live.json
qa_http anonymous GET /api/v1/auth/session 401 evidence/no-session.json
qa_http public GET /api/v1/auth/session 404 evidence/public-no-admin.json
qa_http anonymous GET /api/v1/not-a-route 404 evidence/no-api.json
qa_http anonymous GET /assets/not-a-real-file.js 404 evidence/no-asset.txt
jq -e '.status=="ready"' evidence/ready.json
jq -e '.name=="PKI-Console" and (.version|length>0)' evidence/version.json
```

核对版本为本次部署版本。代理层或本机直连用错误 Host 的请求应为 421，不能落到管理页面；
若 Nginx 先拒绝未知域名，另按部署指南从本机回环端口验证应用的 421，并分别记录两层结果。

**AUTH-01**：管理员在浏览器使用环境配置的邮箱和密码登录。页面没有第二因子输入。
刷新页面仍登录，退出后不能访问已登录页面。重新登录再继续。浏览器网络面板检查登录
请求只提交 `login/password`；生产响应 Cookie 具有 Secure、HttpOnly、SameSite=Strict。
根账户不要用于错误密码锁定试验。

**USER-01**：管理员打开“用户管理”，手工创建下列账户；密码自行生成并独立保管，
普通/运维密码为 15–128 字节，建议随机 ASCII。每个账户分别在浏览器完成登录、刷新、退出再登录。

| 用户名 | 邮箱 | 角色 | 用途 |
| --- | --- | --- | --- |
| `qa-operator` | `qa-operator@example.test` | 运维人员 | 审批、授权和吊销 |
| `qa-user-a` | `qa-user-a@example.test` | 普通用户 | 申请者、独立签发实例所有者 |
| `qa-user-b` | `qa-user-b@example.test` | 普通用户 | 他人隔离与锁定测试 |

终端登录辅助命令会交互读取密码，不将密码放在命令参数中：

```bash
qa_login admin "$ROOT_LOGIN"
qa_login op qa-operator
qa_login a qa-user-a
qa_login b qa-user-b
qa_http admin GET /api/v1/users 200 evidence/users.json
export OP_ID=$(jq -er '.items[] | select(.username=="qa-operator") | .id' evidence/users.json)
export A_ID=$(jq -er '.items[] | select(.username=="qa-user-a") | .id' evidence/users.json)
export B_ID=$(jq -er '.items[] | select(.username=="qa-user-b") | .id' evidence/users.json)
qa_http a GET /api/v1/users 403 evidence/a-no-users.json
qa_http op GET /api/v1/users 403 evidence/op-no-users.json
qa_http a GET /api/v1/auth/session 200 evidence/a-session.json
jq -e '.user.username=="qa-user-a" and .user.role=="user"' evidence/a-session.json
```

## 3. 人工在系统中创建根和中间 CA

**CA-WEB-01**：管理员进入“证书机构”→“创建 CA”，分别按表创建两个 CA。
第二次创建前确认已选择第一次创建的根作为上级。

| 字段 | 根 CA | 中间 CA |
| --- | --- | --- |
| 机构类型 | 根 CA | 中间 CA |
| 显示名称 | `QA Web Root` | `QA Web Issuing` |
| 公开标识 | `qa-root-web` | `qa-issuing-web` |
| 最大下级 CA 深度 | `1` | `0` |
| CN | `PKI QA Web Root 2026` | `PKI QA Web Issuing 2026` |
| O | `PKI Acceptance Lab` | `PKI Acceptance Lab` |
| OU | `Trust Services` | `Issuing Services` |
| C / ST / L | `CN` / `Shanghai` / `Shanghai` | 相同 |
| 上级 CA | 无 | `QA Web Root` |

系统新建根固定 RSA-4096，中间固定 RSA-3072；名义有效期分别 10×365 天、3×365 天，
会回溯约 5 分钟并受上级有效期限制，不按自然年或页面显示天数精确相减来判错。
导出证书并验证，以接口为准定位唯一对象：

```bash
qa_http admin GET /api/v1/cas 200 evidence/cas-web.json
export ROOT_WEB_ID=$(jq -er '.items[] | select(.slug=="qa-root-web") | .id' evidence/cas-web.json)
export INT_WEB_ID=$(jq -er '.items[] | select(.slug=="qa-issuing-web") | .id' evidence/cas-web.json)
qa_http admin GET "/api/v1/cas/$ROOT_WEB_ID" 200 evidence/root-web.json
qa_http admin GET "/api/v1/cas/$INT_WEB_ID" 200 evidence/int-web.json
jq -ej '.certificate_pem' evidence/root-web.json > downloads/root-web.pem
jq -ej '.certificate_pem' evidence/int-web.json > downloads/int-web.pem
jq -e '.kind=="root" and .path_length==1 and .subject.common_name=="PKI QA Web Root 2026"' evidence/root-web.json
jq -e --arg root "$ROOT_WEB_ID" '.parent_ca_id==$root and .kind=="intermediate" and .path_length==0' evidence/int-web.json
qa_check web-root-signature openssl verify -check_ss_sig -CAfile downloads/root-web.pem downloads/root-web.pem
qa_check web-ca-chain openssl verify -CAfile downloads/root-web.pem downloads/int-web.pem
openssl x509 -in downloads/root-web.pem -noout -subject -issuer -dates -text > evidence/root-web-fields.txt
openssl x509 -in downloads/int-web.pem -noout -subject -issuer -dates -text > evidence/int-web-fields.txt
```

人工逐项对照 CN/O/OU/C/ST/L、算法、有效期、CA:TRUE、pathlen、Certificate Sign、
CRL Sign、SKI/AKI；根的 Subject=Issuer，中间的 Issuer=根 Subject。
另尝试重复公开标识、深度为 0 的根创建中间、普通账户调用导入接口，均应拒绝，
不能创建出隐藏的成功对象。深度为 0 的根可另建 `qa-root-zero` 专用于拒绝测试。

## 4. 人工用 OpenSSL 准备导入材料

**CA-IMPORT-01**：下面各段由验收员在终端逐段执行；不依赖系统替你生成密钥。
两个 CA 的主题、序列号、算法和约束是固定的，密钥和 SKI 每轮不同。
根用 RSA-2048、中间用 ECDSA P-256，额外覆盖导入算法与混合算法链。

```bash
cat > fixtures/root.cnf <<'EOF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = root_ext
[dn]
C = CN
ST = Shanghai
L = Shanghai
O = PKI Acceptance Lab
OU = Import Trust Services
CN = PKI QA Import Root 2026
[root_ext]
basicConstraints = critical,CA:true,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out .secrets/root-import.key
openssl req -new -x509 -sha256 -days 3650 -set_serial 0x1001 \
  -key .secrets/root-import.key -config fixtures/root.cnf -out fixtures/root-import.pem

cat > fixtures/intermediate.cnf <<'EOF'
[req]
prompt = no
distinguished_name = dn
[dn]
C = CN
ST = Shanghai
L = Shanghai
O = PKI Acceptance Lab
OU = Import Issuing Services
CN = PKI QA Import Issuing 2026
EOF
cat > fixtures/intermediate.ext <<EOF
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
authorityInfoAccess = caIssuers;URI:$PUBLIC/issuers/qa-root-import.cer,OCSP;URI:$PUBLIC/ocsp/qa-root-import
crlDistributionPoints = URI:$PUBLIC/crl/qa-root-import.crl
EOF
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out .secrets/int-import.key
openssl req -new -sha256 -key .secrets/int-import.key -config fixtures/intermediate.cnf -out fixtures/int-import.csr
openssl x509 -req -sha256 -days 1095 -set_serial 0x2001 \
  -in fixtures/int-import.csr -CA fixtures/root-import.pem -CAkey .secrets/root-import.key \
  -extfile fixtures/intermediate.ext -out fixtures/int-import.pem
qa_check import-root-signature openssl verify -check_ss_sig -CAfile fixtures/root-import.pem fixtures/root-import.pem
qa_check import-ca-chain openssl verify -CAfile fixtures/root-import.pem fixtures/int-import.pem
openssl x509 -in fixtures/root-import.pem -noout -subject -issuer -serial -text > evidence/root-import-fields.txt
openssl x509 -in fixtures/int-import.pem -noout -subject -issuer -serial -text > evidence/int-import-fields.txt
```

**CA-IMPORT-02**：浏览器“导入 CA”先导入根：类型根、名称 `QA Import Root`、标识
`qa-root-import`，证书 `fixtures/root-import.pem`、私钥 `.secrets/root-import.key`。
再导入中间：名称 `QA Import Issuing`、标识 `qa-issuing-import`、上级选刚导入的根，
证书 `fixtures/int-import.pem`、私钥 `.secrets/int-import.key`。
通过文件选择器上传；隐藏目录可在选择器输入完整路径。不把链文件当作单张 CA 证书上传。

```bash
qa_http admin GET /api/v1/cas 200 evidence/cas-import.json
export ROOT_ID=$(jq -er '.items[] | select(.slug=="qa-root-import") | .id' evidence/cas-import.json)
export INT_ID=$(jq -er '.items[] | select(.slug=="qa-issuing-import") | .id' evidence/cas-import.json)
qa_http admin GET "/api/v1/cas/$ROOT_ID" 200 evidence/root-import.json
qa_http admin GET "/api/v1/cas/$INT_ID" 200 evidence/int-import.json
jq -ej '.certificate_pem' evidence/root-import.json > downloads/root-import.pem
jq -ej '.certificate_pem' evidence/int-import.json > downloads/int-import.pem
openssl x509 -in fixtures/root-import.pem -outform DER -out fixtures/root-import.der
openssl x509 -in downloads/root-import.pem -outform DER -out downloads/root-import.der
openssl x509 -in fixtures/int-import.pem -outform DER -out fixtures/int-import.der
openssl x509 -in downloads/int-import.pem -outform DER -out downloads/int-import.der
cmp fixtures/root-import.der downloads/root-import.der
cmp fixtures/int-import.der downloads/int-import.der
jq -e '.serial=="4097" and .path_length==1' evidence/root-import.json
jq -e --arg root "$ROOT_ID" '.serial=="8193" and .path_length==0 and .parent_ca_id==$root' evidence/int-import.json
```

PEM 的空白和换行可能被规范化，以上比较 DER 来判断证书身份，不比较文件显示格式。检查导入后的 Subject、NotBefore/NotAfter、序列号和公钥没有重签或改写。

**CA-IMPORT-03**：以下拒绝测试必须使用新的幂等键，防止误命中成功缓存：

```bash
jq -n --rawfile cert fixtures/root-import.pem --rawfile key .secrets/root-import.key \
  '{kind:"root",name:"Duplicate",slug:"qa-root-duplicate",certificate_pem:$cert,private_key_pem:$key}' > .secrets/duplicate-import.json
qa_http admin POST /api/v1/cas/import 409 evidence/duplicate-ca.json .secrets/duplicate-import.json
qa_http a POST /api/v1/cas/import 403 evidence/a-no-import.json .secrets/duplicate-import.json
jq '.slug="qa-root-wrong-key"' .secrets/duplicate-import.json > .secrets/wrong-key-import.json
# 用另一把真实私钥测试“不匹配”，不是只测试 JSON 格式错误。
jq --rawfile key .secrets/int-import.key '.private_key_pem=$key' \
  .secrets/wrong-key-import.json > .secrets/wrong-key-final.json
qa_http admin POST /api/v1/cas/import 422 evidence/wrong-ca-key.json .secrets/wrong-key-final.json
```

浏览器再试“把中间当根导入”和“中间选择 Web 根作为错误上级”，均应失败。
核对列表没有 `qa-root-duplicate`、`qa-root-wrong-key` 等失败对象。

## 5. 策略、授权与标准 CSR

**PROFILE-01**：在 `QA Import Issuing`→“签发策略”手工新建 `qa-tls-7d`，
允许签发开启、默认有效期 7 天、最大 30 天，KU 选 digitalSignature/signing 和
keyEncipherment/key encipherment，EKU 选 server auth、client auth。
DNS 模式填 `*.qa.example.test`，IP 网段填 `192.0.2.0/24`，Email/URI 开关关闭，
扩展策略 JSON 为 `{}`。每个标签输入后按回车，确认页面确实显示为独立项。

```bash
qa_http admin GET "/api/v1/cas/$INT_ID/profiles" 200 evidence/profiles.json
export PROFILE_ID=$(jq -er '.items[] | select(.name=="qa-tls-7d") | .id' evidence/profiles.json)
jq -e --arg id "$PROFILE_ID" '.items[] | select(.id==$id) |
  .enabled and .default_validity_seconds==604800 and .max_validity_seconds==2592000 and
  .allowed_dns_patterns==["*.qa.example.test"] and .allowed_ip_ranges==["192.0.2.0/24"] and
  (.allow_email_sans|not) and (.allow_uri_sans|not)' evidence/profiles.json
```

**GRANT-01**：管理员在该中间 CA→“运维授权”，给 `qa-operator` 分别授予
“查看申请与证书”和“审批申请”，暂不授予“吊销证书”。根 CA 不应允许委派。
`issue/执行签发` 不等于绕过审批的直接签发接口，本计划不把它当作此类能力。

**CSR-01**：验收员在终端生成叶私钥和 CSR。此 CSR 只有 SAN 请求扩展，后面也用于独立签发。

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out .secrets/leaf-a.key
openssl req -new -sha256 -key .secrets/leaf-a.key \
  -subj '/C=CN/ST=Shanghai/L=Shanghai/O=PKI Acceptance Lab/OU=Service QA/CN=service.qa.example.test' \
  -addext 'subjectAltName=DNS:service.qa.example.test,DNS:alt.qa.example.test,IP:192.0.2.10' \
  -out fixtures/leaf-a.csr
qa_check csr-signature openssl req -in fixtures/leaf-a.csr -verify -noout
openssl req -in fixtures/leaf-a.csr -noout -text > evidence/leaf-csr-fields.txt
```

**PROFILE-02**：A 在页面提交以下申请，预期失败且不进入可审批队列：

| 输入 | 固定值 | 预期 |
| --- | --- | --- |
| 服务器生成，越界 DNS | `outside.example.test` | SAN 策略拒绝 |
| 服务器生成，越界 IP | `198.51.100.10` | 网段策略拒绝 |
| 有效 DNS，但有效期超上限 | `service.qa.example.test`、`2592001` 秒 | 有效期拒绝 |
| Email 或 URI SAN | `qa@example.test` 或 `spiffe://qa.example.test/app` | 关闭的 SAN 类型拒绝 |

然后编辑策略，修改说明并保存，刷新确认保存；临时禁用策略时它不应可用于新申请，
再启用。另新建未引用策略 `qa-delete-me` 后删除成功；默认策略或已被申请引用的策略
不允许删除（引用检查在下节申请完成后执行）。

## 6. 申请、审批、后台签发与验证

**ISSUE-01**：A 打开“证书申请”→“申请证书”，选 `QA Import Issuing`、`qa-tls-7d`，
选择“提交 CSR”，粘贴 `fixtures/leaf-a.csr`，有效期留空。提交后记录申请 ID：

```bash
export REQ_A='替换为申请详情地址中的UUID'
qa_http a GET "/api/v1/certificate-requests/$REQ_A" 200 evidence/request-a-pending.json
jq -e '.status=="pending" and .key_generation_mode=="client_csr"' evidence/request-a-pending.json
qa_http b GET "/api/v1/certificate-requests/$REQ_A" 404 evidence/b-no-request-a.json
qa_http op GET "/api/v1/certificate-requests/$REQ_A" 200 evidence/op-request-a.json
```

运维在自己的浏览器打开该申请，批准并填写 `QA approve CSR A`。
先看到 `approved/issuing` 均可，但必须继续刷新到 `issued`。超过 60 秒仍未签发记为 FAIL，
保存申请的 `error_code`、ready 检查和服务日志；不能把 HTTP 202 当作签发完成。

```bash
qa_http a GET "/api/v1/certificate-requests/$REQ_A" 200 evidence/request-a-issued.json
jq -e '.status=="issued"' evidence/request-a-issued.json
qa_http a GET /api/v1/certificates 200 evidence/a-certificates.json
export CERT_A=$(jq -er --arg req "$REQ_A" '.items[] | select(.request_id==$req) | .id' evidence/a-certificates.json)
qa_http a GET "/api/v1/certificates/$CERT_A" 200 evidence/cert-a.json
qa_http a GET "/api/v1/certificates/$CERT_A/download" 200 downloads/leaf-a-chain.pem
jq -ej '.certificate_pem' evidence/cert-a.json > downloads/leaf-a.pem
qa_http b GET "/api/v1/certificates/$CERT_A" 404 evidence/b-no-certificate-a.json
qa_http b GET "/api/v1/certificates/$CERT_A/download" 404 evidence/b-no-chain-a.json
qa_check leaf-chain openssl verify -CAfile downloads/root-import.pem -untrusted downloads/int-import.pem \
  -purpose sslserver -verify_hostname service.qa.example.test downloads/leaf-a.pem
qa_check leaf-client-purpose openssl verify -CAfile downloads/root-import.pem -untrusted downloads/int-import.pem \
  -purpose sslclient downloads/leaf-a.pem
qa_check leaf-ip openssl verify -CAfile downloads/root-import.pem -untrusted downloads/int-import.pem \
  -verify_ip 192.0.2.10 downloads/leaf-a.pem
qa_reject leaf-wrong-host 'hostname mismatch' openssl verify -CAfile downloads/root-import.pem \
  -untrusted downloads/int-import.pem -verify_hostname outside.example.test downloads/leaf-a.pem
openssl x509 -in downloads/leaf-a.pem -pubkey -noout > downloads/leaf-a.pub
openssl pkey -in .secrets/leaf-a.key -pubout > .secrets/leaf-a.pub
cmp downloads/leaf-a.pub .secrets/leaf-a.pub
openssl x509 -in downloads/leaf-a.pem -noout -text > evidence/leaf-a-fields.txt
```

检查叶证书为非 CA，三个 SAN 精确匹配、无额外身份，KU/EKU 符合策略；有效期约 7 天且
不超过链上任何 CA 的到期时间。AIA issuer/OCSP/CRL URL 指向公开域名下
`qa-issuing-import` 的对应端点。普通 `openssl verify` 不会联网查吊销，吊销另按第 8 节检查。

**ISSUE-02**：再用同一 CSR，通过 `QA Web Issuing` 的默认策略申请一次，
由管理员审批。下载为 `downloads/leaf-web.pem`（若链文件，第一张为叶证书），执行：

```bash
qa_check web-leaf-chain openssl verify -CAfile downloads/root-web.pem \
  -untrusted downloads/int-web.pem -verify_hostname service.qa.example.test downloads/leaf-web.pem
```

这一步确保系统自己生成的 CA 也能实际签发，而不只是建表或展示成功。

**ISSUE-03**：A 再提交一次同 CSR 申请，管理员“拒绝”，原因 `QA reject case`。
申请变为 `rejected`，没有对应签发证书，证书总览过滤“已拒绝”可找到它。
再由运维创建一个自己的有效申请，选导入中间与 `qa-tls-7d`，记下 ID，验证不能自审批：

```bash
export REQ_OP='替换为运维自己申请的UUID'
printf '{"comment":"QA self approval must fail"}\n' > fixtures/self-approve.json
qa_http op POST "/api/v1/certificate-requests/$REQ_OP/approve" 409 evidence/op-no-self-approval.json fixtures/self-approve.json
qa_http op GET "/api/v1/certificate-requests/$REQ_OP" 200 evidence/op-own-pending.json
jq -e '.status=="pending"' evidence/op-own-pending.json
```

由管理员审批后应能签发。管理员自己创建的申请也按相同步骤用 admin 别名验证 409，
再由有授权的运维审批。所有角色都不能自审批。

## 7. 服务器生成密钥和敏感导出

**KEY-01**：A 在 `QA Import Issuing`、`qa-tls-7d` 提交“服务端生成”申请，
CN `serverkey.qa.example.test`，SAN `serverkey.qa.example.test`、`192.0.2.11`，
O `PKI Acceptance Lab`，OU `Server Key QA`，有效期 `86400` 秒；运维审批到 `issued`。
记录证书 ID 为 `CERT_SERVER`。首次领取前先测试 B 无法领取，然后由 A 真正领取。

```bash
export CERT_SERVER='替换为服务器生成证书的UUID'
printf '{}\n' > fixtures/empty.json
qa_http b POST "/api/v1/certificates/$CERT_SERVER/private-key/download" 404 evidence/b-no-private-key.json fixtures/empty.json
qa_http a GET "/api/v1/certificates/$CERT_SERVER" 200 evidence/server-cert.json
jq -ej '.certificate_pem' evidence/server-cert.json > downloads/server-leaf.pem
qa_http a POST "/api/v1/certificates/$CERT_SERVER/private-key/download" 200 .secrets/server-leaf.key fixtures/empty.json
qa_http a POST "/api/v1/certificates/$CERT_SERVER/private-key/download" 410 evidence/private-key-gone.json fixtures/empty.json
openssl x509 -in downloads/server-leaf.pem -pubkey -noout > downloads/server-leaf.pub
openssl pkey -in .secrets/server-leaf.key -pubout > .secrets/server-leaf.pub
cmp downloads/server-leaf.pub .secrets/server-leaf.pub
```

首次领取由命令完成，随后浏览器再点“下载一次性私钥”应提示已经不可用。
客户端 CSR 证书没有服务器保存的叶私钥，A 对 `CERT_A` 的领取也应为 410。
另用 CN/SAN `latekey.qa.example.test` 创建一张服务器生成证书，有效期 259200 秒，审批
签发后记录 ID 和签发时间，不领取。签发超过 24 小时后用其申请者领取应为 410；
未完成等待时将这一项记录为 BLOCKED，不要修改系统时钟或直接改库模拟通过。

**KEY-02**：管理员在导入中间 CA 详情选择“导出私钥”，先输错误管理员密码，应拒绝；
再输入当前正确密码，保存为 `.secrets/int-exported.key`，比较公钥：

```bash
openssl pkey -in .secrets/int-import.key -pubout > .secrets/int-original.pub
openssl pkey -in .secrets/int-exported.key -pubout > .secrets/int-exported.pub
cmp .secrets/int-original.pub .secrets/int-exported.pub
```

运维和普通用户不应有此操作权限；接口额外测试可提交 `{}` 到导出端点，预期 403。
敏感导出响应应为 `Cache-Control: no-store...`，不要把私钥放进普通验收附件。

## 8. 吊销、CRL 和 OCSP

### 8.1 吊销前建立基准

**STATUS-01**：先保留 `CERT_SERVER` 为 good，专门吊销 `CERT_A`。
下载导入中间 CA 的 DER issuer 和 CRL：

```bash
qa_http public GET /issuers/qa-issuing-import.cer 200 downloads/issuer.der
openssl x509 -inform DER -in downloads/issuer.der -out downloads/issuer.pem
cmp downloads/issuer.der downloads/int-import.der
qa_http public GET /crl/qa-issuing-import.crl 200 downloads/before.crl.der
openssl crl -inform DER -in downloads/before.crl.der -out downloads/before.crl.pem
qa_check crl-before-signature openssl crl -in downloads/before.crl.pem -verify -CAfile downloads/int-import.pem -noout
qa_check crl-before-good openssl verify -CAfile downloads/root-import.pem -untrusted downloads/int-import.pem \
  -CRLfile downloads/before.crl.pem -crl_check downloads/leaf-a.pem
openssl ocsp -issuer downloads/int-import.pem -cert downloads/leaf-a.pem -no_nonce -reqout fixtures/ocsp-a.req
curl --fail --silent --show-error --proto '=https' -H 'Content-Type: application/ocsp-request' \
  --data-binary @fixtures/ocsp-a.req "$PUBLIC/ocsp/qa-issuing-import" -o downloads/ocsp-before.der
qa_check ocsp-before-signature openssl ocsp -respin downloads/ocsp-before.der -issuer downloads/int-import.pem \
  -cert downloads/leaf-a.pem -CAfile downloads/root-import.pem -verify_other downloads/int-import.pem -no_nonce
grep -F 'Response verify OK' evidence/ocsp-before-signature.log
grep -F 'downloads/leaf-a.pem: good' evidence/ocsp-before-signature.log
```

必须同时看到 OCSP 签名验证成功和目标证书 good。部分 OpenSSL 版本对 revoked/unknown 仍
可返回退出码 0，所以不能只检查 `qa_check`。同理，不能跳过响应者委托证书的链与 EKU 验证。

### 8.2 人工吊销，再验证状态变化

**REVOKE-01**：尚未授予 revoke 时，运维调用吊销应失败且 `CERT_A` 仍 good。

```bash
printf '{"reason":1,"comment":"QA must deny before revoke grant"}\n' > fixtures/revoke-denied.json
qa_http op POST "/api/v1/certificates/$CERT_A/revoke" 422 evidence/op-no-revoke.json fixtures/revoke-denied.json
qa_http a GET "/api/v1/certificates/$CERT_A" 200 evidence/still-good-before-revoke.json
jq -e '.status=="good"' evidence/still-good-before-revoke.json
```

随后管理员在中间 CA 授权页给运维增加“吊销证书”，运维在证书详情点击“吊销”，
原因为 keyCompromise（1），说明 `QA deliberate revocation`，确认永久吊销。

```bash
qa_http a GET "/api/v1/certificates/$CERT_A" 200 evidence/cert-a-revoked.json
jq -e '.status=="revoked"' evidence/cert-a-revoked.json
export SERIAL_A=$(jq -er '.serial' evidence/cert-a-revoked.json)
export FP_A=$(jq -er '.fingerprint_sha256' evidence/cert-a-revoked.json)
qa_http public GET "/pki/v1/status/qa-issuing-import/$SERIAL_A" 200 evidence/status-a.json
qa_http public GET "/pki/v1/certificates/by-fingerprint/$FP_A" 200 evidence/public-a-fingerprint.json
qa_http public GET "/pki/v1/certificates/by-issuer/qa-issuing-import/serial/$SERIAL_A" 200 evidence/public-a-serial.json
jq -e '.status=="revoked"' evidence/status-a.json
jq -e --arg id "$CERT_A" '.id==$id and .status=="revoked"' evidence/public-a-fingerprint.json
qa_http public GET /crl/qa-issuing-import.crl 200 downloads/after.crl.der
openssl crl -inform DER -in downloads/after.crl.der -out downloads/after.crl.pem
qa_check crl-after-signature openssl crl -in downloads/after.crl.pem -verify -CAfile downloads/int-import.pem -noout
qa_reject crl-revoked 'certificate revoked' openssl verify -CAfile downloads/root-import.pem \
  -untrusted downloads/int-import.pem -CRLfile downloads/after.crl.pem -crl_check downloads/leaf-a.pem
qa_check crl-control-good openssl verify -CAfile downloads/root-import.pem -untrusted downloads/int-import.pem \
  -CRLfile downloads/after.crl.pem -crl_check downloads/server-leaf.pem
curl --fail --silent --show-error --proto '=https' -H 'Content-Type: application/ocsp-request' \
  --data-binary @fixtures/ocsp-a.req "$PUBLIC/ocsp/qa-issuing-import" -o downloads/ocsp-after.der
qa_check ocsp-after-signature openssl ocsp -respin downloads/ocsp-after.der -issuer downloads/int-import.pem \
  -cert downloads/leaf-a.pem -CAfile downloads/root-import.pem -verify_other downloads/int-import.pem -no_nonce
grep -F 'Response verify OK' evidence/ocsp-after-signature.log
grep -F 'downloads/leaf-a.pem: revoked' evidence/ocsp-after-signature.log
openssl crl -in downloads/before.crl.pem -noout -crlnumber -lastupdate -nextupdate > evidence/crl-before-fields.txt
openssl crl -in downloads/after.crl.pem -noout -text > evidence/crl-after-fields.txt
```

检查 CRL Number 增加、NextUpdate 晚于当前时间、序列号与原因 1 正确，且未误吊销
`CERT_SERVER`。页面/接口状态、CRL 和 OCSP 三者必须一致。普通链验证仍可能显示 OK，
它没有执行吊销检查，不能据此判定吊销无效。

**STATUS-02**：公开目录只列 CA；精确查询可查到目标叶证书，不提供叶证书全量列表。
不存在的有效格式指纹和序列号应 404，非法指纹应 400。公开精确查询会带 owner/request UUID，
按当前设计记录它，不把公开的这些字段误报为“匿名化通过”。
GET OCSP 也要测试：将同一请求的标准 Base64 逐字节 URL 编码后请求，验证与 POST 一致。

```bash
OCSP_PATH=$(python3 - <<'PY'
import base64, pathlib, urllib.parse
print(urllib.parse.quote(base64.b64encode(pathlib.Path('fixtures/ocsp-a.req').read_bytes()).decode(), safe=''))
PY
)
qa_http public GET "/ocsp/qa-issuing-import/$OCSP_PATH" 200 downloads/ocsp-get.der
qa_check ocsp-get-signature openssl ocsp -respin downloads/ocsp-get.der -issuer downloads/int-import.pem \
  -cert downloads/leaf-a.pem -CAfile downloads/root-import.pem -verify_other downloads/int-import.pem -no_nonce
grep -F 'downloads/leaf-a.pem: revoked' evidence/ocsp-get-signature.log
```

## 9. PKI 工具页面

**TOOL-01**：A 打开“PKI 工具”→“证书解析”，粘贴 `downloads/leaf-a.pem`。
核对 Subject、Issuer、十进制序列号、SAN、有效期、is_ca=false 和 SHA-256 指纹，
应与 OpenSSL 和证书详情一致。粘贴非证书文本应报错。

```bash
jq -n --rawfile cert downloads/leaf-a.pem '{certificate_pem:$cert}' > fixtures/certinfo.json
qa_http a POST /api/v1/utilities/certinfo 200 evidence/certinfo.json fixtures/certinfo.json
jq -e --arg fp "$FP_A" '.fingerprint_sha256==$fp and (.is_ca|not)' evidence/certinfo.json
```

**TOOL-02**：在“CSR 生成”页面，CN/SAN 为 `tool.qa.example.test`、O 为
`PKI Acceptance Lab`，依次测试 RSA-3072、RSA-4096、ECDSA P-256、ECDSA P-384。
每次保存返回的 CSR 与私钥到私有目录，用 `openssl req -verify -noout` 验证签名，
并像第 6 节那样提取两边公钥比较。页面刷新不应重新展示上一轮私钥。
可用下面的接口请求获得一次便于自动核对的原始材料：

```bash
cat > fixtures/utility-csr.json <<'EOF'
{"subject":{"common_name":"tool.qa.example.test","organization":"PKI Acceptance Lab"},"sans":["tool.qa.example.test"],"algorithm":"ecdsa","key_size":256}
EOF
qa_http a POST /api/v1/utilities/csr 200 .secrets/utility-result.json fixtures/utility-csr.json
jq -ej '.csr_pem' .secrets/utility-result.json > fixtures/utility.csr
jq -ej '.private_key_pem' .secrets/utility-result.json > .secrets/utility.key
qa_check utility-csr-signature openssl req -in fixtures/utility.csr -verify -noout
openssl req -in fixtures/utility.csr -pubkey -noout > downloads/utility.pub
openssl pkey -in .secrets/utility.key -pubout > .secrets/utility.pub
cmp downloads/utility.pub .secrets/utility.pub
```

RSA-1024、ECDSA 521 等未支持组合应拒绝；生成的私钥不是服务器待领取材料。

**TOOL-03**：在“证书链优化”页面，叶证书用 `downloads/leaf-a.pem`、中间证书用
`downloads/int-import.pem`、信任根用 `downloads/root-import.pem`，依次选择
optimal/ubiquitous/force。记录结果包含正确链且公钥、叶证书未改变。
吊销不会让这个只构建链的工具自动拒绝，不能把它当作在线吊销验证器。

```bash
jq -n --rawfile leaf downloads/leaf-a.pem --rawfile roots downloads/root-import.pem \
  --rawfile ints downloads/int-import.pem \
  '{certificates_pem:$leaf,roots_pem:$roots,intermediates_pem:$ints,flavor:"optimal"}' > fixtures/bundle.json
qa_http a POST /api/v1/utilities/bundle 200 evidence/bundle.json fixtures/bundle.json
jq -ej '.bundle' evidence/bundle.json > downloads/bundle.pem
qa_check bundle-chain openssl verify -CAfile downloads/root-import.pem \
  -untrusted downloads/int-import.pem downloads/bundle.pem
```

将信任根改为 `root-web.pem`，保留导入叶和中间，optimal 模式应拒绝，不能联网获取
其他 CA 后悄悄成功。force 的语义不等于验证可信，不用它作为这一负例的判定模式。

## 10. TSA 时间戳

**TSA-01**：管理员在 `QA Import Issuing`→“时间戳服务”创建：名称 `QA TSU`、
公开路径标识 `qa-tsa`、签名证书有效期 30 天、策略 OID `1.3.6.1.4.1.55555.2026.1`。
此 OID 仅作隔离验收占位，不声明企业号归属；业务部署改用组织实际控制的 OID。
普通用户不能创建 TSU。下载/查看 TSU 证书，检查 KU digitalSignature、critical EKU
只含 timeStamping、链和有效期正确。

```bash
qa_http admin GET "/api/v1/cas/$INT_ID/timestamp-authorities" 200 evidence/tsus.json
jq -e '.items[] | select(.slug=="qa-tsa") | .policy_oid=="1.3.6.1.4.1.55555.2026.1"' evidence/tsus.json
printf 'PKI manual acceptance artifact\n' > fixtures/artifact.bin
for hash in sha256 sha384 sha512; do
  openssl ts -query -data fixtures/artifact.bin -"$hash" -cert \
    -tspolicy 1.3.6.1.4.1.55555.2026.1 -out "fixtures/$hash.tsq"
  curl --fail --silent --show-error --proto '=https' -H 'Content-Type: application/timestamp-query' \
    --data-binary "@fixtures/$hash.tsq" "$PUBLIC/tsa/qa-tsa" -o "downloads/$hash.tsr"
  qa_check "tsa-$hash" openssl ts -verify -queryfile "fixtures/$hash.tsq" \
    -in "downloads/$hash.tsr" -CAfile downloads/root-import.pem -untrusted downloads/int-import.pem
  openssl ts -reply -in "downloads/$hash.tsr" -text > "evidence/tsa-$hash.txt"
done
```

三种摘要均须 `Verification: OK`。人工对照请求与响应的 policy、message imprint、nonce，
检查响应时间接近服务器时间，有 Accuracy 和新的正序列号。
对同一 tsq 再请求一次，验证仍成功但时间戳序列号不同，不能被 Nginx 缓存重放。
响应头应有 `application/timestamp-reply` 和 `Cache-Control: no-store`。

**TSA-02**：修改原文后验证必须失败；SHA-1、错误策略、坏 DER 请求应拒绝。

```bash
printf 'tampered artifact\n' > fixtures/artifact-changed.bin
qa_reject tsa-tampered 'Verification: FAILED' openssl ts -verify -data fixtures/artifact-changed.bin \
  -in downloads/sha256.tsr -CAfile downloads/root-import.pem -untrusted downloads/int-import.pem
openssl ts -query -data fixtures/artifact.bin -sha1 -cert -out fixtures/sha1.tsq
curl --fail --silent --show-error --proto '=https' -H 'Content-Type: application/timestamp-query' \
  --data-binary @fixtures/sha1.tsq "$PUBLIC/tsa/qa-tsa" -o downloads/sha1-rejected.tsr
openssl ts -reply -in downloads/sha1-rejected.tsr -text > evidence/tsa-sha1-rejected.txt
grep -F 'Rejected' evidence/tsa-sha1-rejected.txt
```

再生成指定错误 OID 的 SHA-256 查询，预期 DER 中为 unacceptedPolicy；错误 Content-Type
为 HTTP 415，超过 64 KiB 的 body 应由应用或代理以 413 拒绝。
协议拒绝仍可能 HTTP 200，必须解析 DER status，不记作签发成功。
生产 NTP 未同步时应为 timeNotAvailable，正向时间戳验收记 BLOCKED，恢复时间同步后重做；
不要开启开发模式或改系统时间绕过。具体失败文字可能由 OpenSSL 显示为自然语言，保留完整响应。

## 11. 独立 CA + 凭据自动签发

### 11.1 人工建立实例和凭据

**IND-01**：A 登录“独立签发”，新建 `QA Independent`，CA 证书选择
`fixtures/int-import.pem`、私钥 `.secrets/int-import.key`、完整上级链
`fixtures/root-import.pem`。这有意与系统 CA 重复，验证两个功能的数据互不覆盖。
上级链不重复放签名中间本身。按表填写策略：

| 字段 | 固定值 |
| --- | --- |
| DNS 白名单 | `service.qa.example.test`、`alt.qa.example.test` |
| IP 网段 | `192.0.2.0/24` |
| Email / URI 白名单 | 空 |
| 允许通配符 | 关闭 |
| EKU | server_auth |
| 默认 / 最大有效期 | 3600 / 86400 秒 |
| SAN 数量上限 | 3 |

保存下列完整策略；创建后用接口回读和更新核对页面保存的字段。

```bash
cat > fixtures/independent-policy.json <<'EOF'
{"version":1,"allowed_dns_names":["service.qa.example.test","alt.qa.example.test"],"allowed_ip_ranges":["192.0.2.0/24"],"allowed_email_domains":[],"allowed_uri_prefixes":[],"allow_wildcards":false,"extended_key_usages":["server_auth"],"default_validity_seconds":3600,"max_validity_seconds":86400,"max_sans":3}
EOF
qa_http a GET /api/v1/signing-instances 200 evidence/signing-instances.json
export INSTANCE=$(jq -er '.items[] | select(.name=="QA Independent") | .id' evidence/signing-instances.json)
jq -n --slurpfile p fixtures/independent-policy.json '{name:"QA Independent",enabled:true,policy:$p[0]}' > fixtures/independent-update.json
qa_http a PUT "/api/v1/signing-instances/$INSTANCE" 200 evidence/signing-updated.json fixtures/independent-update.json
qa_http b GET "/api/v1/signing-instances/$INSTANCE" 404 evidence/b-no-instance.json
qa_http admin GET "/api/v1/signing-instances/$INSTANCE" 404 evidence/admin-no-instance.json
```

超级管理员没有隐式代管权限。再由 A 用同一套 CA 建立 `QA Independent Copy` 应成功，
两个实例 UUID 不同，管理 CA 列表不增加或改变。后文主要在第一个实例操作。

**IND-02**：A 在第一个实例创建两枚凭据：

| 名称 / 本地别名 | scopes | 总签发额度 | 有效期 | 每分钟速率 |
| --- | --- | --- | --- | --- |
| `qa-main` / `token-main` | issue、read、revoke | 2 | 86400 秒 | 10 |
| `qa-read-only` / `token-read` | read | 10 | 86400 秒 | 10 |

凭据附加策略留空。本章使用完整 CA 策略，不另放大凭据权限。
每枚完整 token 只展示一次：在本机终端隐藏输入保存，不写进命令历史、截图或普通证据文件。

```bash
python3 - <<'PY'
import getpass, os, pathlib
for alias in ('token-main', 'token-read'):
    token = getpass.getpass(f'Paste one-time credential for {alias}: ').strip()
    if not token.startswith('ist_') or len(token) != 47:
        raise SystemExit('Invalid credential; stop and check the selected credential')
    for suffix, value in (('txt', token+'\n'), ('headers', 'Authorization: Bearer '+token+'\n')):
        with os.fdopen(os.open(f'.secrets/{alias}.{suffix}', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), 'w') as out:
            out.write(value)
PY
qa_http a GET "/api/v1/signing-instances/$INSTANCE/credentials" 200 evidence/credentials.json
```

关闭展示框后列表不应再显示 token 明文。记录两枚 credential ID，不记录 token。

### 11.2 签发、幂等、白名单和权限

**IND-03**：此时 qa-main 尚未使用；以下顺序保证负例不会被“额度已用尽”提前拦住。

```bash
jq -n --rawfile csr fixtures/leaf-a.csr '{csr_pem:$csr,validity_seconds:3600}' > fixtures/independent-issue.json
qa_http token-main POST "/signing/$INSTANCE/issue" 201 evidence/independent-first.json fixtures/independent-issue.json qa-independent-0001
qa_http token-main POST "/signing/$INSTANCE/issue" 201 evidence/independent-replay.json fixtures/independent-issue.json qa-independent-0001
export INDEPENDENT_CERT=$(jq -er '.id' evidence/independent-first.json)
export INDEPENDENT_FP=$(jq -er '.fingerprint_sha256' evidence/independent-first.json)
jq -e --arg id "$INDEPENDENT_CERT" '.id==$id and .status=="good"' evidence/independent-replay.json
grep -i 'Idempotency-Replayed: true' evidence/independent-replay.json.headers
jq -ej '.certificate_pem' evidence/independent-first.json > downloads/independent-leaf.pem
qa_check independent-chain openssl verify -CAfile downloads/root-import.pem -untrusted downloads/int-import.pem \
  -purpose sslserver -verify_hostname service.qa.example.test downloads/independent-leaf.pem
qa_http token-main GET "/signing/$INSTANCE/certificates/$INDEPENDENT_CERT" 200 evidence/independent-read.json
qa_http token-read GET "/signing/$INSTANCE/certificates/$INDEPENDENT_CERT" 404 evidence/other-credential-no-record.json
qa_http token-read POST "/signing/$INSTANCE/issue" 401 evidence/read-scope-no-issue.json fixtures/independent-issue.json
qa_http public POST "/signing/$INSTANCE/issue" 401 evidence/no-bearer.json fixtures/independent-issue.json
jq '.validity_seconds=7200' fixtures/independent-issue.json > fixtures/independent-conflict.json
qa_http token-main POST "/signing/$INSTANCE/issue" 409 evidence/independent-conflict.json fixtures/independent-conflict.json qa-independent-0001
```

同一凭据、幂等键和完全相同的 JSON 重放，ID/序列号/指纹不变且只扣一次额度；
改变 body 使用原 key 必须 409。同一个实例的另一枚凭据也不能读取别人的签发记录。
新建请求不支持无幂等键；使用 curl 省略该头单独验证为 400（辅助函数会自动添加，
不能用它伪装“省略”测试）。

```bash
NO_KEY_STATUS=$(curl --silent --show-error --proto '=https' \
  --header @.secrets/token-main.headers --header 'Content-Type: application/json' \
  --data-binary @fixtures/independent-issue.json --output evidence/independent-no-key.json \
  --write-out '%{http_code}' "$PUBLIC/signing/$INSTANCE/issue")
test "$NO_KEY_STATUS" = 400
jq -e '.code=="signing_idempotency_required"' evidence/independent-no-key.json
```

**IND-04**：生成真实越界 CSR，预期 422。再测试携带 CA 请求扩展也被拒绝。

```bash
openssl req -new -sha256 -key .secrets/leaf-a.key -subj '/CN=outside.example.test' \
  -addext 'subjectAltName=DNS:outside.example.test' -out fixtures/independent-outside.csr
jq -n --rawfile csr fixtures/independent-outside.csr '{csr_pem:$csr,validity_seconds:3600}' > fixtures/independent-outside.json
qa_http token-main POST "/signing/$INSTANCE/issue" 422 evidence/independent-outside.json fixtures/independent-outside.json
openssl req -new -sha256 -key .secrets/leaf-a.key -subj '/CN=service.qa.example.test' \
  -addext 'subjectAltName=DNS:service.qa.example.test' -addext 'basicConstraints=critical,CA:TRUE' -out fixtures/independent-ca.csr
jq -n --rawfile csr fixtures/independent-ca.csr '{csr_pem:$csr,validity_seconds:3600}' > fixtures/independent-ca.json
qa_http token-main POST "/signing/$INSTANCE/issue" 422 evidence/independent-no-ca.json fixtures/independent-ca.json
printf '{"csr_pem":"x","csr_pem":"y"}\n' > fixtures/duplicate-fields.json
qa_http token-main POST "/signing/$INSTANCE/issue" 400 evidence/independent-duplicate-fields.json fixtures/duplicate-fields.json
```

在实例编辑页面临时移除 `alt.qa.example.test`，原正常 CSR 使用新 key 应 422；
原 `qa-independent-0001` 和原 body 重放仍返回原证书，不重新签发。
恢复策略后停用实例，新 key 应 403，查询历史记录和读取 CRL 仍可用；再启用。
这几项都要实际执行并记录响应，不能只观察开关。

### 11.3 客户端、额度、吊销与隔离

**IND-05**：使用项目随附的 Python 客户端签发第二张证书并原样重试。
内部 HTTPS CA 时在每条命令加 `--ca-file /path/to/https-roots.pem`。

```bash
python3 "$REPO/scripts/signing-client.py" issue --endpoint "$PUBLIC/signing/$INSTANCE/issue" \
  --token-file .secrets/token-main.txt --csr fixtures/leaf-a.csr --validity-seconds 3600 \
  --state .secrets/client-issue-state.json --output downloads/independent-client-chain.pem > evidence/client-issue.json
python3 "$REPO/scripts/signing-client.py" issue --endpoint "$PUBLIC/signing/$INSTANCE/issue" \
  --token-file .secrets/token-main.txt --csr fixtures/leaf-a.csr --validity-seconds 3600 \
  --state .secrets/client-issue-state.json --output downloads/independent-client-chain.pem > evidence/client-replay.json
cmp evidence/client-issue.json evidence/client-replay.json
export CLIENT_CERT=$(jq -er '.id' evidence/client-issue.json)
python3 "$REPO/scripts/signing-client.py" read --endpoint "$PUBLIC/signing/$INSTANCE/issue" \
  --token-file .secrets/token-main.txt --certificate-id "$CLIENT_CERT" \
  --output downloads/independent-client-read.pem > evidence/client-read.json
cmp downloads/independent-client-chain.pem downloads/independent-client-read.pem
qa_http token-main POST "/signing/$INSTANCE/issue" 403 evidence/independent-quota.json fixtures/independent-issue.json
jq -e '.code=="signing_quota_exhausted"' evidence/independent-quota.json
```

此时恰好使用 2 次额度。网络故障后保留 state 文件原样重试，不能删除 state 当作“重试”；
更新 CSR 或续期使用新的 state 文件。原请求失败/重放不得额外扣额度。
在页面检查两张记录，另用每页一条验证游标翻页没有重复：

```bash
qa_http a GET "/api/v1/signing-instances/$INSTANCE/certificates?limit=1" 200 evidence/signing-page-1.json
NEXT_CURSOR=$(jq -er '.next_cursor | select(length>0)' evidence/signing-page-1.json)
qa_http a GET "/api/v1/signing-instances/$INSTANCE/certificates?limit=1&before=$NEXT_CURSOR" 200 evidence/signing-page-2.json
jq -e --slurpfile first evidence/signing-page-1.json \
  '(.items|length)==1 and ($first[0].items|length)==1 and .items[0].id!=$first[0].items[0].id' evidence/signing-page-2.json
qa_http a GET "/api/v1/signing-instances/$INSTANCE/certificates?before=not-a-uuid" 400 evidence/signing-bad-cursor.json
```

**IND-06**：由凭据持有者吊销第一张独立证书，原因 1；同原因再调用成功，改原因 4 为 409。
随后 A 在网页实例证书列表中吊销第二张独立证书，验证所有者的管理操作也生效。

```bash
printf '{"reason":1}\n' > fixtures/revoke-1.json
printf '{"reason":4}\n' > fixtures/revoke-4.json
qa_http token-main POST "/signing/$INSTANCE/certificates/$INDEPENDENT_CERT/revoke" 200 evidence/independent-revoke.json fixtures/revoke-1.json
qa_http token-main POST "/signing/$INSTANCE/certificates/$INDEPENDENT_CERT/revoke" 200 evidence/independent-revoke-repeat.json fixtures/revoke-1.json
qa_http token-main POST "/signing/$INSTANCE/certificates/$INDEPENDENT_CERT/revoke" 409 evidence/independent-revoke-conflict.json fixtures/revoke-4.json
qa_http public GET "/signing/$INSTANCE/issuer.cer" 200 downloads/independent-issuer.der
qa_http public GET "/signing/$INSTANCE/crl" 200 downloads/independent.crl.der
openssl crl -inform DER -in downloads/independent.crl.der -out downloads/independent.crl.pem
qa_check independent-crl-signature openssl crl -in downloads/independent.crl.pem -verify -CAfile downloads/int-import.pem -noout
qa_reject independent-crl-revoked 'certificate revoked' openssl verify -extended_crl \
  -CAfile downloads/root-import.pem -untrusted downloads/int-import.pem -CRLfile downloads/independent.crl.pem \
  -crl_check downloads/independent-leaf.pem
openssl crl -in downloads/independent.crl.pem -noout -text > evidence/independent-crl-fields.txt
qa_http public GET "/pki/v1/certificates/by-fingerprint/$INDEPENDENT_FP" 404 evidence/independent-not-managed.json
qa_http a GET "/api/v1/certificates/$CERT_SERVER" 200 evidence/managed-still-good.json
jq -e '.status=="good"' evidence/managed-still-good.json
qa_http a GET /api/v1/certificates 200 evidence/managed-inventory-after.json
jq -e --arg id "$INDEPENDENT_CERT" 'all(.items[]; .id!=$id)' evidence/managed-inventory-after.json
```

检查独立 CRL 有 critical Issuing Distribution Point，URI 只指向本实例、只含本实例记录。
将它拿去验证同 CA 的 `downloads/server-leaf.pem`，OpenSSL 必须报不同 CRL scope 或找不到
适用 CRL，不能显示 good 或误报 revoked；再用系统 CRL 验证该证书仍应 good。
同样下载 `QA Independent Copy` 的 CRL，不能用于第一实例的叶证书。
独立实例首版没有 OCSP，不要求托管 OCSP 返回其历史签发状态。

**IND-07**：A 在页面撤销 qa-main 凭据，用它查询、签发（含原幂等键重放）和吊销都应 401；
已签发证书不会因凭据撤销自动被吊销，历史状态需按此前显式吊销结果检查。

```bash
qa_http token-main GET "/signing/$INSTANCE/certificates/$INDEPENDENT_CERT" 401 evidence/revoked-token-read.json
qa_http token-main POST "/signing/$INSTANCE/issue" 401 evidence/revoked-token-replay.json fixtures/independent-issue.json qa-independent-0001
qa_http token-main POST "/signing/$INSTANCE/certificates/$INDEPENDENT_CERT/revoke" 401 evidence/revoked-token-revoke.json fixtures/revoke-1.json
```

停用/重新启用所有者账户也要分别验证 token 拒绝/恢复；使用额外新凭据和有效签发记录完成，
避免拿已经撤销的 qa-main 验证“恢复”而得到错误结论。
另建附加策略更窄的凭据（例如只允许一个 DNS），多 SAN CSR 应被拒绝，不能扩大实例权限。
真实到期用例另建 `qa-expiry`，scopes 为 issue/read、额度 1、有效期 3600 秒，
按 IND-02 的方式用本地别名 `token-expiry` 保存 token，再签发并读取它自己的证书确认成功。
记录 credential 的 expires_at，真实等待到期后，用同 token 读取该证书应为 401；未执行记录 BLOCKED。

## 12. 会话、权限、幂等和账户恢复

**AUTH-02**：无 CSRF 的写入必须 403，错误 Origin 必须 403；合法请求可继续使用原会话。

```bash
printf '{}\n' > fixtures/empty.json
QA_NO_CSRF=1 qa_http admin POST /api/v1/utilities/certinfo 403 evidence/no-csrf.json fixtures/empty.json
jq -e '.code=="csrf_failed"' evidence/no-csrf.json
QA_ORIGIN=https://untrusted.example.test qa_http a GET /api/v1/auth/session 403 evidence/wrong-origin.json
qa_http a GET /api/v1/auth/session 200 evidence/session-after-csrf-test.json
qa_http op POST "/api/v1/cas/$INT_ID/keys/export" 403 evidence/op-no-ca-key.json fixtures/empty.json
qa_http a GET /api/v1/audit-events 403 evidence/a-no-audit.json
qa_http a GET /api/v1/metrics 403 evidence/a-no-metrics.json
qa_http op GET /api/v1/metrics 200 evidence/operator-metrics.txt
qa_http admin GET /api/v1/metrics 200 evidence/admin-metrics.txt
```

**IDEM-01**：托管申请同样验证幂等，第二次不能多一条申请。

```bash
jq -n --arg ca "$INT_ID" --arg profile "$PROFILE_ID" --rawfile csr fixtures/leaf-a.csr \
  '{ca_id:$ca,profile_id:$profile,csr_pem:$csr,server_generate_key:false}' > fixtures/managed-replay.json
qa_http a POST /api/v1/certificate-requests 201 evidence/managed-first.json fixtures/managed-replay.json qa-managed-request-0001
qa_http a POST /api/v1/certificate-requests 201 evidence/managed-replay.json fixtures/managed-replay.json qa-managed-request-0001
FIRST_REQUEST=$(jq -er '.id' evidence/managed-first.json)
jq -e --arg id "$FIRST_REQUEST" '.id==$id' evidence/managed-replay.json
jq '.requested_validity_seconds=86400' fixtures/managed-replay.json > fixtures/managed-conflict.json
qa_http a POST /api/v1/certificate-requests 409 evidence/managed-conflict.json fixtures/managed-conflict.json qa-managed-request-0001
```

首次申请保持 pending 可作为最后清点样本。独立实例导入和凭据创建不支持此类幂等缓存，
不要用盲目重试假设 token 可以找回。

**GRANT-02**：管理员删除运维的 view_requests、approve、revoke 授权，刷新授权页确认。
运维对 A 的申请详情变 404，审批和吊销均被拒绝；管理员恢复所需授权后重新验证。
根 CA 的委派必须拒绝，用户 A 不能获取运维授权。
证书总览分别用 pending/issued/rejected 过滤，和对应申请/证书详情一致。
`failed` 过滤无失败样本时可为空，不要求制造无对应功能的“手动重试”按钮。

**USER-02**：用 B 做禁用、密码重置与锁定验证，A 和管理员保持正常：

1. B 已登录时管理员在用户管理禁用 B，B 的旧页面/API 会话应失效，旧密码不能登录。
2. 管理员启用 B，B 重新登录成功；旧会话不会因为启用自动恢复。
3. 管理员重置 B 密码，旧会话和旧密码失效，新密码可登录。新密码仍用交互输入保存。
4. 等待同 IP 登录限流窗口过去，再对 B 输入错误密码 5 次，随后输入正确密码，
   预期 401 `account_locked` 且有 Retry-After。锁定期内重试不应延长锁定结束时间。
5. 停止重试，等待 15 分钟后，正确密码应成功；也可由管理员重置该普通账户密码恢复，
   但必须把“等待自然解锁”和“管理员重置恢复”分别记录，不能互相冒充。

账户锁定和每 IP 每分钟 10 次登录限流是两种结果；429 不是锁定正确的证据。
全过程不向管理员账户反复试错。浏览器与命令行会话是各自独立的，分别观察撤销结果。

**AUTH-03**：最后重新登录 A，退出终端会话并确认不可再用。浏览器也单独退出并验证刷新。

```bash
qa_login a qa-user-a
qa_http a POST /api/v1/auth/logout 204 evidence/logout.txt fixtures/empty.json
qa_http a GET /api/v1/auth/session 401 evidence/session-after-logout.json
qa_login a qa-user-a
```

会话超过配置的 idle/max 时限也应 401；需按真实时间等待并单独记录，不能改服务器时钟。

## 13. 审计、重启与部署可靠性

**AUDIT-01**：管理员打开“审计日志”，按时间查找本次登录、CA 创建/导入、授权、
模板修改、申请、审批/拒绝、签发、吊销、私钥领取/导出、独立签发/凭据撤销记录。
接口可读取最近事件，必要时分批保留，不假设一次 limit 能覆盖整轮全部操作。

```bash
qa_http admin GET '/api/v1/audit-events?limit=200' 200 evidence/audit.json
jq -e '.items | length>0' evidence/audit.json
```

核对 actor、action、resource、outcome、request_id 和实际操作；例如独立签发重放不能
多出一笔真正签发或多扣额度。不要要求每次被路由或认证前置拦截的坏请求都有业务审计事件。
审计 JSON、普通响应和服务日志不得出现私钥、原密码或 Bearer 明文；检查时不把搜索到的
敏感内容复制进报告。带盐密码摘要和 CSRF/Cookie 也不能当作公开验收附件。

**OPS-01**：运维在验收主机执行一次正常重启（独立终端，不在验收机混用服务配置）：

```bash
sudo systemctl restart pki-console
sudo systemctl status pki-console --no-pager
```

重新做 ready/version、CA 指纹、good/revoked 证书状态、CRL/OCSP、TSA 和独立历史查询。
数据和吊销结果应保留，后台无需第二个 worker 服务；相同环境密码不应因单纯重启重置账户。
root 会话若已超过时限，重新登录继续，不能把超时当作重启丢失数据。

**OPS-02**：在同一服务环境、运行账户下再执行一次 `pki-console migrate`，验证同基线
重复初始化不清空账户、会话、CA 或证书；比较前后指纹和 ID。首次空库安装已由第 1 节
覆盖。对于未知非空数据库，另建隔离空库后放一个测试表再运行初始化，应明确拒绝，
测试表仍保留；不要拿当前验收库做破坏性模拟。

**OPS-03**：按 [备份恢复指南](deployment-migration-export.md) 备份整个数据库和独立保管的
KEK，在另一隔离部署向空库恢复，不先建表。验证 CA 私钥仍能解密并签发新测试证书、
历史吊销/凭据撤销/已领取私钥状态保留、旧时间戳仍可验证。原部署和恢复副本不得同时
作为同一正式签发服务使用。恢复失败或没有实际恢复都不能标为备份恢复通过。

**OPS-04**：仅在验收部署安排故障注入：暂时中断其数据库连接，ready 应 503，
认证故障应呈现服务不可用而不是误报密码错误；签发与 TSA 不得在未持久化成功时
返回有效成功结果。恢复连接后重查既有申请和凭据额度再重试，不盲目创建新请求。
根据日志记录实际结果；不停止宿主机共享数据库、Nginx 或 NTP 来做试验。

## 14. 覆盖清单与当前边界

逐行签字。表中任一能力未执行或依赖失败，注明 BLOCKED/原因，不能写“全部通过”。
接口细节以 [OpenAPI](openapi.yaml) 和 [server.go](../../console/httpapi/server.go) 为准。

| 能力 / 对应路由组 | 用例 |
| --- | --- |
| 双站点、静态资源、health、version、未知 Host/路由 | ENV-01 |
| login/session/logout、三角色、Cookie/CSRF/Origin | AUTH-01/02/03 |
| 用户创建、禁用/启用、密码重置、锁定与解锁 | USER-01/02 |
| 根/中间创建、CA 列表/详情/证书/链与 key export | CA-WEB-01、KEY-02 |
| 根/中间导入、重复与错误材料拒绝 | CA-IMPORT-01/02/03 |
| profile 列表/创建/编辑/启停/删除/引用保护 | PROFILE-01/02 |
| grants 列表/授予/撤销、根禁止授权、自审批 | GRANT-01/02、ISSUE-03 |
| request 创建/列表/详情/批准/拒绝、后台签发 | ISSUE-01/02/03、IDEM-01 |
| inventory 筛选、certificate 列表/详情/下载、越权拒绝 | ISSUE-01/03、GRANT-02 |
| CSR 密钥匹配、服务器生成密钥/一次领取/超时 | CSR-01、KEY-01 |
| revoke、公开 CA、指纹/序列号精确查询、状态 | REVOKE-01、STATUS-01/02 |
| issuer DER、CRL 签名/范围/编号、OCSP POST/GET | STATUS-01/02、REVOKE-01 |
| 证书解析、4 种 CSR 生成、3 种链优化 | TOOL-01/02/03 |
| TSU 创建/列表、SHA-256/384/512、策略/篡改/协议拒绝 | TSA-01/02 |
| 独立实例创建/重复 CA/列表/详情/编辑/启停/所有者隔离 | IND-01/04 |
| 凭据创建/列表/一次展示/scope/额度/到期/撤销/附加策略 | IND-02/03/05/07 |
| 独立签发/重放/冲突/查询/客户端/列表分页与管理吊销 | IND-03/04/05/06 |
| 独立 issuer/CRL 作用域、系统数据与重复实例隔离 | IND-01/06 |
| 审计、metrics 权限、日志去敏 | AUDIT-01、AUTH-02 |
| 重启、初始化、备份恢复、数据库故障 | OPS-01/02/03/04 |

以下不属于当前可验收成功功能：标准 ACME、DNS/HTTP 域名控制权挑战、HSM/离线根、
CA/TSU 原地续期、CA 生命周期管理 API、独立实例删除/私钥导出/OCSP、历史叶证书及
吊销记录批量导入、批量重加密、后台任务手动重试按钮。不要按不存在的按钮设计通过标准。
长期等待与故障注入结果单列；本手册不构成吞吐压测或无漏洞保证。

## 15. 结果模板与材料归档

复制下面内容填写；每项引用实际记录，不只勾选功能名称：

```text
验收环境 / 两个 origin / 数据库基线：
源码提交 / 运行版本 / Go、OpenSSL、curl 版本：
执行人 / 起止时间 / 复核人：
测试 CA 的名称、UUID、SHA-256、算法与层级：

用例：
前置条件 / 使用角色 / 对象 ID：
操作、输入文件、幂等键（不含凭据）：
预期 HTTP/JSON/证书/吊销/界面结果：
实际结果 / PASS、FAIL 或 BLOCKED：
日志、截图、请求编号、DER/PEM/JSON 文件：
失败原因 / 修复提交 / 重测结果：

等待项：24 小时私钥过期、1 小时凭据过期、自然解锁、会话过期：
故障与恢复项：
最终结论 / 未通过或未执行项 / 是否具备发布条件：
```

仅归档经检查的 `evidence/`、公开证书、CRL/OCSP/时间戳响应和公开测试 CSR。
不要打包整个 `WORK`；`.secrets/` 中包含登录会话、CSRF、Bearer、导入请求中的私钥及
导出私钥，必须留在受限位置，按测试密钥保管规则处置。截图也避开一次性 token 弹框。
对外分发前复核响应头和 JSON，确认没有会话或敏感材料。
证据的校验和与验收记录一起保留；完成后由验收环境负责人销毁专用部署和测试密钥，
不是对共享环境执行清库命令。

命令依据：[OpenSSL verify](https://docs.openssl.org/3.0/man1/openssl-verify/)、
[OpenSSL OCSP](https://docs.openssl.org/3.0/man1/openssl-ocsp/)、
[OpenSSL 时间戳](https://docs.openssl.org/3.0/man1/openssl-ts/)。业务约束参见
[CA 导入](ca-import.md)、[独立签发](independent-signing.md)、[TSA](tsa.md)和
[认证](password-authentication.md)。

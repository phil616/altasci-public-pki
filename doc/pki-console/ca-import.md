# 导入已有根 CA 和中间 CA

状态：当前指南；核对日期：2026-11-16。

超级管理员可在“证书机构”页面点击“导入 CA”，上传或粘贴 PEM 证书和对应私钥。
仍可使用原有“创建 CA”功能生成新的机构。

首版 [初始化 SQL](../../console/store/schema.sql) 已包含 RSA-2048 CA、
不限路径深度（`path_length=-1`）及 CA 证书唯一索引，无需额外增量迁移。
新安装步骤见 [数据库初始化](schema-initialization.md)。

## Web 操作

1. 打开“证书机构”→“导入 CA”，选择“根 CA”或“中间 CA”。
2. 中间 CA 需先导入上级，并选择实际签发其证书的已有根或中间 CA。
3. 填写显示名称和唯一公开标识，上传或粘贴一张 PEM 格式的 CA 证书及其私钥。
4. 点击“验证并导入”。成功后可以查看证书、配置签发模板与授权，以及继续签发。

支持 RSA-2048、RSA-3072、RSA-4096、ECDSA-P256 和 ECDSA-P384。
私钥接受未加密的 PKCS#8 (`PRIVATE KEY`)、PKCS#1 (`RSA PRIVATE KEY`)、
SEC1 (`EC PRIVATE KEY`)。文件只在浏览器中读取，点击导入才提交；私钥不会写入
浏览器本地存储。加密 PEM、PFX/P12 和 DER 需先在本地转换为上述格式。
单个上传文件上限 256 KiB，API JSON 请求上限 1 MiB。

## 校验与保存

系统验证证书的 CA Basic Constraints、keyCertSign/cRLSign 用途、当前有效期、
Subject Key Identifier、证书与私钥匹配、算法及未知关键扩展。根 CA 必须具有有效
自签名；中间 CA 必须由选定上级签发，完整链需以自签名根结束，且不能超出任一
上级的路径长度约束。证书链校验使用 Go 的
[X.509 验证器](https://pkg.go.dev/crypto/x509#Certificate.Verify)。

原证书 DER、序列号、主题、有效期和路径约束保持原样，PEM 文本会规范化。
显示名称和本站公开标识独立于原证书 Subject。私钥转换为 PKCS#8 后使用现有
AES-256-GCM 信封加密；CA、密钥、默认签发模板和委托 OCSP 响应者在同一事务内保存。
导入接口在事务提交后尝试初始化本站 CRL；失败会记日志，CA 仍可返回 201，
应检查公开 CRL 地址（读取时也会按需刷新）。重复证书（即使标识不同）和重复公开标识均被拒绝。
导入成功与失败写入审计，响应、审计和幂等缓存不保存导入的私钥明文。

## 已有 CA 的迁移范围

此功能导入 CA 证书和私钥，不导入历史叶证书、审批、吊销记录、旧 CRL 编号或
原有 OCSP 响应者。本站签发与吊销服务以当前 PostgreSQL 中的记录为依据。
原证书中的 AIA、CRL Distribution Points 和 OCSP URL 不会改写。

目前没有历史签发/吊销状态批量导入接口。使用已有 CA 接管服务时，须另外完成这些
状态迁移并验证一致性，再接管旧发布地址；在完成
之前保持原发布服务可用，勿将本站新初始化的 CRL/OCSP 当作旧 CA 的完整状态。
仅更换显示名称或公开标识无法改变已签发证书中的 URL。

## API

```http
POST /api/v1/cas/import
Cookie: __Host-pki_session=<session>
X-CSRF-Token: <csrf>
Idempotency-Key: <unique-request-key>
Content-Type: application/json

{
  "kind": "root",
  "name": "Existing Root CA",
  "slug": "existing-root",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
}
```

中间 CA 使用 `kind=intermediate` 并提供 `parent_ca_id`。
成功返回 201，内容与其他 CA 查询接口相同，不含私钥。
无权限返回 403；重复证书或标识返回 409；证书、私钥和链校验失败返回 422。
支持现有 CSRF 和幂等机制，详见 [openapi.yaml](openapi.yaml)。

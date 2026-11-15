# PKI-Console 当前范围

状态：当前需求与实现边界；核对日期：2026-11-16。
原始 Cloudflare 版本需求完整保留在 [历史归档](doc/pki-console/archive/cloudflare-2026/original-requirements.md)。
旧要求由后续单机化、外部 PostgreSQL 和 CA 导入要求替代；本文与当前代码一并维护。

## 当前架构

基于 CFSSL Go 库直接实现业务，单个 `pki-console` 二进制内嵌前端、API、本地认证和
签发 worker，外部 Nginx 反代，外部 PostgreSQL 18+ 持久化，不依赖 Cloudflare 服务。
管理与公开服务通过两个域名隔离。生产使用 HTTPS、回环监听和明确的可信代理范围。

## 已实现

- 超级管理员、运维人员和普通用户统一采用本地用户名/邮箱和密码登录，保留会话与 CSRF。
- CA 新建与 PEM 根/中间 CA 导入，私钥信封加密，敏感导出确认当前管理员密码。
- 中间 CA 授权、签发模板、CSR 或服务器生成密钥申请、禁止自审批、后台签发、吊销。
- 证书库、PEM 链下载、服务器生成叶私钥 24 小时内一次性领取。
- 公开 CA 列表、叶证书精确查询、签发者证书、CRL、OCSP 和 RFC 3161 TSA。
- 独立 CSR 自动签发工具：用户自带 CA、凭据授权、显式白名单、幂等签发、独立证书与作用域 CRL；不采用 ACME 协议。
- 单一 SQL 初始化空库，不提供预发布数据库增量升级。
- 结构化日志、数据库审计、健康检查、受保护的 Prometheus 指标。

公开服务没有叶证书全量列表；精确查询仍含 owner/request UUID 元数据。
当前只暴露明确实现的 CFSSL 能力，不承诺全部 CLI 已映射为 API。
CA 为在线软件密钥模式，不含离线根、HSM 或仅证书托管。没有历史叶证书/吊销批量导入、
备份恢复 API、任务手动重试 API、密钥批量重加密或 CA/TSU 原地续期接口。

## 验收与维护

以 [当前文档入口](doc/pki-console/README.md)、[OpenAPI](doc/pki-console/openapi.yaml)
和同提交源码为依据，按 [发布指南](doc/pki-console/release.md) 执行质量、安全和隔离数据库测试。
带日期的安全报告记录当次结果，不构成无漏洞保证。文档更新、归档与检查规则见
[文档维护](doc/pki-console/documentation-maintenance.md)。

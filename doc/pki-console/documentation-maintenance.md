# 文档维护规范

状态：当前规范；核对日期：2026-11-17。文档与代码在同一次变更中更新和评审。
维护目标是可执行、可追溯，避免将设计愿望、历史现场和当前实现混在一起。

## 入口与状态

[README](README.md) 是应用文档入口，当前能力和边界在业务指南及
[人工验收手册](manual-acceptance.md) 中维护。
当前操作指南说明同提交实现，修改行为时更新其核对日期；日期不是线上状态证明。
安全报告、故障记录是带日期快照，保留原检查范围、结果和限制，不改写成持续有效的结论。
旧 Cloudflare 资料放入 [归档](archive/cloudflare-2026/README.md)，原入口保留跳转。
归档的版本、资源状态和旧命令不作为当前操作依据，正文不参加当前语义一致性检查。
原 CFSSL 包级文档仅描述对应工具/库，不等同于 Console 支持的接口和部署方式。

## 信息来源

| 文档信息 | 必须核对的源码或配置 |
| --- | --- |
| 工具链、依赖与构建命令 | [go.mod](../../go.mod)、[package.json](../../web/package.json)、锁文件、[Makefile](../../Makefile) |
| PR 检查、版本触发与发布附件 | [工作流](../../.github/workflows/pki-console.yml)、[打包脚本](../../.github/scripts/build-release.sh)、[发布脚本](../../.github/scripts/publish-release.sh) |
| 环境变量、默认值与约束 | [config.go](../../console/config/config.go)、[.env.example](../../.env.example) |
| 路由、认证、幂等与错误 | [server.go](../../console/httpapi/server.go)、同目录 handlers、[auth](../../console/auth/service.go) |
| JSON 返回字段 | [models.go](../../console/store/models.go) 和处理函数中的响应构造 |
| 初始数据结构和基线 | [schema.sql](../../console/store/schema.sql)、[migrate.go](../../console/store/migrate.go) |
| CA、签发与导入校验 | [service.go](../../console/pki/service.go)、[import.go](../../console/pki/import.go) |
| 独立签发策略、凭据与隔离 | [signing](../../console/signing)、[策略及接入](independent-signing.md) |
| TSA 与时钟 | [tsa](../../console/tsa) |
| 页面、开发代理、模拟测试 | [web](../../web)、[vite.config.ts](../../web/vite.config.ts)、[playwright.config.ts](../../web/playwright.config.ts) |
| 启动和代理示例 | [main.go](../../cmd/pki-console/main.go)、[systemd](pki-console.service)、[Nginx](nginx.conf.example) |

API 合约采用 [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.0.html)。示例统一使用
`pki-console.example.com` 和 `pki.example.com`，不写真实凭据或把示例部署写成当前线上事实。
依赖精确版本从源码/锁文件查询，不在多个指南中复制“最新版”和固定测试通过数量。
外部标准或兼容要求优先引用官方文档；涉及更改时重新核对，不将旧测试结果当作当前证据。

## 自动检查

文档工具需要 Python 3.10+，与运行时无关。使用独立虚拟环境：

```sh
python3 -m venv /tmp/pki-console-docs-venv
/tmp/pki-console-docs-venv/bin/python -m pip install -r scripts/requirements-docs.txt
make pki-console-docs PYTHON=/tmp/pki-console-docs-venv/bin/python
```

也可用 `uv venv` 和 `uv pip install --python ... -r ...`。依赖安装完成后，检查无需数据库、
应用密钥或网络。脚本拒绝重复 YAML key，验证 OpenAPI 格式与本地引用，并核对：

- Go 显式注册的管理/公开路由与 OpenAPI 方法、路径、域名，包括两端的存活检查。
- 会话、CSRF、独立 Bearer scope、幂等头及其必填标志是否与路由和处理函数一致。
- 已绑定的请求结构、存储模型和证书详情输出的 JSON 字段名称。
- 配置加载、环境示例、入口配置表中的变量集合。
- 当前 Markdown 和归档目录入口的行内本地链接、ATX 标题或显式 HTML id/name 锚点，
  以及正文中的 Console Make 目标。

当前检查不请求外部链接，不验证完整 Markdown 渲染、真实线上状态、JSON 字段类型/必填性/
验证边界、权限语义或示例命令的执行结果；归档正文不扫描。
路由和结构读取依赖当前 Go 声明形式，重构后需同步更新检查器及字段绑定。
新增 JSON 类型、响应构造方式或接口，评审时扩充映射，而不是删掉失败断言。

## 每次变更的复核

修改接口时同时更新 OpenAPI 的请求、响应、错误和权限说明；区分 HTTP 错误和
OCSP/TSA 协议内错误。修改 schema、密钥或部署流程时同时核对初始化、基线、备份与恢复限制。
检查命令应说明前提、环境和副作用，尤其是数据库集成测试会清空测试库。

运行文档检查及 [发布指南](release.md) 中与变更相关的应用验证。
数据库测试跳过、网络扫描失败和历史上游测试失败都需明确记录。
文档检查通过只能证明上述静态检查通过，仍需人工评审业务语义和实际部署验收。

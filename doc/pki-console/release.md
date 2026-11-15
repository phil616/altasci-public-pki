# 单体应用构建、检查与发布

状态：当前指南；核对日期：2026-11-15。目前没有 `.github/workflows`，没有自动发布
PKI-Console 的 GitHub Actions。根目录 Dockerfile、`.goreleaser.yml`、`make release`
和原 CFSSL 安装目标不构建或发布当前单体应用。

## 构建与检查

工具版本以 [go.mod](../../go.mod)、[package.json](../../web/package.json) 和锁文件为准。
`pki-console-check` 还使用 Python 3 执行随附客户端的状态恢复测试。
Make 默认使用 vendor 模式且关闭 GOPROXY，预先安装 Go 工具链；`npm ci` 仍需可用源或缓存。

```sh
make pki-console-check
make pki-console-e2e
make pki-console-security
make pki-console-docs PYTHON=/path/to/docs-venv/bin/python
make pki-console
sha256sum bin/pki-console > bin/pki-console.sha256
```

文档检查依赖安装见 [维护规范](documentation-maintenance.md)。安全检查需安装 `govulncheck`
（可通过 `GOVULNCHECK` 指定），其与 `npm audit` 需漏洞数据库网络。Playwright 使用已安装
Google Chrome，在浏览器边界模拟 API，不代替数据库测试。

未配置 `PKI_TEST_DATABASE_URL` 时数据库集成测试会跳过。按 [README](README.md) 使用
独立 PostgreSQL 18+ 测试库，记录实际执行结果，不能仅凭总体退出码声称数据库测试通过。
上游完整 `go test ./...` 的历史失败见 [安全检查快照](security-review-2026-11-14.md)，
当前结果需重新运行确认。

`make pki-console` 内嵌前端，生产只需二进制。交叉编译：
`make pki-console TARGETOS=linux TARGETARCH=arm64`。不要用未指定目标的 `make`
替代 Console 构建。正式环境及 TSA 使用 Linux。

## 依赖维护

版本以源码和锁文件为准，不维护永久有效的“最新版”声明。更新 Go 模块后运行
`make vendor`，会重新应用 [timestamp-oid.patch](../../vendor-patches/timestamp-oid.patch)
保留解析修复。Make 设置 `GOPROXY=off`，先准备模块缓存或显式指定组织允许的代理。
更新后重新执行应用检查、数据库集成、安全扫描和文档检查，评估弃用与行为变化。

## 交付与部署

记录提交号、平台、工具链、校验和和检查结果。版本默认来自
`git describe --tags --always --dirty`，可用 `PKI_CONSOLE_VERSION` 指定；上线后在
`/api/v1/version` 核对。发布标签本身不会触发自动构建。

交付二进制及对应文档、配置示例，环境密钥通过独立渠道配置。按
[部署指南](production-deployment.md) 备份、迁移、替换程序、重启和验收。
回退前核实 schema 与新数据兼容性，不能只恢复旧二进制。

Go 工具链升级后，漏洞扫描器也需使用能解析对应 Go 语法的版本；用 `go version -m`
核对扫描器构建信息。解析失败不是扫描通过，必要时更新扫描工具并重新运行。

# 单体应用构建、检查与发布

状态：当前指南；核对日期：2026-11-15。[GitHub Actions 工作流](../../.github/workflows/pki-console.yml)
支持 PR 精简测试和版本 tag 自动发布 PKI-Console 单体应用。
根目录 Dockerfile、`.goreleaser.yml`、`make release` 和原 CFSSL 安装目标不构建或发布当前单体应用。

## GitHub 自动测试与发布

工作流面向 GitHub.com，运行于 `ubuntu-24.04`，使用 `go.mod` 的 Go 工具链、Node.js 24、
`web/package.json` 声明的 npm 版本及已提交的 vendor/锁文件。
`pull_request` 对合并引用执行一个 `Lightweight checks` job：

- 前端：`npm ci --no-audit --no-fund`、`npm test`、`npm run build`，构建包含 TypeScript 类型检查。
- Go：`go test -p 1 ./console/... ./cmd/pki-console ./web`。
- Python：`python3 -B -m unittest discover -s scripts -p test_signing_client.py`。

PR 更新会取消同一 PR 的旧运行。PR 不发布，不使用发布凭证；默认 token 仅有 `contents: read`。
为了控制耗时，自动检查不启动 PostgreSQL 或 Playwright，不额外执行 race、独立 lint/vet、
漏洞数据库扫描或文档检查；未配置数据库的集成测试会跳过。它不替代下述完整检查和上线验收。

推送 `vMAJOR.MINOR.PATCH` tag（例如 `v1.2.3`）或预发布 tag（例如 `v1.2.3-rc.1`）后，
先执行同样的检查，再使用 [打包脚本](../../.github/scripts/build-release.sh) 构建两种 Linux 架构。
版本号和纯数字预发布段不接受前导零，不支持 `+build` 元数据；其他以 `v` 开头的 tag 会在打包时失败。
tag 指向的提交必须包含本工作流；发布过程不自动创建 tag。

```sh
# 在已提交且核验过的版本提交上执行；将版本替换为本次实际版本。
git tag -a v1.2.3 -m 'Release v1.2.3'
git push origin refs/tags/v1.2.3
```

每个版本提供三个 Release 附件：

| 附件 | 内容 |
| --- | --- |
| `pki-console-v1.2.3-linux-amd64.tar.gz` | Linux amd64 静态 Go 二进制及部署示例 |
| `pki-console-v1.2.3-linux-arm64.tar.gz` | Linux arm64 静态 Go 二进制及部署示例 |
| `SHA256SUMS` | 两个压缩包的 SHA-256 校验和 |

压缩包包含 `pki-console`（已内嵌前端）、`LICENSE`、`.env.example`、`pki-console.service`、
`nginx.conf.example` 和 `signing-client.py`。部署只运行一个应用程序，仍需外部 PostgreSQL 和 Nginx；
部署前修改示例配置并准备运行密钥。核对校验和后解压对应架构：

```sh
# 将两个压缩包和 SHA256SUMS 下载到同一目录。
sha256sum -c SHA256SUMS
tar -xzf pki-console-v1.2.3-linux-amd64.tar.gz
```

构建 job 仅有读权限，通过同一次运行的 Actions artifact 传递产物。
只有 `Publish release` job 获得 `contents: write`，使用自动提供的 `GITHUB_TOKEN`，不需要额外 PAT。
[发布脚本](../../.github/scripts/publish-release.sh) 核对附件清单和远端 tag 对应的提交，
先创建 draft 并上传全部附件，核对服务器上的文件名、大小及可用的 SHA-256，再正式发布。
正式版标记为 Latest，预发布标记为 prerelease 且不设为 Latest；发布说明由 GitHub 自动生成。
校验和用于校验文件完整性，此流程未生成独立的构建来源证明。

tag 运行不会互相取消。测试或构建失败不会发布；可以修复代码并使用新 tag。
发布中断可能留下 draft，重跑遇到已有 Release/draft 会停止，避免覆盖已发布附件。
先用 `gh release view TAG --repo OWNER/REPO --json isDraft,assets,url` 核对状态；
只有确认仍为 draft、源提交及附件完整性均正确后，才可补传缺失文件并手动发布。
已经发布的版本用新 tag 修正，不移动旧 tag 或覆盖附件。
分支保护可将 `Lightweight checks` 设为必需检查；tag 创建权限、rulesets 和不可变 Release 设置需在仓库中配置，
工作流文件不会自动启用这些仓库设置。

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
`/api/v1/version` 核对。自动发布将触发 tag 原样写入此版本字段。

交付二进制及对应文档、配置示例，环境密钥通过独立渠道配置。按
[部署指南](production-deployment.md) 备份、迁移、替换程序、重启和验收。
回退前核实 schema 与新数据兼容性，不能只恢复旧二进制。

Go 工具链升级后，漏洞扫描器也需使用能解析对应 Go 语法的版本；用 `go version -m`
核对扫描器构建信息。解析失败不是扫描通过，必要时更新扫描工具并重新运行。

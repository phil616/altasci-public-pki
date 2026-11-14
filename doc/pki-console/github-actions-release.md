> 历史文档：本文中的 Cloudflare / Pages / Access / Tunnel 部署步骤适用于旧版本。
> 当前单体应用使用本地密码/TOTP、外部 PostgreSQL 和 Nginx，部署与迁移以
> [production-deployment.md](production-deployment.md) 为准；Web 业务流程与数据库操作请结合当前版本核对。

# GitHub Actions 自动发布与 Cloudflare Pages 部署

该方案在 GitHub 收到 `v*` tag 时执行一次受控发布：测试项目、构建 Linux 后端二进制、用 Wrangler 部署 React 和 Pages Functions，并在部署成功后创建 GitHub Release。

工作流文件位于 `.github/workflows/release.yaml`。

这是仓库唯一保留的 workflow。不构建或发布 Docker 镜像，不运行上游 CFSSL 的旧版数据库矩阵、快照和 Cloudflare 内部 Semgrep 流程。

## 发布边界

GitHub Release 的附件只有：

- `pki-console_<version>_linux_amd64`
- `pki-console_<version>_linux_arm64`
- `SHA256SUMS`

前端 `dist` 不会上传到 GitHub Release，也不会保存为 Actions Artifact。GitHub 会在 Release 页面自动提供 tag 对应的源码归档，这不是工作流上传的附件。

预发布 tag，例如 `v1.2.3-rc.1`，会创建 prerelease；普通 `v1.2.3` 创建正式 release。

## Pages Functions 是否会失效

`wrangler pages deploy` 不会导致 Pages Functions 失效，但必须同时满足：

1. 命令从 Pages 项目根目录 `web` 执行。
2. Function 位于 `web/functions/`，而不是 `web/dist/functions/`。
3. 使用 `wrangler pages deploy dist`，不能使用 Dashboard 拖拽上传。
4. `_routes.json` 位于构建输出 `web/dist`，用于限制仅 API 路径调用 Function。

工作流通过 `working-directory: web` 固化了该目录边界。Wrangler 会读取同级 `functions/`，编译后与 `dist` 静态资源一起创建一个 Pages deployment。

## GitHub 仓库配置

在仓库 **Settings > Actions > General** 中启用 Actions，并允许使用 GitHub 官方 `actions/*` Actions。工作流只申请：

```yaml
permissions:
  contents: write
```

该权限允许内置 `${{ github.token }}` 读取仓库并创建 Release，不需要额外创建 GitHub PAT。工作流中的官方 Actions 均固定到经过核对的完整 commit SHA，行尾注释保留对应版本号，便于 Dependabot 更新。

在 **Settings > Secrets and variables > Actions > Variables** 添加：

| Variable | 示例 | 说明 |
| --- | --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare Account ID | 非 API Token |
| `CLOUDFLARE_PAGES_PROJECT` | `pki-web` | 已创建的 Pages 项目名称 |

在 **Settings > Secrets and variables > Actions > Secrets** 添加：

| Secret | 说明 |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | Cloudflare Custom API Token，仅授予 `Account / Cloudflare Pages / Edit` |

不要把 `PKI_ORIGIN_SHARED_SECRET` 放入 GitHub。它是 Pages Function 的运行时 Secret，应继续在 Cloudflare Pages 的 **Settings > Variables and Secrets** 中加密保存。

## Cloudflare Pages 配置

Pages 项目应预先创建，并将 production branch 配置为 `main`。工作流不会自动创建项目，以避免 tag 发布时误建同名项目。

`web/wrangler.jsonc` 是 Pages 非敏感配置的 source of truth，并声明以下 Function bindings：

| 名称 | 类型 |
| --- | --- |
| `PKI_ORIGIN_URL` | 普通变量 |
| `PKI_PUBLIC_HOST` | 普通变量 |
| `PKI_CONSOLE_HOST` | 普通变量 |
| `PKI_ORIGIN_SHARED_SECRET` | 加密 Secret，仅在 Cloudflare 保存 |

普通变量、兼容日期和 `pages_build_output_dir` 随 Git 版本维护。`PKI_ORIGIN_SHARED_SECRET` 不进入配置文件；首次部署和轮换时使用 `wrangler pages secret put PKI_ORIGIN_SHARED_SECRET --project-name pki-web` 写入。

## 执行顺序与失败行为

一次 tag 发布按以下顺序执行：

1. 运行 Go tests、Go vet、前端 lint、TypeScript、Vitest、Vite build 和 Pages Function build。
2. 构建 `linux/amd64`、`linux/arm64` 后端并生成校验和。
3. 从 `web` 目录执行 Wrangler production deployment。
4. Pages 成功后创建 GitHub Release 并上传后端附件。

如果测试、构建或 Pages 发布失败，GitHub Release 不会被创建。已经存在同名 Release 时，workflow 会失败且不会覆盖已有附件。

工作流对同一 tag 使用 `concurrency`，不会取消正在进行的发布，并设置 45 分钟超时。

## 发布 tag

建议配置 tag protection 或 Repository Ruleset，仅允许发布负责人创建 `v*` tag。发布示例：

```sh
git switch main
git pull --ff-only
git tag -s v1.0.0 -m 'PKI-Console v1.0.0'
git push origin v1.0.0
```

`gh release create --verify-tag` 只验证远端 tag 已存在，不校验 GPG 签名。需要强制签名时，应增加组织规则或单独的可信公钥验证步骤。

## 本地验证

```sh
go test ./console/... ./cmd/pki-console
go vet ./console/... ./cmd/pki-console

cd web
npm ci --no-audit --no-fund
npm run check
```

`npm run check` 已包含 Wrangler Pages Function 编译。需要连同静态页面本地运行时：

```sh
cd web
npm run build
npm run pages:dev
```

本地运行时变量放入未提交的 `web/.dev.vars`，不要复制生产 Secret。

## 官方参考

- [GitHub Actions workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub CLI release create](https://cli.github.com/manual/gh_release_create)
- [Cloudflare Pages Direct Upload](https://developers.cloudflare.com/pages/get-started/direct-upload/)
- [Cloudflare Pages CI with Wrangler](https://developers.cloudflare.com/pages/how-to/use-direct-upload-with-continuous-integration/)
- [Cloudflare Pages Functions deployment](https://developers.cloudflare.com/pages/functions/get-started/)

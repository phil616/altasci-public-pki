# GitHub Actions 自动发布与 Cloudflare Pages 部署

该方案在 GitHub 收到 `v*` SemVer tag 时执行一次受控发布：测试完整项目、构建 Linux 后端二进制、创建 GitHub Release，并用 Wrangler 把 React 静态文件和 Pages Functions 一起部署到 Cloudflare Pages。

工作流文件位于 `.github/workflows/release.yaml`。

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
| `CLOUDFLARE_PAGES_PROJECT` | `pki-console` | 已创建的 Pages 项目名称 |
| `CLOUDFLARE_PAGES_PRODUCTION_BRANCH` | `main` | 必须与 Pages production branch 一致 |

在 **Settings > Secrets and variables > Actions > Secrets** 添加：

| Secret | 说明 |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | Cloudflare Custom API Token，仅授予 `Account / Cloudflare Pages / Edit` |

不要把 `PKI_ORIGIN_SHARED_SECRET` 放入 GitHub。它是 Pages Function 的运行时 Secret，应继续在 Cloudflare Pages 的 **Settings > Variables and Secrets** 中加密保存。

## Cloudflare Pages 配置

Pages 项目应预先创建，production branch 与 `CLOUDFLARE_PAGES_PRODUCTION_BRANCH` 一致。工作流不会自动创建项目，以避免 tag 发布时误建同名项目。

Production 环境必须已有这些 Function bindings：

| 名称 | 类型 |
| --- | --- |
| `PKI_ORIGIN_URL` | 普通变量 |
| `PKI_PUBLIC_HOST` | 普通变量 |
| `PKI_CONSOLE_HOST` | 普通变量 |
| `PKI_ORIGIN_SHARED_SECRET` | 加密 Secret |

当前仓库没有提交 `wrangler.jsonc`，因此 Dashboard 继续管理 Pages 运行时变量和 Secret。Wrangler tag 部署只更新静态资源与 Function 代码。

如果以后运行 `wrangler pages download config` 并提交含 `pages_build_output_dir` 的配置，该文件会成为 Pages 配置的 source of truth；提交前必须确认 production/preview bindings 完整，避免覆盖 Dashboard 配置。

## 执行顺序与失败行为

一次 tag 发布按以下顺序执行：

1. 校验 tag 是 `v1.2.3` 风格的 SemVer，且 tagged commit 位于配置的 production branch 历史中。
2. 运行 Go tests、Go vet、前端 lint、TypeScript、Vitest、Vite build 和 Pages Function build。
3. 构建 `linux/amd64`、`linux/arm64` 后端并生成校验和。
4. 创建 GitHub draft release 并上传后端附件。
5. 从 `web` 目录执行 Wrangler production deployment。
6. Pages 成功后才把 GitHub Release 从 draft 改为 published。

如果 Pages 发布失败，Release 会保持 draft。重新运行同一个 workflow 时会复用该 draft，并使用 `--clobber` 替换同名附件；已经发布的 Release 不允许被自动覆盖。

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

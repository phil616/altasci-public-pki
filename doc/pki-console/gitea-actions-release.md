# Gitea Actions 自动发布与 Cloudflare Pages 部署

该方案在推送 `v*` SemVer tag 时执行一次受控发布：测试完整项目、构建 Linux 后端二进制、创建 Gitea Release，并用 Wrangler 把 React 静态文件和 Pages Functions 一起部署到 Cloudflare Pages。

工作流文件位于 `.gitea/workflows/release.yaml`。

## 是否可行

可行。Gitea Actions 与 GitHub Actions 工作流大体兼容，并提供内置 `GITEA_TOKEN` 调用当前仓库的 Release API。Cloudflare Pages 支持从任意 CI 使用 Wrangler Direct Upload，因此不要求源码位于 GitHub 或 GitLab。

`wrangler pages deploy` **不会导致 Pages Functions 失效**，但必须同时满足：

1. 命令从 Pages 项目根目录 `web` 执行。
2. Function 位于 `web/functions/`，而不是 `web/dist/functions/`。
3. 使用 `wrangler pages deploy dist`，不能使用 Dashboard 拖拽上传。
4. `_routes.json` 位于构建输出 `web/dist`，用于限制仅 API 路径调用 Function。

当前工作流通过 `working-directory: web` 固化了这个目录边界。Wrangler 会读取同级的 `functions/`，编译后与 `dist` 静态资源一起创建同一个 Pages deployment。

## 发布产物

Gitea Release 的附件只有：

- `pki-console_<version>_linux_amd64`
- `pki-console_<version>_linux_arm64`
- `SHA256SUMS`

前端 `dist` 不会上传到 Gitea Release，也不会作为 Actions Artifact 保存。Gitea 自己可能在 Release 页面显示 tag 对应的源码归档，这不是工作流上传的附件。

预发布 tag，例如 `v1.2.3-rc.1`，会创建 prerelease；普通 `v1.2.3` 创建正式 release。

## Gitea 仓库配置

进入仓库 **Settings > Actions**，启用 Actions，并确保 job token 最大权限允许：

- Code：Read
- Releases：Write

工作流使用 Gitea 自动提供的 `${{ secrets.GITEA_TOKEN }}`，不需要额外创建 Gitea PAT。若实例版本较旧、不支持 job token 的 Release 写权限，应优先升级 Gitea；确需兼容旧版时再使用仅限当前仓库 Release 权限的 PAT。

在 **Settings > Actions > Variables** 添加：

| Variable | 示例 | 说明 |
| --- | --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare Account ID | 非 API Token |
| `CLOUDFLARE_PAGES_PROJECT` | `pki-console` | 已经创建的 Pages 项目名称 |
| `CLOUDFLARE_PAGES_PRODUCTION_BRANCH` | `main` | 必须与 Pages 项目的 production branch 一致 |

在 **Settings > Actions > Secrets** 添加：

| Secret | 说明 |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | Cloudflare Custom API Token，仅授予 `Account / Cloudflare Pages / Edit` |

不要把 `PKI_ORIGIN_SHARED_SECRET` 放入 Gitea。它是 Pages Function 的运行时 Secret，应继续在 Cloudflare Pages 的 **Settings > Variables and Secrets** 中加密保存。

## Cloudflare Pages 配置

Pages 项目应预先创建，生产分支与 `CLOUDFLARE_PAGES_PRODUCTION_BRANCH` 一致。工作流不会自动创建项目，以避免 tag 发布时进入交互流程或误建同名项目。

Production 环境必须已有这些 Function bindings：

| 名称 | 类型 |
| --- | --- |
| `PKI_ORIGIN_URL` | 普通变量 |
| `PKI_PUBLIC_HOST` | 普通变量 |
| `PKI_CONSOLE_HOST` | 普通变量 |
| `PKI_ORIGIN_SHARED_SECRET` | 加密 Secret |

当前仓库没有提交 `wrangler.jsonc`，因此 Dashboard 是 Pages 运行时变量和 Function compatibility date 的配置源。Wrangler tag 部署只更新静态资源与 Function 代码，不会把这些 Secret 写入仓库。

如果以后运行 `wrangler pages download config` 并提交含 `pages_build_output_dir` 的配置，该文件会成为 Pages 配置的 source of truth；提交前必须确认 production/preview bindings 完整，避免覆盖 Dashboard 配置。

## Runner 要求

工作流使用 `runs-on: ubuntu-latest`。对应 runner 环境需要：

- 能执行 Bash，并包含 Git、curl、jq、sha256sum。
- 能访问 Gitea API、Cloudflare API、GitHub Actions 源和 Go/Node 工具链下载地址。
- 支持 `actions/checkout@v4`、`actions/setup-go@v5` 和 `actions/setup-node@v4`。
- 至少具备 Go 构建、Node 安装和两个静态交叉编译所需的内存与磁盘。

Go 依赖使用已提交的 `vendor`，工作流设置 `GOPROXY=off`。npm 和 Wrangler 使用 `web/package-lock.json` 中的精确版本与 integrity 校验。

若 runner 不能访问 GitHub，请把所用 actions 镜像到自己的 Gitea，并在 workflow 中使用完整的 Gitea action URL，或配置实例的 `DEFAULT_ACTIONS_URL`。

## 执行顺序与失败行为

一次 tag 发布按以下顺序执行：

1. 校验 tag 是 `v1.2.3` 风格的 SemVer，且 tagged commit 位于配置的生产分支历史中。
2. 运行 Go tests、Go vet、前端 lint、TypeScript、Vitest、Vite build 和 Pages Function build。
3. 构建 `linux/amd64`、`linux/arm64` 后端并生成校验和。
4. 创建 Gitea draft release 并上传后端附件。
5. 从 `web` 目录执行 Wrangler production deployment。
6. Pages 成功后才把 Gitea release 从 draft 改为 published。

如果 Pages 发布失败，Release 会保持 draft，不会向使用者宣告一个不完整版本。重新运行同一个 workflow 时会复用该 draft，清理旧附件并重新上传；已经发布的 release 不允许被自动覆盖。

工作流同时兼容部分旧版 Gitea 的差异：如果按 tag 查询不到草稿，会再通过带写权限的 Release 列表查找同名 draft，避免重跑时误建重复 Release。

部分 Gitea 版本会忽略 Actions 的 `concurrency`，因此工作流没有依赖该功能。不要同时推送多个生产 tag；等待前一个 tag 工作流完成后再推送下一个。

## 发布 tag

建议保护 `v*` tag，并只允许发布负责人创建。发布示例：

```sh
git switch main
git pull --ff-only
git tag -s v1.0.0 -m 'PKI-Console v1.0.0'
git push gitea v1.0.0
```

工作流要求 tag 指向 production branch 历史中的 commit，但当前不会自动校验 GPG 签名。需要强制签名时，应在 runner 安装受信任发布公钥，并增加 `git verify-tag "$GITHUB_REF_NAME"`。

## 本地验证 Pages Functions

```sh
cd web
npm ci --no-audit --no-fund
npm run check
```

`npm run check` 已包含 `wrangler pages functions build`，因此 Function 的编译错误会在 tag 发布前被发现。需要连同静态页面本地运行时：

```sh
cd web
npm run build
npm run pages:dev
```

本地运行时变量放入未提交的 `web/.dev.vars`，不要复制生产 Secret。

## 官方参考

- [Gitea Actions](https://docs.gitea.com/usage/actions/)
- [Gitea Actions variables](https://docs.gitea.com/usage/actions/actions-variables/)
- [Gitea job token permissions](https://docs.gitea.com/usage/actions/token-permissions/)
- [Gitea Create Release API](https://docs.gitea.com/api/operations/repo-create-release/)
- [Gitea Release attachment API](https://docs.gitea.com/api/operations/repo-create-release-attachment/)
- [Cloudflare Pages Direct Upload](https://developers.cloudflare.com/pages/get-started/direct-upload/)
- [Cloudflare Pages CI with Wrangler](https://developers.cloudflare.com/pages/how-to/use-direct-upload-with-continuous-integration/)
- [Cloudflare Pages Functions deployment](https://developers.cloudflare.com/pages/functions/get-started/)

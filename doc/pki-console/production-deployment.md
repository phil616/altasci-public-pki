# 单机部署：单体程序 + Nginx + PostgreSQL

状态：当前指南；核对日期：2026-11-16。示例域名和路径需按实际环境替换。

当前部署只运行一个 `pki-console` 程序，前端、API、认证和签发任务都在其中。
外部 PostgreSQL 18+ 提供存储，Nginx 终止 HTTPS 并反代同机回环端口。
不再配置 Cloudflare Pages、Functions、Access、Tunnel 或 origin 共享密钥。

## 1. 准备与构建

准备两个指向 Nginx 的域名，例如管理端 `pki-console.example.com`、公开端
`pki.example.com`，以及相应的 HTTPS 证书。继续使用原有发布域名可保持已有证书中的
AIA、CRL、OCSP 地址可用。应用端口无需对外开放。

生产主机使用 Linux，TSA 的内核时钟健康检查仅在 Linux 实现。
数据库要求 PostgreSQL 18+（当前 schema 使用 `uuidv7()`），编码使用 UTF-8。
使用现有平台创建专用空数据库和独立角色，确保 `public` 为空，
让该角色拥有应用 schema 的建表、函数与分区权限。
当前审计写入会创建月分区；备份和恢复应包含这些对象。

构建机安装 `go.mod` 指定的 Go 工具链，以及 Node.js 24 / `web/package.json` 指定的 npm：

```sh
make pki-console
# 前端会先构建并嵌入该二进制。
# 交叉编译示例：make pki-console TARGETOS=linux TARGETARCH=arm64
install -o root -g root -m 0755 bin/pki-console /usr/local/bin/pki-console
```

也可下载正式发行包，按包内 `README.md` 安装。发行包附带 SQL 和部署模板，
无需在生产主机编译。运行时不必复制 `web/dist`。不含前端的手工构建在 `serve` 启动时会报出
重新构建提示。生产机无需 Node.js、npm 或独立静态文件服务器。

## 2. 配置本地认证和数据库

```sh
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin pki-console
sudo install -d -o root -g pki-console -m 0750 /etc/pki-console
sudo install -o root -g pki-console -m 0640 .env.example /etc/pki-console/pki-console.env
```

编辑环境文件，填入数据库 URL、两个 origin、超级管理员凭据和加密密钥。
远程 PostgreSQL 必须显式使用 `sslmode=verify-full`；需要私有 CA 时在 URL 配置 `sslrootcert`，并确保服务账户能读取。
生产监听保持 `127.0.0.1:8080`，可信代理设置为同机 Nginx 的回环 CIDR。
所有配置说明见 [README.md](README.md)。

仅在首次新建部署时生成凭据；已有部署必须保留原 `PKI_MASTER_KEYS` 和 active ID，
避免失去现有密钥解密能力。生成命令：

```sh
# ROOT_USER_PASSWORD
openssl rand -hex 32
# PKI_MASTER_KEYS 中的每个值
openssl rand -base64 32
```

所有角色均使用本地用户名/邮箱和密码登录。超级管理员使用环境文件中的邮箱和密码。
账户初始化与客户端请求示例见 [密码认证](password-authentication.md)。

## 3. 初始化与 systemd

环境示例使用单引号保存字面量；下面通过 shell 加载，避免在值中引入 shell 展开语法。

```sh
sudo -u pki-console env -i sh -c 'set -a; . /etc/pki-console/pki-console.env; exec /usr/local/bin/pki-console migrate'
sudo install -o root -g root -m 0644 doc/pki-console/pki-console.service /etc/systemd/system/pki-console.service
sudo systemctl daemon-reload
sudo systemctl enable --now pki-console
sudo systemctl status pki-console --no-pager
```

初始化是独立命令，不在 `serve` 启动时自动执行。唯一 SQL 为
[schema.sql](../../console/store/schema.sql)，只面向空库；重复执行应用命令不会重置数据。
事务、基线检查和手动 SQL 方式见 [数据库初始化](schema-initialization.md)。`serve` 自带签发 worker，无需另外安装
worker 服务。TSA 继续要求 Linux 系统时间同步；生产模式下 NTP 未同步或误差过大会拒绝签发时间戳。
额外的 `worker` 进程不再同步 root 凭据，避免其环境覆盖管理服务的身份配置。
登录故障按 [密码认证](password-authentication.md) 检查运行进程的实际环境和锁定状态。

## 4. Nginx

将 [nginx.conf.example](nginx.conf.example) 放入 Nginx 的 `http {}` 配置上下文，
替换两个域名和证书路径。所有路径（包括前端、API、CRL、OCSP、TSA）都转发到同一个
`http://127.0.0.1:8080`，不需要配置 `root`、`try_files` 或独立前端服务。
现有 Nginx 已有默认站点时，可将示例的两个 HTTPS location 合入相应站点。

关键代理配置：

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host $host; # 保留请求的业务域名
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_cache off;
}
```

`Host` 必须对应当前站点的配置域名，否则应用返回 421。此处直接覆盖 `X-Forwarded-For`，
防止客户端自带地址影响登录限流和审计。若 Nginx 前面还有代理，应先在 Nginx 正确配置真实
IP 信任边界，再将处理后的 `$remote_addr` 转发。
Nginx 的代理头语法参见[官方文档](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)。

```sh
sudo nginx -t
sudo systemctl reload nginx
```

## 5. 验证

```sh
# 本机直连不需要共享密钥或任何 Cloudflare 头。
curl --fail -H 'Host: pki-console.example.com' http://127.0.0.1:8080/api/v1/health/ready
curl --fail -H 'Host: pki.example.com' http://127.0.0.1:8080/health/live
# 经 Nginx 检查两端页面和服务。
curl --fail https://pki-console.example.com/login
curl --fail https://pki.example.com/pki/v1/authorities
```

浏览器打开管理域名，输入用户名/邮箱和密码。验证登录、会话、
CA 列表和普通账户权限；到公开域名检查 CA、证书精确查询、CRL/OCSP/TSA。
使用当前管理员密码测试私钥导出。

管理域名的 `/api/v1/auth/session` 在未登录时返回 401；公开域名同一路径返回 404。
错误 Host 返回 421；缺失的 `/assets/*.js` 或 API 路径返回 404，不返回首页 HTML。
静态哈希资源长缓存，HTML 重新验证，API 响应继续保留自身缓存策略。

## 6. 首版数据库基线

首个正式版只支持新建空库初始化，或恢复同一基线的完整备份。
预发布编号迁移不再提供，旧 Cloudflare 部署或其他预发布数据库不能原地执行初始化。
命令会拒绝没有本基线标记的非空 `public`，不会删除旧表或转换旧数据。
需要保留旧数据时先备份，并单独制定导入或迁移方案，不要手工补写基线标记。

同一正式版更换主机时，恢复完整数据库与全部 KEK，保留证书的 AIA/CRL/OCSP 发布域名。
完整恢复前不要运行建表 SQL；回退需要匹配的数据库备份、二进制和配置。
具体见 [备份与恢复](deployment-migration-export.md)。

## 7. 备份与排障

备份至少包含 PostgreSQL 完整备份和独立加密保管的 KEK/配置；丢失 KEK 无法解密已有私钥。
更新前先验证数据库基线与备份，在同一服务中替换二进制即可更新前后端。查看日志：

```sh
sudo journalctl -u pki-console -n 100 --no-pager
```

| 现象 | 检查 |
| --- | --- |
| Nginx 502 | 程序状态、127.0.0.1:8080、本机 health |
| 421 | Nginx Host 与两个 BASE_URL 的域名是否一致 |
| 登录 401 | 核对用户名、密码、锁定和 login denied 日志中的 stage；account_locked 按 Retry-After 等待 |
| 写请求 401 | Cookie、会话是否过期；HTTPS 是否正确 |
| 写请求 403 csrf_failed | CSRF token 是否与当前会话匹配 |
| 登录/会话 503 authentication_unavailable | 数据库连通性、schema 初始化、进程环境与服务日志 |
| 页面脚本加载失败 | 是否用 `make pki-console` 重新构建并部署完整二进制 |
| 无法解密密钥 | 旧 KEK 是否完整保留，active ID 是否有效 |
| TSA 拒绝签发 | 系统 NTP 状态与内核时钟不确定度 |

日常运维见 [operations-runbook.md](operations-runbook.md)，备份、隔离恢复和导出见
[deployment-migration-export.md](deployment-migration-export.md)。

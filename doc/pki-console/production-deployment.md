# 单机部署：单体程序 + Nginx + PostgreSQL

状态：当前指南；核对日期：2026-11-15。示例域名和路径需按实际环境替换。

当前部署只运行一个 `pki-console` 程序，前端、API、认证和签发任务都在其中。
外部 PostgreSQL 18+ 提供存储，Nginx 终止 HTTPS 并反代同机回环端口。
不再配置 Cloudflare Pages、Functions、Access、Tunnel 或 origin 共享密钥。

## 1. 准备与构建

准备两个指向 Nginx 的域名，例如管理端 `pki-console.example.com`、公开端
`pki.example.com`，以及相应的 HTTPS 证书。继续使用原有发布域名可保持已有证书中的
AIA、CRL、OCSP 地址可用。应用端口无需对外开放。

生产主机使用 Linux，TSA 的内核时钟健康检查仅在 Linux 实现。
数据库要求 PostgreSQL 18+（当前 schema 使用 `uuidv7()`），编码使用 UTF-8。
使用现有平台创建数据库和独立角色，让该角色拥有应用 schema 的建表、函数与分区权限。
当前审计写入会创建月分区；备份和恢复应包含这些对象。

构建机安装 `go.mod` 指定的 Go 工具链，以及 Node.js 20.19+ / npm：

```sh
make pki-console
# 前端会先构建并嵌入该二进制。
# 交叉编译示例：make pki-console TARGETOS=linux TARGETARCH=arm64
install -o root -g root -m 0755 bin/pki-console /usr/local/bin/pki-console
```

生成后只分发二进制，不必复制 `web/dist`。不含前端的手工构建在 `serve` 启动时会报出
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

仅在首次新建部署时生成凭据；已有部署必须保留原 `PKI_MASTER_KEYS`、active ID 和
TOTP secret，避免失去现有密钥解密能力或需要重新绑定验证器。生成命令：

```sh
# ROOT_USER_PASSWORD
openssl rand -hex 32
# PKI_MASTER_KEYS 中的每个值
openssl rand -base64 32
# ROOT_USER_TOTP_SECRET
python3 -c 'import base64,secrets; print(base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="))'
```

在兼容的验证器中添加 TOTP：算法 **SHA-256**、6 位、周期 30 秒（不是常见的 SHA-1 默认值）。
超级管理员用环境文件中的邮箱、密码和动态验证码登录。普通用户和运维账户继续使用
原本的本地用户名/邮箱和密码，无需外部身份提供方。

## 3. 迁移与 systemd

```sh
sudo -u pki-console env -i sh -c 'set -a; . /etc/pki-console/pki-console.env; exec /usr/local/bin/pki-console migrate'
sudo install -o root -g root -m 0644 doc/pki-console/pki-console.service /etc/systemd/system/pki-console.service
sudo systemctl daemon-reload
sudo systemctl enable --now pki-console
sudo systemctl status pki-console --no-pager
```

迁移是独立命令，不在 `serve` 启动时自动执行。`serve` 自带签发 worker，无需另外安装
worker 服务。TSA 继续要求 Linux 系统时间同步；生产模式下 NTP 未同步或误差过大会拒绝签发时间戳。

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

浏览器打开管理域名，勾选超级管理员，输入邮箱、密码和 TOTP。验证登录、会话、
CA 列表和普通账户权限；到公开域名检查 CA、证书精确查询、CRL/OCSP/TSA。
使用一个新验证码测试私钥导出；登录时用过的验证码不能再次用于导出。

管理域名的 `/api/v1/auth/session` 在未登录时返回 401；公开域名同一路径返回 404。
错误 Host 返回 421；缺失的 `/assets/*.js` 或 API 路径返回 404，不返回首页 HTML。
静态哈希资源长缓存，HTML 重新验证，API 响应继续保留自身缓存策略。

## 6. 从 Cloudflare 版本迁移

1. 先备份原 PostgreSQL（含 schema、函数、分区）与受限访问的环境配置，保留旧二进制。
2. 构建新二进制，在临时数据库副本验证。保持 `DATABASE_URL`、全部 `PKI_MASTER_KEYS`、
   `PKI_MASTER_KEY_ACTIVE_ID`、root 凭据和两个正式域名。沿用原库，执行 `migrate` 应用增量迁移。
3. 从新环境文件移除 `CF_ACCESS_TEAM_DOMAIN`、`CF_ACCESS_AUD`、`PKI_ORIGIN_SHARED_SECRET`。
   Nginx 不再转发 `Cf-Access-*` 或 `X-PKI-*` 私有头，按上述方式设置 Host 和真实 IP。
4. 将新程序安装为现有 systemd 服务，执行 `migrate` 后重启，确认本机检查正常。
5. 配置 HTTPS Nginx 并验证，然后将业务域名切换到该 Nginx。
   全部客户端的请求必须到达 Nginx，不再经过旧 Pages 转发链路。
6. 验证成功后停用对应 Pages、Access 和 Tunnel 路由。共享 Tunnel 承载其他服务时只移除
   PKI 路由；保留旧环境与部署记录供回滚。上述外部资源变更由运维按实际环境执行。

现有账户、CA、证书、加密私钥、审批、任务与审计均沿用；历史审计的 `cf_access_sub`
字段保留，新登录不再写入 Cloudflare 身份。已有会话可用性受密码同步、过期和撤销影响；
切换后重新登录验证新链路。桌面程序移除 Cloudflare OAuth 流程，直接
执行本地登录，参见 [desktop-client-integration.md](desktop-client-integration.md)。

回滚时恢复旧二进制、旧代理/DNS 路由和完整旧环境（含 Access 与共享密钥配置）。
CA 导入功能包含增量 schema 迁移；降级前须处理 RSA-2048 和不限深度 CA，
迁移会拒绝破坏性降级。独立签发的 `00004_independent_signing.sql` 在存在实例时也会拒绝
删除相关表的降级；备份须包含独立 CA 密钥、凭据摘要、额度和签发/吊销记录。
按日常变更流程先验证备份和回滚路径。保留原证书发布域名，
避免已签发证书携带的 AIA/CRL/OCSP URL 失效。

## 7. 备份与排障

备份至少包含 PostgreSQL 完整备份和独立加密保管的 KEK/配置；丢失 KEK 无法解密已有私钥。
升级前先迁移，在同一服务中替换二进制即可更新前后端。查看日志：

```sh
sudo journalctl -u pki-console -n 100 --no-pager
```

| 现象 | 检查 |
| --- | --- |
| Nginx 502 | 程序状态、127.0.0.1:8080、本机 health |
| 421 | Nginx Host 与两个 BASE_URL 的域名是否一致 |
| 登录 401 | 本地密码、账户锁定、TOTP 算法/时间/重放；查看 login denied 日志 |
| 写请求 401 | Cookie、CSRF token、会话是否过期；HTTPS 是否正确 |
| 页面脚本加载失败 | 是否用 `make pki-console` 重新构建并部署完整二进制 |
| 无法解密密钥 | 旧 KEK 是否完整保留，active ID 是否有效 |
| TSA 拒绝签发 | 系统 NTP 状态与内核时钟不确定度 |

日常运维见 [operations-runbook.md](operations-runbook.md)，备份、隔离恢复和导出见
[deployment-migration-export.md](deployment-migration-export.md)。

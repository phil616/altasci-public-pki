# PKI-Console 安装说明

本发行包支持 Linux，包含已嵌入前端的单体程序。运行时需要外部 PostgreSQL 18+ 和
Nginx HTTPS 反向代理。生产主机不需要 Go、Node.js 或 npm。

## 1. 安装与配置

下载对应架构的压缩包及 `SHA256SUMS`，核对下载文件的 SHA-256 后解压。
以下命令在解压目录执行，示例假设使用 systemd：

```sh
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin pki-console
sudo install -o root -g root -m 0755 pki-console /usr/local/bin/pki-console
sudo install -d -o root -g pki-console -m 0750 /etc/pki-console
sudo install -o root -g pki-console -m 0640 .env.example /etc/pki-console/pki-console.env
```

编辑环境文件中的全部示例值，尤其是 `DATABASE_URL`、`ROOT_USER_EMAIL`、
`ROOT_USER_PASSWORD`、`PKI_MASTER_KEYS` 和两个业务域名。
管理员密码至少 32 字节；可用 `openssl rand -hex 32` 生成。
每个主密钥为 32 个随机字节的标准 Base64，可用 `openssl rand -base64 32` 生成，
替换 JSON 中的全零占位值。独立加密备份这些密钥，丢失后无法解密已有私钥。
远程数据库显式使用 `sslmode=verify-full`，回环 IP 可显式使用 `sslmode=disable`。

## 2. 初始化数据库和启动

创建专用的 PostgreSQL 18+ UTF-8 空数据库，由应用角色拥有 `public` schema 的
表、函数和分区权限。首版只提供空库初始化，不支持预发布数据库原地升级。
下面使用 shell 加载环境文件；示例文件采用单引号，请保持值为字面量，避免 shell 展开。

```sh
sudo -u pki-console env -i sh -c 'set -a; . /etc/pki-console/pki-console.env; exec /usr/local/bin/pki-console migrate'
sudo install -o root -g root -m 0644 pki-console.service /etc/systemd/system/pki-console.service
sudo systemctl daemon-reload
sudo systemctl enable --now pki-console
sudo systemctl status pki-console --no-pager
```

`migrate` 在事务内应用内嵌的唯一初始化 SQL；重复运行不会重置业务数据或账户。
`schema.sql` 是相同 SQL 的审阅副本，需要手动初始化时由 DBA 使用
`psql --single-transaction --set=ON_ERROR_STOP=1 --file=schema.sql` 对空库执行。
完整备份恢复时直接恢复到空库，不要先初始化。

`serve` 同时提供网页、API、认证和签发任务，无需额外 worker 服务。
所有角色使用用户名/邮箱和密码登录。超级管理员在首次 `serve` 启动时根据环境配置创建。

## 3. 配置 Nginx 和验证

按 `nginx.conf.example` 配置独立的管理域名与公开域名，替换 HTTPS 证书路径，
将请求代理到 `127.0.0.1:8080`，保留 Host 并覆盖 X-Forwarded-For。
应用端口保持仅回环监听。执行 `sudo nginx -t` 后重载 Nginx。

浏览器打开管理域名并登录。检查 `/api/v1/health/ready` 与 `/api/v1/version`，
在公开域名检查 `/health/live` 和 `/pki/v1/authorities`。
TSA 需要 Linux 内核报告系统时间已同步，误差符合配置上限。
故障日志：`sudo journalctl -u pki-console -n 100 --no-pager`。

完整操作指南、OpenAPI 和发布说明位于同版本源码的 `doc/pki-console/`。
`signing-client.py` 是可选的独立签发客户端，需要 Python 3；服务端无需 Python。

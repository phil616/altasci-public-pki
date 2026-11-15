# 备份、迁移、恢复与导出

状态：当前指南；核对日期：2026-11-15。适用于单体应用和外部 PostgreSQL 18+。
首次安装及 Cloudflare 版本切换见 [部署指南](production-deployment.md)。

## 备份范围

完整备份包含数据库结构与数据（含审计分区、函数、触发器、序列、约束），独立加密
保管的全部 KEK/配置、二进制及校验和、迁移状态、Nginx/systemd 配置、域名和 TLS 材料。
数据库包含加密私钥，与 KEK 同时泄露仍可能泄露私钥；两类备份分开加密保管并限制权限。
CA PEM、CSV 和审计查询不是完整备份。定义保留期并定期实际恢复验证。

## PostgreSQL 逻辑备份

安装与服务器兼容的 PostgreSQL 客户端，事先在 `pg_service.conf` 配置 `pki_backup`
和隔离演练库 `pki_restore`。密码使用受限权限的 `.pgpass` 等机制，不放入命令行或记录。

```sh
umask 077
pg_dump --dbname=service=pki_backup --format=custom --file=pki-console.dump
pg_restore --list pki-console.dump > pki-console.dump.list
sha256sum pki-console.dump > pki-console.dump.sha256
```

`pg_dump` 对运行中的单库生成一致性快照；角色、表空间等集群对象需 DBA 单独备份。
检查清单包含实际使用的审计月分区。规则见
[PostgreSQL 18 官方文档](https://www.postgresql.org/docs/18/backup-dump.html)。
环境备份至少保留数据库快照涉及的所有 KEK。

## 隔离恢复演练

目标为隔离的 PostgreSQL 18+ 空库，先创建拥有角色。以下假设 DBA 已准备 `pki_console`
角色，`pki_restore` 连接身份有权切换至该角色：

```sh
sha256sum --check pki-console.dump.sha256
pg_restore --exit-on-error --no-owner --role=pki_console \
  --dbname=service=pki_restore pki-console.dump
```

不要先迁移创建整套空表再恢复完整 dump，否则会产生对象冲突。`--no-owner` 不恢复原
所有权；源库 ACL 引用目标不存在的角色时，先重建角色或由 DBA 评估 `--no-acl` 后重授权限。
不能忽略恢复错误。

用独立配置指向演练库，保留对应 KEK，使用不会接管正式业务的域名和端口，运行目标
版本 `migrate` 后再启动。验收登录、已存私钥解密、审批签发、CRL/OCSP/TSA、审计和
前端。集成测试会清空数据库，只能在另一个专用测试库运行。

恢复旧快照会丢失之后的签发、吊销、审计和时间戳记录。正式恢复前明确 RPO/RTO，
收敛旧实例，避免两个数据分支同时签发。唯一约束不能跨两个恢复副本保证序列号或状态一致。

## 主机或存储迁移

1. 在副本验证目标二进制、数据库版本、配置和迁移。
2. 备份并安排写入维护窗口，停止旧程序及额外 worker，完成最终数据同步。
3. 迁移数据库和 KEK，保留正式域名；已有证书的 AIA/CRL/OCSP URL 无法追溯修改。
4. 安装新程序、Nginx/systemd，显式执行 `migrate`，启动 `serve`。
5. 检查健康、登录、签发和公开发布后切流，观察日志和队列。
6. 记录校验和、迁移状态、切换时点和回滚条件。

外部 PostgreSQL 可在独立主机、数据库服务或容器中运行；根目录 Dockerfile 和
`.goreleaser.yml` 属于原 CFSSL，不是当前 Console 镜像或发布配置。见 [发布指南](release.md)。

## 回滚

二进制回退前核实数据库兼容性。`00003_ca_import.sql` 在存在 RSA-2048 或不限路径深度
CA 时拒绝恢复旧约束。处理新数据后恢复旧库可能丢失签发与吊销记录，需制定衔接方案。
回到 Cloudflare 旧版还需原身份、代理和路由配置，历史例子不能直接套用。

## 证书与记录导出

管理 API 支持单证书 PEM 链下载、CA 证书/链查询、二次验证保护的 CA 私钥导出和
申请者服务器生成私钥的一次性领取，见 [OpenAPI](openapi.yaml)。私钥最多保存 24 小时，
在返回内容前提交擦除；网络或保存失败不能自动重取。

目前没有备份/恢复、历史吊销批量导入、全库 ZIP、批量私钥导出或主密钥重加密 API。
需要业务清单时，可在只读数据库连接的 `psql` 中导出经确认的字段：

```sql
\copy (SELECT id, issuer_ca_id, serial, status, not_before, not_after, created_at FROM certificates ORDER BY created_at) TO 'certificates.csv' WITH (FORMAT csv, HEADER true)
```

CSV 仍含业务元数据，需受控分发。不要将密钥表、会话表、口令或完整环境加入通用报表。
已有 CA 迁移的范围见 [ca-import.md](ca-import.md)。

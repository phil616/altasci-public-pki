# 数据库初始化

状态：当前指南；核对日期：2026-11-16。首个正式版使用单一基线 `pki-console-1`。

## 安装约定

准备专用 PostgreSQL 18+ 数据库，UTF-8 编码，`public` schema 为空。
运行账户需要连接、建表、建索引、建函数和创建审计分区的权限；无需数据库超级用户。
应用固定使用 `public,pg_catalog` 搜索路径。数据库连接与 TLS 规则见
[配置说明](README.md#配置) 和 [部署指南](production-deployment.md)。

唯一的初始化 SQL 是 [schema.sql](../../console/store/schema.sql)，构建时嵌入二进制，
发行包同时提供可审阅的副本。内容包括账户与会话、托管 PKI、CA 导入约束、TSA、
独立签发、审计分区和基线标记，不再包含编号增量迁移、旧认证清理或降级脚本。

## 推荐执行方式

先加载与服务相同的环境配置，再运行：

```sh
pki-console migrate
pki-console serve
```

`migrate` 名称保留为数据库准备命令，行为是初始化空库。
初始化在一个事务内完成，并用事务级 advisory lock 串行化应用初始化请求。
任何语句失败都会回滚，不留下半套表。`serve` 和 `worker` 只检查基线标记，
不会自动建表。首次启动 `serve` 时才创建环境配置的超级管理员。

对已具有本基线标记的数据库重复执行 `migrate`，只校验标记并准备当月、下月审计分区，
不重置密码、锁定、会话、CA 或签发数据。该命令不负责修复人为删除的表或约束。

如果 `public` 中已有表、函数或自定义类型，却没有本基线标记，命令会拒绝执行。
预发布数据库不支持原地升级；应另外准备空库。不会自动清空旧数据库，
也不要手动伪造标记来绕过检查。需要保留的数据先备份并单独制定迁移方案。

## 手动 SQL 方式

也可由 DBA 在同一个空库执行发行包中的 SQL。以下假设已在 PostgreSQL 客户端配置
`pki_init` service，连接身份是应用对象的拥有者，凭据通过受限 `.pgpass` 提供：

```sh
psql --dbname=service=pki_init --single-transaction --set=ON_ERROR_STOP=1 --file=schema.sql
```

必须使用事务和遇错即停选项，不能将文件中的语句逐条自动提交。
直接执行 SQL 是一次性替代方式，重复执行会遇到已存在对象错误；应用的 `migrate` 可重复执行。
不要混用并发的手动 SQL 和应用初始化。

## 备份恢复

完整数据库备份包含 `pki_schema`、函数、触发器和审计分区。
恢复完整备份时，先向空库恢复，不要预先执行初始化 SQL。
恢复后使用匹配的二进制和 KEK，再运行 `migrate` 检查基线和分区，最后启动服务。
具体步骤见 [备份与恢复](deployment-migration-export.md)。

# PKI-Console 运维记录模板

以下模板用于受控工单、值班系统或内部知识库。它们可以复制使用，但不要把动态运行记录
和敏感值提交到 Git。密码、TOTP、JWT、Cookie、数据库 URL、origin secret、Tunnel
Token、私钥和 KEK 只能记录其保管位置或版本 ID，不能记录内容。

## 日常巡检记录

```text
日期/时区：
值班人：

[ ] pki.altasci.com 首页、live、authorities 正常
[ ] pki-origin.altasci.com 匿名请求为 403
[ ] pki-console.altasci.com 进入 Access
[ ] pki-console.service active + enabled
[ ] cloudflared.service active + enabled
[ ] PostgreSQL 容器运行，应用 healthcheck 通过
[ ] 最近 24h 无未处理 ERROR/WARN/panic/audit write failure
[ ] issuance_jobs 无超时 running/积压 queued/failed
[ ] CA、CRL、OCSP 无临近到期告警
[ ] 最近一次数据库备份成功且大小合理
[ ] 磁盘、内存、时间同步和数据库连接正常

异常与工单：
交接事项：
```

## 生产变更记录

```text
变更编号：
申请人/执行人/批准人：
计划时间/实际时间/时区：
变更原因：
关联 issue/commit/tag：
影响域名/服务/CA：

变更前状态：
- 当前 binary version/SHA-256：
- 当前 Pages deployment：
- 数据库 migration version：
- 最近备份/PITR 点：
- public/origin/Console 基线结果：

实施步骤：
验证步骤：
回滚触发条件：
回滚步骤：

实际结果：
健康检查结果：
真实 Console 登录结果：
观察窗口与日志结论：
遗留事项：
```

## 备份与恢复演练记录

```text
演练编号/日期：
执行人/复核人：
隔离环境：
目标恢复时间点：
数据库备份 ID/校验和：
WAL 范围：
应用 tag/binary SHA-256：
KEK key IDs（不写值）：

恢复开始/结束时间：
实际 RPO：
实际 RTO：
表数量与审计分区检查：
CA envelope 解密检查：
申请/审批/签发/下载/吊销/CRL/OCSP 结果：
隔离环境销毁确认：

失败点与人工步骤：
改进工单：
批准人：
```

## 凭据或密钥轮换记录

```text
轮换编号/对象：
原因：例行 / 人员变更 / 疑似泄漏 / 算法策略 / Access 应用重建
执行人/见证人/批准人：
维护窗口：
旧版本 ID（不写值）：
新版本 ID（不写值）：
安全副本位置：

依赖方更新顺序：
服务重启/Pages deployment：
public 200 / origin 403 / ready：
真实 root 登录：
CA envelope 恢复验证：
旧材料销毁时间与见证人：
异常与后续事项：
```

## 安全或可用性事件记录

```text
事件编号/等级：P0 / P1 / P2 / P3
发现时间/恢复时间/关闭时间/时区：
发现人/指挥人/参与人：
影响域名、CA、用户和时间窗：
当前是否冻结签发：

症状：
第一条可靠证据：
request_id / audit event ID / backup ID（不得粘贴凭据）：
时间线：
根因：
处置：
数据或密钥影响：
公开 PKI 影响：
恢复验证：
证据保全位置：
对外/内部通知：
防复发行动、负责人和截止时间：
批准关闭人：
```

具体检查命令、阈值和处置步骤见 [operations-runbook.md](operations-runbook.md)。

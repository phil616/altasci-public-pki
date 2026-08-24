import { AuditOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Button, Card, Descriptions, Drawer, Select, Space, Table, Tag, Typography } from 'antd';
import { useState } from 'react';
import type { ColumnsType } from 'antd/es/table';

import { ErrorAlert, LoadingScreen, PageHeader, StatusTag } from '@/components/common';
import { consoleAPI } from '@/lib/api';
import { formatDate, shortID } from '@/lib/format';
import type { AuditRecord } from '@/types';

const { Text } = Typography;

export function AuditPage() {
  const [limit, setLimit] = useState(100);
  const [selected, setSelected] = useState<AuditRecord>();
  const events = useQuery({ queryKey: ['audit', limit], queryFn: () => consoleAPI.auditEvents(limit) });
  if (events.isPending) return <LoadingScreen />;
  if (events.error) return <ErrorAlert error={events.error} />;
  const columns: ColumnsType<AuditRecord> = [
    { title: '时间', dataIndex: 'occurred_at', width: 185, render: formatDate },
    { title: '动作', dataIndex: 'action', render: (value: string) => <Text code>{value}</Text> },
    { title: '结果', dataIndex: 'outcome', width: 100, render: (value: string) => <StatusTag status={value} /> },
    { title: '资源', responsive: ['md'], render: (_, item) => <Space><Tag>{item.resource_type}</Tag><Text type="secondary">{shortID(item.resource_id)}</Text></Space> },
    { title: '操作者', responsive: ['lg'], render: (_, item) => item.actor_role ? <Space><Tag>{item.actor_role}</Tag><Text>{shortID(item.actor_user_id)}</Text></Space> : '匿名' },
    { title: '来源地址', dataIndex: 'source_ip', responsive: ['xl'], render: (value?: string) => value ?? '—' },
    { title: '', width: 70, render: (_, item) => <Button type="link" onClick={() => setSelected(item)}>详情</Button> },
  ];
  return (
    <>
      <PageHeader eyebrow="IMMUTABLE AUDIT CHAIN" title="审计日志" description="按时间倒序查看哈希链保护的安全与业务事件。" actions={<><Select value={limit} onChange={setLimit} options={[50, 100, 250, 500].map((value) => ({ value, label: `最近 ${value} 条` }))} /><Button icon={<ReloadOutlined />} onClick={() => void events.refetch()}>刷新</Button></>} />
      <Card className="audit-integrity" variant="borderless"><Space><AuditOutlined /><div><Text strong>审计记录为追加写入并按月分区</Text><div><Text type="secondary">数据库触发器拒绝 UPDATE 与 DELETE；previous_hash 和 event_hash 可用于完整性核验。</Text></div></div></Space></Card>
      <Card className="content-card"><Table rowKey="id" columns={columns} dataSource={events.data?.items ?? []} scroll={{ x: 900 }} pagination={{ pageSize: 25, hideOnSinglePage: true }} /></Card>
      <Drawer title="审计事件详情" size={620} open={Boolean(selected)} onClose={() => setSelected(undefined)}>
        {selected ? <><Descriptions column={1} items={[
          { key: 'id', label: '事件 ID', children: <Text copyable>{selected.id}</Text> }, { key: 'request', label: '请求 ID', children: <Text copyable>{selected.request_id}</Text> },
          { key: 'action', label: '动作', children: selected.action }, { key: 'outcome', label: '结果', children: <StatusTag status={selected.outcome} /> },
          { key: 'actor', label: '操作者', children: selected.actor_user_id ?? '匿名' }, { key: 'session', label: '会话', children: selected.session_id ?? '—' },
          { key: 'resource', label: '资源', children: `${selected.resource_type} / ${selected.resource_id ?? '—'}` }, { key: 'source', label: '来源', children: selected.source_ip ?? '—' },
          { key: 'previous', label: '前序哈希', children: <Text code className="break-all">{selected.previous_hash}</Text> }, { key: 'hash', label: '事件哈希', children: <Text code className="break-all">{selected.event_hash}</Text> },
        ]} /><pre className="json-block">{JSON.stringify({ before: selected.before_state, after: selected.after_state, metadata: selected.metadata }, null, 2)}</pre></> : null}
      </Drawer>
    </>
  );
}

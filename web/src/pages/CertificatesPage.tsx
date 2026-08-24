import { DownloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Button, Card, Space, Table, Tabs, Typography } from 'antd';
import { useState } from 'react';
import type { ColumnsType } from 'antd/es/table';
import { Link } from 'react-router-dom';

import { useAuth } from '@/auth';
import { ErrorAlert, LoadingScreen, PageHeader, StatusTag } from '@/components/common';
import { consoleAPI } from '@/lib/api';
import { formatDate, roleLabels, shortID } from '@/lib/format';
import type { CertificateInventoryItem, CertificateInventoryStatus } from '@/types';

const { Text } = Typography;
type InventoryTab = 'all' | CertificateInventoryStatus;

export function CertificatesPage() {
  const { user } = useAuth();
  const [tab, setTab] = useState<InventoryTab>('all');
  const inventory = useQuery({
    queryKey: ['certificate-inventory', tab],
    queryFn: () => consoleAPI.certificateInventory(tab === 'all' ? undefined : tab),
    refetchInterval: tab === 'pending' || tab === 'all' ? 10_000 : 30_000,
  });
  if (inventory.isPending) return <LoadingScreen />;
  if (inventory.error) return <ErrorAlert error={inventory.error} />;
  const columns: ColumnsType<CertificateInventoryItem> = [
    {
      title: '证书或申请',
      render: (_, item) => {
        const href = item.certificate_id ? `/certificates/${item.certificate_id}` : `/requests/${item.request_id}`;
        return <Space><div className={`list-icon ${item.certificate_id ? 'certificate' : ''}`}><SafetyCertificateOutlined /></div><div><Link to={href}><Text strong>{item.subject?.common_name || item.serial || '证书申请'}</Text></Link><div><Text type="secondary">{item.serial ? `序列号 ${item.serial}` : `申请 ${shortID(item.request_id ?? '')}`}</Text></div></div></Space>;
      },
    },
    {
      title: '状态',
      render: (_, item) => <StatusTag status={item.certificate_status === 'revoked' ? 'revoked' : item.request_status ?? item.workflow_status} />,
    },
    { title: '申请人', dataIndex: 'requester_username', responsive: ['md'] },
    {
      title: '审批记录',
      responsive: ['lg'],
      render: (_, item) => item.approver_username
        ? <><Text>{item.approver_username}</Text><div><Text type="secondary">{item.request_status === 'rejected' ? '拒绝申请' : '批准申请'}</Text></div></>
        : <Text type="secondary">{item.workflow_status === 'pending' ? '等待审批' : '—'}</Text>,
    },
    { title: '签发机构', responsive: ['xl'], render: (_, item) => <Link to={`/authorities/${item.issuer_ca_id}`}>{item.issuer_name}</Link> },
    { title: '更新时间', responsive: ['lg'], render: (_, item) => formatDate(item.issued_at ?? item.submitted_at) },
    {
      title: '操作',
      align: 'right',
      render: (_, item) => item.certificate_id
        ? <Space><Button icon={<DownloadOutlined />} onClick={() => void consoleAPI.downloadCertificate(item.certificate_id!)}>下载</Button><Link to={`/certificates/${item.certificate_id}`}>详情</Link></Space>
        : <Link to={`/requests/${item.request_id}`}>{item.request_status === 'rejected' ? '查看原因' : '跟踪申请'}</Link>,
    },
  ];
  const description = user?.role === 'super_admin'
    ? '系统内全部证书和申请，包含所有用户与运维人员处理的记录。'
    : user?.role === 'operator'
      ? '查看本人申请、经手的审批历史，以及授权 CA 下的待处理和已签发记录。'
      : '查看自己的证书及申请进度；申请提交后会立即出现在“待签发”中。';
  return (
    <>
      <PageHeader eyebrow="CERTIFICATE INVENTORY" title="证书库" description={`${roleLabels[user?.role ?? 'user']}视图 · ${description}`} />
      <Card className="content-card">
        <Tabs
          activeKey={tab}
          onChange={(value) => setTab(value as InventoryTab)}
          items={[
            { key: 'all', label: '全部' },
            { key: 'pending', label: '待签发' },
            { key: 'issued', label: '已签发' },
            { key: 'rejected', label: '已拒绝' },
            { key: 'failed', label: '失败或取消' },
          ]}
        />
        <Table
          rowKey={(item) => item.certificate_id ?? item.request_id ?? `${item.issuer_ca_id}-${item.serial}`}
          columns={columns}
          dataSource={inventory.data?.items ?? []}
          scroll={{ x: 960 }}
          pagination={{ pageSize: 20, hideOnSinglePage: true }}
        />
      </Card>
    </>
  );
}

import {
  CheckCircleFilled,
  ClockCircleFilled,
  CloseCircleFilled,
  CopyOutlined,
  DownloadOutlined,
  ExclamationCircleFilled,
  SafetyCertificateOutlined,
} from '@ant-design/icons';
import { Alert, Button, Card, Empty, Flex, Skeleton, Space, Tag, Tooltip, Typography, message } from 'antd';
import type { ReactNode } from 'react';

import { APIError } from '@/lib/api';
import { copyText, downloadText } from '@/lib/format';

const { Text, Title } = Typography;

export function LoadingScreen({ compact = false }: { compact?: boolean }) {
  return (
    <div className={compact ? 'loading-compact' : 'loading-screen'} aria-label="正在加载">
      <Skeleton active paragraph={{ rows: compact ? 2 : 5 }} />
    </div>
  );
}

export function ErrorAlert({ error, title = '加载失败' }: { error: unknown; title?: string }) {
  const detail = error instanceof APIError ? error.message : error instanceof Error ? error.message : '发生未知错误';
  const requestID = error instanceof APIError ? error.requestID : undefined;
  return (
    <Alert
      type="error"
      showIcon
      title={title}
      description={<>{detail}{requestID ? <Text type="secondary"> · 请求 ID：{requestID}</Text> : null}</>}
    />
  );
}

export function PageHeader({ eyebrow, title, description, actions }: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <Flex className="page-header" justify="space-between" align="flex-start" gap="large" wrap>
      <div>
        {eyebrow ? <Text className="eyebrow">{eyebrow}</Text> : null}
        <Title level={2}>{title}</Title>
        {description ? <Text type="secondary" className="page-description">{description}</Text> : null}
      </div>
      {actions ? <Space wrap>{actions}</Space> : null}
    </Flex>
  );
}

const statusMap: Record<string, { color: string; label: string; icon?: ReactNode }> = {
  active: { color: 'green', label: '有效', icon: <CheckCircleFilled /> },
  good: { color: 'green', label: '正常', icon: <CheckCircleFilled /> },
  issued: { color: 'green', label: '已签发', icon: <CheckCircleFilled /> },
  success: { color: 'green', label: '成功', icon: <CheckCircleFilled /> },
  pending: { color: 'gold', label: '待审批', icon: <ClockCircleFilled /> },
  approved: { color: 'cyan', label: '已批准', icon: <ClockCircleFilled /> },
  issuing: { color: 'blue', label: '签发中', icon: <ClockCircleFilled /> },
  rejected: { color: 'red', label: '已拒绝', icon: <CloseCircleFilled /> },
  revoked: { color: 'red', label: '已吊销', icon: <CloseCircleFilled /> },
  disabled: { color: 'default', label: '已停用', icon: <CloseCircleFilled /> },
  locked: { color: 'orange', label: '已锁定', icon: <ExclamationCircleFilled /> },
  failed: { color: 'red', label: '失败', icon: <CloseCircleFilled /> },
  cancelled: { color: 'default', label: '已取消', icon: <CloseCircleFilled /> },
  failure: { color: 'red', label: '失败', icon: <CloseCircleFilled /> },
  denied: { color: 'orange', label: '已拒绝', icon: <ExclamationCircleFilled /> },
  expired: { color: 'default', label: '已过期', icon: <ClockCircleFilled /> },
  root: { color: 'purple', label: '根 CA' },
  intermediate: { color: 'geekblue', label: '中间 CA' },
};

export function StatusTag({ status }: { status: string }) {
  const item = statusMap[status] ?? { color: 'default', label: status };
  return <Tag color={item.color} icon={item.icon}>{item.label}</Tag>;
}

export function CopyButton({ value, label = '复制' }: { value: string; label?: string }) {
  const [messageAPI, contextHolder] = message.useMessage();
  return <>{contextHolder}<Button icon={<CopyOutlined />} onClick={() => void copyText(value).then(() => messageAPI.success('已复制'))}>{label}</Button></>;
}

export function PEMViewer({ value, filename }: { value: string; filename: string }) {
  return (
    <Card className="pem-card" size="small">
      <Flex justify="space-between" align="center" gap="small" className="pem-toolbar">
        <Space><SafetyCertificateOutlined /><Text strong>{filename}</Text></Space>
        <Space>
          <Tooltip title="复制 PEM"><CopyButton value={value} label="复制" /></Tooltip>
          <Button icon={<DownloadOutlined />} onClick={() => downloadText(value, filename)}>下载</Button>
        </Space>
      </Flex>
      <pre className="pem-block"><code>{value}</code></pre>
    </Card>
  );
}

export function EmptyPanel({ title, description }: { title: string; description?: string }) {
  return <Card><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={<Space orientation="vertical" size={0}><Text strong>{title}</Text>{description ? <Text type="secondary">{description}</Text> : null}</Space>} /></Card>;
}

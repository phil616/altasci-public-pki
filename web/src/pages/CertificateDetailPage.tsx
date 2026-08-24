import { CopyOutlined, DownloadOutlined, KeyOutlined, StopOutlined, WarningOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { App, Alert, Button, Card, Descriptions, Form, Input, Modal, Select, Space, Tag, Typography } from 'antd';
import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { useAuth } from '@/auth';
import { ErrorAlert, LoadingScreen, PageHeader, PEMViewer, StatusTag } from '@/components/common';
import { consoleAPI } from '@/lib/api';
import { copyText, formatDate } from '@/lib/format';
import { can } from '@/lib/permissions';

const { Text } = Typography;
const revocationReasons = [
  { value: 0, label: '未指定' }, { value: 1, label: '密钥泄露' }, { value: 2, label: 'CA 泄露' },
  { value: 3, label: '隶属关系变更' }, { value: 4, label: '证书被替代' }, { value: 5, label: '停止运营' },
  { value: 6, label: '暂停证书' }, { value: 8, label: '从 CRL 移除' }, { value: 9, label: '权限撤销' }, { value: 10, label: '属性机构泄露' },
];

export function CertificateDetailPage() {
  const { id = '' } = useParams();
  const { user } = useAuth();
  const { message, modal } = App.useApp();
  const queryClient = useQueryClient();
  const certificate = useQuery({ queryKey: ['certificate', id], queryFn: () => consoleAPI.certificate(id), enabled: Boolean(id) });
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [form] = Form.useForm<{ reason: number; comment: string }>();
  const revoke = useMutation({
    mutationFn: (values: { reason: number; comment: string }) => consoleAPI.revokeCertificate(id, values.reason, values.comment),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['certificate', id] }); void queryClient.invalidateQueries({ queryKey: ['certificates'] }); setRevokeOpen(false); form.resetFields(); message.success('证书已吊销，CRL 与 OCSP 状态已更新'); },
    onError: (error) => message.error(error.message),
  });
  if (certificate.isPending) return <LoadingScreen />;
  if (certificate.error) return <ErrorAlert error={certificate.error} />;
  const cert = certificate.data;
  const ownsCertificate = user?.id === cert.owner_user_id;
  return (
    <>
      <PageHeader
        eyebrow="X.509 CERTIFICATE"
        title={cert.subject?.common_name || `证书 ${cert.serial}`}
        description={`序列号 ${cert.serial}`}
        actions={<><StatusTag status={cert.status} /><Button icon={<DownloadOutlined />} onClick={() => void consoleAPI.downloadCertificate(id)}>下载证书链</Button>{ownsCertificate ? <Button icon={<KeyOutlined />} onClick={() => { modal.confirm({ title: '下载一次性私钥？', icon: <WarningOutlined />, content: '仅服务端生成的私钥可下载，成功响应后服务器会立即擦除密文。请准备好安全存储位置。', okText: '下载并擦除服务端副本', onOk: () => consoleAPI.downloadPrivateKey(id).then(() => message.success('私钥已下载，服务端副本已擦除')).catch((error: Error) => message.error(error.message)) }); }}>下载一次性私钥</Button> : null}{can(user?.role, 'revoke_certificates') && cert.status === 'good' ? <Button danger icon={<StopOutlined />} onClick={() => setRevokeOpen(true)}>吊销</Button> : null}</>}
      />
      <Card className="content-card">
        <Descriptions column={{ xs: 1, md: 2 }} items={[
          { key: 'issuer', label: '签发机构', children: <Link to={`/authorities/${cert.issuer_ca_id}`}>{cert.issuer_ca_id}</Link> },
          { key: 'owner', label: '所有者 ID', children: <Text copyable>{cert.owner_user_id}</Text> },
          { key: 'request', label: '关联申请', children: cert.request_id ? <Link to={`/requests/${cert.request_id}`}>{cert.request_id}</Link> : '—' },
          { key: 'status', label: '状态', children: <StatusTag status={cert.status} /> },
          { key: 'before', label: '生效时间', children: formatDate(cert.not_before) },
          { key: 'after', label: '到期时间', children: formatDate(cert.not_after) },
          { key: 'sans', label: 'SAN', span: 2, children: <Space wrap>{(cert.sans ?? []).map((value) => <Tag key={value}>{value}</Tag>)}{!cert.sans?.length ? '—' : null}</Space> },
          { key: 'fingerprint', label: 'SHA-256 指纹', span: 2, children: <Space><Text code className="break-all">{cert.fingerprint_sha256}</Text><Button type="text" icon={<CopyOutlined />} onClick={() => void copyText(cert.fingerprint_sha256).then(() => message.success('指纹已复制'))} /></Space> },
        ]} />
      </Card>
      <Space orientation="vertical" size="large" className="full-width">
        <PEMViewer value={cert.certificate_pem} filename={`${cert.id}.pem`} />
        <PEMViewer value={cert.chain_pem} filename={`${cert.id}-chain.pem`} />
      </Space>
      <Modal title="吊销证书" open={revokeOpen} onCancel={() => setRevokeOpen(false)} onOk={() => form.submit()} confirmLoading={revoke.isPending} okText="永久吊销" okButtonProps={{ danger: true }} destroyOnHidden>
        <Alert type="warning" showIcon title="吊销操作不可撤销" description="提交后会重新生成 CRL，并立即更新 OCSP 响应。" />
        <Form form={form} layout="vertical" initialValues={{ reason: 0 }} onFinish={(values) => revoke.mutate(values)} requiredMark={false}>
          <Form.Item name="reason" label="RFC 5280 吊销原因" rules={[{ required: true }]}><Select options={revocationReasons} /></Form.Item>
          <Form.Item name="comment" label="审计说明"><Input.TextArea rows={4} maxLength={2000} showCount /></Form.Item>
        </Form>
      </Modal>
    </>
  );
}

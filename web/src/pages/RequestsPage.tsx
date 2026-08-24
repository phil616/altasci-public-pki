import { FileAddOutlined, FileProtectOutlined, PlusOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { App, Button, Card, Col, Form, Input, InputNumber, Modal, Radio, Row, Select, Space, Table, Typography } from 'antd';
import { useState } from 'react';
import type { ColumnsType } from 'antd/es/table';
import { Link } from 'react-router-dom';

import { ErrorAlert, LoadingScreen, PageHeader, StatusTag } from '@/components/common';
import { consoleAPI, type CreateRequestInput } from '@/lib/api';
import { formatDate, shortID } from '@/lib/format';
import type { CertificateRequest, ListResponse } from '@/types';

const { Text } = Typography;
interface RequestValues extends Omit<CreateRequestInput, 'server_generate_key' | 'sans' | 'subject'> {
  mode: 'server_generated' | 'client_csr';
  sans?: string[];
  subject?: CreateRequestInput['subject'];
}

export function RequestsPage() {
  const requests = useQuery({ queryKey: ['requests'], queryFn: consoleAPI.requests, refetchInterval: 10_000 });
  const [open, setOpen] = useState(false);
  const columns: ColumnsType<CertificateRequest> = [
    { title: '申请对象', render: (_, item) => <Space><div className="list-icon"><FileProtectOutlined /></div><div><Link to={`/requests/${item.id}`}><Text strong>{item.requested_subject?.common_name || 'CSR 证书申请'}</Text></Link><div><Text type="secondary">{(item.requested_sans ?? []).slice(0, 2).join(' · ') || shortID(item.id)}</Text></div></div></Space> },
    { title: '状态', dataIndex: 'status', render: (status: string) => <StatusTag status={status} /> },
    { title: '密钥来源', dataIndex: 'key_generation_mode', responsive: ['md'], render: (mode: string) => mode === 'server_generated' ? '服务端生成' : '客户端 CSR' },
    { title: '提交时间', dataIndex: 'submitted_at', responsive: ['lg'], render: formatDate },
    { title: '操作', align: 'right', render: (_, item) => <Link to={`/requests/${item.id}`}>查看详情</Link> },
  ];
  if (requests.isPending) return <LoadingScreen />;
  if (requests.error) return <ErrorAlert error={requests.error} />;
  return (
    <>
      <PageHeader eyebrow="ISSUANCE WORKFLOW" title="证书申请" description="提交 CSR 或由服务端生成密钥，跟踪审批与异步签发状态。" actions={<Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>申请证书</Button>} />
      <Card className="content-card"><Table rowKey="id" columns={columns} dataSource={requests.data?.items ?? []} scroll={{ x: 760 }} pagination={{ pageSize: 20, hideOnSinglePage: true }} /></Card>
      <RequestModal open={open} onClose={() => setOpen(false)} />
    </>
  );
}

function RequestModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { message } = App.useApp();
  const queryClient = useQueryClient();
  const authorities = useQuery({ queryKey: ['authorities'], queryFn: consoleAPI.authorities, enabled: open });
  const [form] = Form.useForm<RequestValues>();
  const caID = Form.useWatch('ca_id', form);
  const mode = Form.useWatch('mode', form);
  const profiles = useQuery({ queryKey: ['profiles', caID], queryFn: () => consoleAPI.profiles(caID), enabled: open && Boolean(caID) });
  const create = useMutation({
    mutationFn: (values: RequestValues) => consoleAPI.createRequest({
      ca_id: values.ca_id,
      profile_id: values.profile_id,
      csr_pem: values.mode === 'client_csr' ? values.csr_pem : undefined,
      subject: values.mode === 'server_generated' ? values.subject ?? { common_name: '' } : { common_name: '' },
      sans: values.mode === 'server_generated' ? values.sans ?? [] : [],
      server_generate_key: values.mode === 'server_generated',
      requested_validity_seconds: values.requested_validity_seconds,
    }),
    onSuccess: (created) => {
      queryClient.setQueryData<ListResponse<CertificateRequest>>(['requests'], (current) => ({
        items: [created, ...(current?.items ?? []).filter((item) => item.id !== created.id)],
      }));
      void queryClient.invalidateQueries({ queryKey: ['certificate-inventory'] });
      form.resetFields();
      onClose();
      message.success('证书申请已提交，可在证书库的“待签发”中跟踪');
    },
    onError: (error) => message.error(error.message),
  });
  const issuers = (authorities.data?.items ?? []).filter((ca) => ca.kind === 'intermediate' && ca.status === 'active');
  return (
    <Modal title={<Space><FileAddOutlined />申请新证书</Space>} open={open} width={720} onCancel={onClose} onOk={() => form.submit()} confirmLoading={create.isPending} okText="提交申请" cancelText="取消" destroyOnHidden>
      <Form form={form} layout="vertical" requiredMark={false} initialValues={{ mode: 'server_generated' }} onFinish={(values) => create.mutate(values)}>
        <Form.Item name="ca_id" label="签发机构" tooltip="选择最终为该证书签名的中间 CA。你只能看到当前身份有权使用的有效机构。" rules={[{ required: true }]}><Select loading={authorities.isPending} placeholder="选择有效的中间 CA" options={issuers.map((ca) => ({ value: ca.id, label: `${ca.name} (${ca.slug})` }))} onChange={() => form.setFieldValue('profile_id', undefined)} /></Form.Item>
        <Form.Item name="profile_id" label="签发策略" tooltip="策略限制证书有效期、密钥用途、SAN 类型以及允许的 DNS/IP 范围。" extra="不选择时使用该 CA 的默认策略。" ><Select allowClear loading={profiles.isFetching} placeholder="默认策略" options={(profiles.data?.items ?? []).filter((profile) => profile.enabled).map((profile) => ({ value: profile.id, label: `${profile.name} · 最长 ${Math.round(profile.max_validity_seconds / 86400)} 天` }))} /></Form.Item>
        <Form.Item name="mode" label="密钥生成方式" tooltip="提交 CSR 时私钥始终保留在你的设备；服务端生成适合无法自行生成密钥的场景，但私钥只能下载一次。"><Radio.Group optionType="button" buttonStyle="solid" options={[{ value: 'server_generated', label: '服务端生成' }, { value: 'client_csr', label: '提交 CSR' }]} /></Form.Item>
        {mode === 'client_csr' ? (
          <Form.Item name="csr_pem" label="PKCS#10 CSR（PEM）" rules={[{ required: true }]} extra="私钥不会上传。主题和 SAN 将从 CSR 中解析。"><Input.TextArea className="code-input" rows={10} spellCheck={false} placeholder="-----BEGIN CERTIFICATE REQUEST-----" /></Form.Item>
        ) : (
          <>
            <Form.Item name={['subject', 'common_name']} label="通用名称（CN）" tooltip="证书的主要显示名称。TLS 客户端实际验证的主机名仍应写入 SAN。" rules={[{ required: true }]}><Input placeholder="service.example.internal" /></Form.Item>
            <Row gutter={12}><Col xs={24} md={12}><Form.Item name={['subject', 'organization']} label="组织（O）" tooltip="证书所属组织，可由签发策略进一步限制。"><Input /></Form.Item></Col><Col xs={24} md={12}><Form.Item name={['subject', 'organizational_unit']} label="组织单位（OU）" tooltip="申请该证书的业务部门或系统团队。"><Input /></Form.Item></Col></Row>
            <Form.Item name="sans" label="主题备用名称（SAN）" tooltip="客户端用于身份匹配的 DNS 名、IP、邮箱或 URI。每输入一项后按回车确认。" extra="TLS 服务器证书应至少包含一个与实际访问地址匹配的 DNS 或 IP SAN。"><Select mode="tags" tokenSeparators={[',']} placeholder="service.example.internal, 10.0.0.10" /></Form.Item>
          </>
        )}
        <Form.Item name="requested_validity_seconds" label="申请有效期（秒，可选）" tooltip="从证书生效开始计算的持续时间，不能超过所选策略的最大有效期。" extra="留空时使用策略默认值；例如 86400 表示 1 天。"><InputNumber min={1} className="full-width" placeholder="留空使用策略默认值" /></Form.Item>
        {mode === 'server_generated' ? <Card size="small" className="inline-warning"><Text strong>私钥仅允许下载一次，并在 24 小时后过期。</Text><br /><Text type="secondary">成功下载后，服务端会擦除密文。</Text></Card> : null}
      </Form>
    </Modal>
  );
}

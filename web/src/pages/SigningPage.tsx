import { PlusOutlined, UploadOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, App, Button, Card, Checkbox, Col, Empty, Form, Input, InputNumber, Modal, Popconfirm, Row, Select, Space, Switch, Table, Tabs, Typography, Upload } from 'antd';
import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import { CopyButton, ErrorAlert, LoadingScreen, PageHeader, PEMViewer, StatusTag } from '@/components/common';
import { formatDate } from '@/lib/format';
import { defaultIssuancePolicy, signingAPI, type IndependentCertificate, type IssuancePolicy, type SigningCreateInput, type SigningCredentialInput, type SigningInstance } from '@/lib/signing';

const { Text, Paragraph } = Typography;

function useCurrentTime() {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 60000); return () => window.clearInterval(timer); }, []);
  return now;
}

function PolicyFields({ prefix = 'policy' }: { prefix?: string }) {
  return <>
    <Form.Item name={[prefix, 'version']} hidden><InputNumber /></Form.Item>
    <Row gutter={16}>{[
      ['allowed_dns_names', '允许的 DNS 名称', '精确名称或 *.example.com；星号规则只匹配下一级。空列表拒绝 DNS。'],
      ['allowed_ip_ranges', '允许的 IP 网段', 'IPv4/IPv6 CIDR，例如 10.20.0.0/16；空列表拒绝 IP。'],
      ['allowed_email_domains', '允许的邮箱域', '仅填写邮箱的域名，不默认包含子域。空列表拒绝邮箱。'],
      ['allowed_uri_prefixes', '允许的 URI 前缀', 'https/spiffe URI，按路径边界匹配；空列表拒绝 URI。'],
    ].map(([name, label, extra]) => <Col xs={24} lg={12} key={name}><Form.Item name={[prefix, name]} label={label} extra={extra}><Select mode="tags" tokenSeparators={[',', '\n']} /></Form.Item></Col>)}</Row>
    <Form.Item name={[prefix, 'allow_wildcards']} label="允许签发通配符证书" valuePropName="checked" extra="还必须由 DNS 白名单中的通配符规则覆盖。"><Switch /></Form.Item>
    <Form.Item name={[prefix, 'extended_key_usages']} label="证书用途" rules={[{ required: true, type: 'array', min: 1 }]}><Checkbox.Group options={[{ value: 'server_auth', label: '服务端认证' }, { value: 'client_auth', label: '客户端认证' }]} /></Form.Item>
    <Row gutter={16}><Col xs={24} md={8}><Form.Item name={[prefix, 'default_validity_seconds']} label="默认有效期（秒）" rules={[{ required: true }]}><InputNumber min={60} max={34300800} precision={0} className="full-width" /></Form.Item></Col><Col xs={24} md={8}><Form.Item name={[prefix, 'max_validity_seconds']} label="最大有效期（秒）" rules={[{ required: true }]}><InputNumber min={60} max={34300800} precision={0} className="full-width" /></Form.Item></Col><Col xs={24} md={8}><Form.Item name={[prefix, 'max_sans']} label="单证书 SAN 数量上限" rules={[{ required: true }]}><InputNumber min={1} max={100} precision={0} className="full-width" /></Form.Item></Col></Row>
  </>;
}

export function SigningPage() {
  const { id } = useParams();
  const now = useCurrentTime();
  const list = useQuery({ queryKey: ['signing-instances'], queryFn: signingAPI.list });
  const [createOpen, setCreateOpen] = useState(false);
  return <>
    <PageHeader eyebrow="INDEPENDENT SIGNING" title="独立签发" description="使用单独导入的 CA，为持有凭据的可信方按策略自动签发证书。" actions={<Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>创建签发实例</Button>} />
    <Alert type="info" showIcon title="凭据即授权，申请不经过人工审批或域名验证" description="请显式设置身份白名单，并为每个可信方分配不同凭据。实例与系统 CA 和证书库分别管理。" />
    {list.isPending ? <LoadingScreen compact /> : list.error ? <ErrorAlert error={list.error} /> : <Row gutter={[16, 16]} style={{ marginTop: 20 }}>{list.data.items.map((item) => <Col xs={24} md={12} xl={8} key={item.id}><Link to={`/tools/signing/${item.id}`}><Card hoverable title={item.name} extra={<StatusTag status={!item.enabled ? 'disabled' : new Date(item.not_after).getTime() <= now ? 'expired' : 'active'} />}><Text type="secondary">CA 到期：{formatDate(item.not_after)}</Text><Paragraph code ellipsis>{item.id}</Paragraph></Card></Link></Col>)}{!list.data.items.length ? <Col span={24}><Empty description="尚未创建独立签发实例" /></Col> : null}</Row>}
    {id ? <SigningDetail key={id} id={id} /> : null}
    {createOpen ? <ImportSigningModal onClose={() => setCreateOpen(false)} /> : null}
  </>;
}

function ImportSigningModal({ onClose }: { onClose: () => void }) {
  const { message } = App.useApp(); const queryClient = useQueryClient(); const navigate = useNavigate();
  const [form] = Form.useForm<SigningCreateInput>(); const generation = useRef(0);
  const create = useMutation({ mutationFn: signingAPI.create, gcTime: 0,
    onSuccess: (item) => { generation.current++; form.resetFields(); create.reset(); void queryClient.invalidateQueries({ queryKey: ['signing-instances'] }); onClose(); void navigate(`/tools/signing/${item.id}`); message.success('独立签发实例已创建'); },
    onError: (error) => message.error(error.message),
  });
  const close = () => { if (create.isPending) return; generation.current++; form.resetFields(); create.reset(); onClose(); };
  const read = async (file: File, field: 'certificate_pem' | 'private_key_pem' | 'chain_pem') => {
    const current = generation.current;
    const limit = { certificate_pem: 65536, private_key_pem: 32768, chain_pem: 262144 }[field];
    if (file.size > limit) { message.error(`文件不能超过 ${limit / 1024} KiB`); return Upload.LIST_IGNORE; }
    try { const text = await file.text(); if (current === generation.current) form.setFieldValue(field, text); } catch { message.error('无法读取文件'); }
    return Upload.LIST_IGNORE;
  };
  return <Modal open title="创建独立签发实例" width={820} onCancel={close} onOk={() => form.submit()} confirmLoading={create.isPending} cancelButtonProps={{ disabled: create.isPending }} okText="验证并创建" cancelText="取消" destroyOnHidden>
    <Form name="signing-import" form={form} layout="vertical" disabled={create.isPending} initialValues={{ policy: defaultIssuancePolicy, chain_pem: '' }} onFinish={(input) => create.mutate(input)}>
      <Alert type="warning" showIcon title="建议使用专用于此服务的中间 CA" description="相同 CA 可以重复导入且分别存储，但复用同一私钥仍具有共同的信任风险。私钥只用于此实例，不提供导出。" />
      <Form.Item name="name" label="实例名称" rules={[{ required: true, whitespace: true }]}><Input maxLength={128} /></Form.Item>
      {([
        ['certificate_pem', '签发 CA 证书', true], ['private_key_pem', '匹配的未加密 CA 私钥', true], ['chain_pem', '上级证书链（根 CA 可留空）', false],
      ] as const).map(([field, label, required]) => <div key={field}><Upload accept=".pem,.crt,.cer,.key" showUploadList={false} beforeUpload={(file) => read(file, field)}><Button icon={<UploadOutlined />}>选择{label}文件</Button></Upload><Form.Item name={field} label={label} rules={[{ required }]}><Input.TextArea rows={4} maxLength={field === 'private_key_pem' ? 32768 : field === 'certificate_pem' ? 65536 : 262144} autoComplete="off" spellCheck={false} /></Form.Item></div>)}
      <PolicyFields />
    </Form>
  </Modal>;
}

function SigningDetail({ id }: { id: string }) {
  const detail = useQuery({ queryKey: ['signing-instance', id], queryFn: () => signingAPI.get(id) });
  if (detail.isPending) return <LoadingScreen compact />;
  if (detail.error) return <ErrorAlert error={detail.error} />;
  const item = detail.data;
  return <Card className="content-card" style={{ marginTop: 24 }} title={item.name}>
    <Paragraph><Text strong>签发地址：</Text><Text code className="signing-endpoint">{item.endpoint}</Text> <CopyButton value={item.endpoint} /></Paragraph>
    <Paragraph type="secondary">客户端本地生成 CSR，使用 Authorization: Bearer 凭据及唯一 Idempotency-Key 请求此地址。此接口使用自定义协议。</Paragraph>
    <Tabs items={[
      { key: 'credentials', label: '访问凭据', children: <Credentials instance={item} /> },
      { key: 'certificates', label: '已签发证书', children: <IssuedCertificates id={id} /> },
      { key: 'policy', label: '签发策略', children: <InstancePolicy key={item.updated_at} instance={item} /> },
      { key: 'issuer', label: 'CA 与发布', children: <><Paragraph><a href={item.endpoint.replace(/\/issue$/, '/issuer.cer')} target="_blank" rel="noreferrer">下载签发者 DER 证书</a> · <a href={item.endpoint.replace(/\/issue$/, '/crl')} target="_blank" rel="noreferrer">下载本实例作用域 CRL</a></Paragraph><PEMViewer value={item.chain_pem} filename="issuer-chain.pem" /></> },
    ]} />
  </Card>;
}

function InstancePolicy({ instance }: { instance: SigningInstance }) {
  const { message } = App.useApp(); const queryClient = useQueryClient();
  const update = useMutation({ mutationFn: (input: { name: string; policy: IssuancePolicy; enabled: boolean }) => signingAPI.update(instance.id, input), onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['signing-instance', instance.id] }); void queryClient.invalidateQueries({ queryKey: ['signing-instances'] }); message.success('策略已更新'); }, onError: (error) => message.error(error.message) });
  return <Form name="signing-policy" layout="vertical" initialValues={{ name: instance.name, policy: instance.policy, enabled: instance.enabled }} onFinish={(values: { name: string; policy: IssuancePolicy; enabled: boolean }) => update.mutate({ name: values.name, policy: values.policy, enabled: values.enabled })}>
    <Form.Item name="name" label="实例名称" rules={[{ required: true, whitespace: true }]}><Input maxLength={128} /></Form.Item>
    <Form.Item name="enabled" label="允许新签发" valuePropName="checked" extra="停用后仍保留历史证书、撤销能力和 CRL 发布。"><Switch /></Form.Item>
    <PolicyFields /><Button type="primary" htmlType="submit" loading={update.isPending}>保存策略</Button>
  </Form>;
}

function Credentials({ instance }: { instance: SigningInstance }) {
  const now = useCurrentTime();
  const { message } = App.useApp(); const queryClient = useQueryClient();
  const credentials = useQuery({ queryKey: ['signing-credentials', instance.id], queryFn: () => signingAPI.credentials(instance.id) });
  const [open, setOpen] = useState(false); const [token, setToken] = useState<string>();
  const [policyView, setPolicyView] = useState<IssuancePolicy>();
  const [restricted, setRestricted] = useState(false); const [form] = Form.useForm<SigningCredentialInput>();
  const refresh = () => { void queryClient.invalidateQueries({ queryKey: ['signing-credentials', instance.id] }); };
  const create = useMutation({ mutationFn: (input: SigningCredentialInput) => signingAPI.createCredential(instance.id, { ...input, policy: restricted ? input.policy : undefined }), gcTime: 0,
    onSuccess: (result) => { setToken(result.token); setOpen(false); form.resetFields(); create.reset(); refresh(); }, onError: (error) => message.error(error.message) });
  const revoke = useMutation({ mutationFn: (credential: string) => signingAPI.revokeCredential(instance.id, credential), onSuccess: refresh, onError: (error) => message.error(error.message) });
  return <Space orientation="vertical" className="full-width" size="large">
    <Button aria-label="创建凭据" icon={<PlusOutlined />} onClick={() => { setRestricted(false); setOpen(true); }}>创建凭据</Button>
    {credentials.error ? <ErrorAlert error={credentials.error} /> : null}
    <Table rowKey="id" loading={credentials.isPending} dataSource={credentials.data?.items ?? []} scroll={{ x: 850 }} columns={[
      { title: '名称', dataIndex: 'name' }, { title: '权限', render: (_, row) => row.scopes.join(', ') },
      { title: '已签发 / 额度', render: (_, row) => `${row.issued_count} / ${row.max_issuances}` },
      { title: '附加策略', render: (_, row) => row.policy ? <Button onClick={() => setPolicyView(row.policy!)}>查看限制</Button> : <Text type="secondary">继承实例</Text> },
      { title: '每分钟上限', dataIndex: 'rate_per_minute' }, { title: '到期', render: (_, row) => formatDate(row.expires_at) },
      { title: '状态', render: (_, row) => <StatusTag status={row.revoked_at ? 'revoked' : new Date(row.expires_at).getTime() <= now ? 'expired' : 'active'} /> },
      { title: '操作', render: (_, row) => <Popconfirm title="撤销凭据后不能继续使用，已签发证书不自动吊销。" onConfirm={() => revoke.mutate(row.id)}><Button danger disabled={Boolean(row.revoked_at)} loading={revoke.isPending}>撤销凭据</Button></Popconfirm> },
    ]} />
    <Modal open={open} title="创建签发凭据" width={800} onCancel={() => { if (create.isPending) return; setOpen(false); form.resetFields(); create.reset(); }} onOk={() => form.submit()} confirmLoading={create.isPending} okText="创建" okButtonProps={{ 'aria-label': '确认创建凭据' }} cancelText="取消" destroyOnHidden>
      <Form name="signing-credential" form={form} layout="vertical" disabled={create.isPending} initialValues={{ scopes: ['issue', 'read'], lifetime_seconds: 2592000, max_issuances: 1000, rate_per_minute: 10, policy: instance.policy }} onFinish={(input) => create.mutate(input)}>
        <Form.Item name="name" label="凭据名称（建议标注接收方）" rules={[{ required: true, whitespace: true }]}><Input maxLength={128} /></Form.Item>
        <Form.Item name="scopes" label="权限" rules={[{ required: true, type: 'array', min: 1 }]}><Checkbox.Group options={[{ value: 'issue', label: '签发' }, { value: 'read', label: '查询自身证书' }, { value: 'revoke', label: '撤销自身证书' }]} /></Form.Item>
        <Row gutter={16}><Col xs={24} md={8}><Form.Item name="lifetime_seconds" label="凭据有效期（秒）" rules={[{ required: true }]}><InputNumber min={3600} max={7776000} precision={0} className="full-width" /></Form.Item></Col><Col xs={24} md={8}><Form.Item name="max_issuances" label="总签发额度" extra="设置为 1 即一次性签发凭据。" rules={[{ required: true }]}><InputNumber min={1} max={1000000} precision={0} className="full-width" /></Form.Item></Col><Col xs={24} md={8}><Form.Item name="rate_per_minute" label="每分钟签发上限" rules={[{ required: true }]}><InputNumber min={1} max={120} precision={0} className="full-width" /></Form.Item></Col></Row>
        <Form.Item label="叠加凭据专属策略" extra="申请必须同时符合实例策略与此策略，无法扩大实例权限。"><Switch checked={restricted} onChange={setRestricted} /></Form.Item>
        {restricted ? <PolicyFields /> : null}
      </Form>
    </Modal>
    <Modal open={Boolean(policyView)} title="凭据附加策略" width={800} footer={null} onCancel={() => setPolicyView(undefined)} destroyOnHidden>
      {policyView ? <Form name="signing-credential-policy-view" layout="vertical" disabled initialValues={{ policy: policyView }}><PolicyFields /></Form> : null}
    </Modal>
    <Modal open={Boolean(token)} title="保存签发凭据" footer={<Button type="primary" onClick={() => setToken(undefined)}>已安全保存，关闭</Button>} onCancel={() => setToken(undefined)} destroyOnHidden>
      <Alert type="warning" showIcon title="完整凭据仅展示这一次" description="请通过安全渠道交给可信方；关闭后不能找回。不要放入 URL、日志或代码仓库。" />
      {token ? <><Input.TextArea readOnly autoComplete="off" value={token} rows={3} style={{ margin: '16px 0' }} /><CopyButton value={token} label="复制凭据" /></> : null}
    </Modal>
  </Space>;
}

function IssuedCertificates({ id }: { id: string }) {
  const { message } = App.useApp(); const queryClient = useQueryClient();
  const [before, setBefore] = useState(''); const [viewing, setViewing] = useState<IndependentCertificate>();
  const [revoking, setRevoking] = useState<IndependentCertificate>(); const [reason, setReason] = useState(0);
  const certificates = useQuery({ queryKey: ['signing-certificates', id, before], queryFn: () => signingAPI.certificates(id, before) });
  const revoke = useMutation({ mutationFn: () => signingAPI.revoke(id, revoking!.id, reason), onSuccess: () => { setRevoking(undefined); void queryClient.invalidateQueries({ queryKey: ['signing-certificates', id] }); message.success('已吊销，CRL 将按需刷新'); }, onError: (error) => message.error(error.message) });
  return <Space orientation="vertical" className="full-width" size="large">
    {certificates.error ? <ErrorAlert error={certificates.error} /> : null}
    <Table rowKey="id" pagination={false} loading={certificates.isPending} dataSource={certificates.data?.items ?? []} scroll={{ x: 800 }} columns={[
      { title: '序列号', dataIndex: 'serial', ellipsis: true }, { title: '凭据 ID', dataIndex: 'credential_id', ellipsis: true },
      { title: '到期', render: (_, row) => formatDate(row.not_after) }, { title: '状态', render: (_, row) => <StatusTag status={row.status} /> },
      { title: '操作', render: (_, row) => <Space><Button onClick={() => setViewing(row)}>查看 / 下载</Button><Button danger disabled={Boolean(row.revoked_at)} onClick={() => { setReason(0); setRevoking(row); }}>吊销</Button></Space> },
    ]} />
    <Space><Button disabled={!before} onClick={() => setBefore('')}>最新记录</Button><Button disabled={!certificates.data?.next_cursor} onClick={() => setBefore(certificates.data?.next_cursor ?? '')}>更早记录</Button></Space>
    <Modal open={Boolean(viewing)} title="证书链" width={900} footer={null} onCancel={() => setViewing(undefined)} destroyOnHidden>{viewing ? <PEMViewer value={viewing.chain_pem} filename={`${viewing.serial}.chain.pem`} /> : null}</Modal>
    <Modal open={Boolean(revoking)} title="吊销证书" onCancel={() => setRevoking(undefined)} onOk={() => revoke.mutate()} confirmLoading={revoke.isPending} okText="确认吊销" cancelText="取消">
      <Paragraph>吊销不可撤回，状态只由本实例发布。</Paragraph><Select aria-label="吊销原因" className="full-width" value={reason} onChange={setReason} options={[{ value: 0, label: '未指定' }, { value: 1, label: '密钥泄露' }, { value: 3, label: '归属变更' }, { value: 4, label: '已替代' }, { value: 5, label: '停止使用' }, { value: 9, label: '权限撤销' }]} />
    </Modal>
  </Space>;
}

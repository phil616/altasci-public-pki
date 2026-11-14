import { ClockCircleOutlined, DeleteOutlined, DownloadOutlined, KeyOutlined, LinkOutlined, PlusOutlined, SafetyOutlined, UserAddOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { App, Button, Card, Col, Descriptions, Form, Input, InputNumber, Modal, Row, Select, Space, Switch, Table, Tabs, Tag, Typography } from 'antd';
import { useState, type ReactNode } from 'react';
import type { ColumnsType } from 'antd/es/table';
import { Link, useParams } from 'react-router-dom';

import { useAuth } from '@/auth';
import { ErrorAlert, LoadingScreen, PageHeader, PEMViewer, StatusTag } from '@/components/common';
import { consoleAPI, type CreateTimestampAuthorityInput, type SigningProfileInput } from '@/lib/api';
import { formatDate, formatDuration, shortID } from '@/lib/format';
import { can } from '@/lib/permissions';
import type { CAGrant, CertificateAuthority, SigningProfile, TimestampAuthority, User } from '@/types';

const { Paragraph, Text } = Typography;
interface ProfileValues extends Omit<SigningProfileInput, 'default_validity_seconds' | 'max_validity_seconds' | 'policy'> { default_days: number; max_days: number; policy_json: string }
interface TimestampAuthorityValues extends Omit<CreateTimestampAuthorityInput, 'validity_seconds'> { validity_days: number }

export function AuthorityDetailPage() {
  const { id = '' } = useParams();
  const { user } = useAuth();
  const { message, modal } = App.useApp();
  const queryClient = useQueryClient();
  const authority = useQuery({ queryKey: ['authority', id], queryFn: () => consoleAPI.authority(id), enabled: Boolean(id) });
  const profiles = useQuery({ queryKey: ['profiles', id], queryFn: () => consoleAPI.profiles(id), enabled: Boolean(id) });
  const timestampAuthorities = useQuery({ queryKey: ['timestamp-authorities', id], queryFn: () => consoleAPI.timestampAuthorities(id), enabled: Boolean(id) });
  const grants = useQuery({ queryKey: ['grants', id], queryFn: () => consoleAPI.grants(id), enabled: Boolean(id) && can(user?.role, 'manage_grants') });
  const users = useQuery({ queryKey: ['users'], queryFn: consoleAPI.users, enabled: can(user?.role, 'manage_grants') });
  const [profileOpen, setProfileOpen] = useState(false);
  const [editingProfile, setEditingProfile] = useState<SigningProfile>();
  const [grantOpen, setGrantOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [timestampAuthorityOpen, setTimestampAuthorityOpen] = useState(false);
  const [profileForm] = Form.useForm<ProfileValues>();
  const [grantForm] = Form.useForm<{ user_id: string; permission: CAGrant['permission'] }>();
  const [exportForm] = Form.useForm<{ password: string; totp: string }>();
  const [timestampAuthorityForm] = Form.useForm<TimestampAuthorityValues>();

  const profileMutation = useMutation({
    mutationFn: ({ profileID, input }: { profileID?: string; input: SigningProfileInput }) =>
      profileID ? consoleAPI.updateProfile(id, profileID, input) : consoleAPI.createProfile(id, input),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['profiles', id] }); setProfileOpen(false); setEditingProfile(undefined); profileForm.resetFields(); message.success('签发策略已保存'); },
    onError: (error) => message.error(error.message),
  });
  const grantMutation = useMutation({
    mutationFn: (value: { user_id: string; permission: CAGrant['permission'] }) => consoleAPI.createGrant(id, value.user_id, value.permission),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['grants', id] }); setGrantOpen(false); grantForm.resetFields(); message.success('授权已添加'); },
    onError: (error) => message.error(error.message),
  });
  const exportMutation = useMutation({
    mutationFn: (values: { password: string; totp: string }) => consoleAPI.exportCAKey(id, values.password, values.totp),
    onSuccess: () => { setExportOpen(false); exportForm.resetFields(); message.success('私钥已下载，请立即转移到安全介质'); },
    onError: (error) => message.error(error.message),
  });
  const timestampAuthorityMutation = useMutation({
    mutationFn: (values: TimestampAuthorityValues) => {
      const { validity_days, ...input } = values;
      return consoleAPI.createTimestampAuthority(id, { ...input, validity_seconds: validity_days * 86400 });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['timestamp-authorities', id] });
      setTimestampAuthorityOpen(false);
      timestampAuthorityForm.resetFields();
      message.success('时间戳签名单元已创建');
    },
    onError: (error) => message.error(error.message),
  });

  if (authority.isPending || profiles.isPending || timestampAuthorities.isPending) return <LoadingScreen />;
  if (authority.error || profiles.error || timestampAuthorities.error) return <ErrorAlert error={authority.error ?? profiles.error ?? timestampAuthorities.error} />;
  const ca = authority.data;
  const profileItems = profiles.data?.items ?? [];
  const timestampAuthorityItems = timestampAuthorities.data?.items ?? [];
  const operatorUsers = (users.data?.items ?? []).filter((item) => item.role === 'operator' && item.status === 'active');
  const openProfile = (profile?: SigningProfile) => {
    setEditingProfile(profile);
    profileForm.setFieldsValue(profile ? {
      name: profile.name, description: profile.description,
      default_days: profile.default_validity_seconds / 86400, max_days: profile.max_validity_seconds / 86400,
      key_usages: profile.key_usages, extended_key_usages: profile.extended_key_usages,
      allowed_dns_patterns: profile.allowed_dns_patterns, allowed_ip_ranges: profile.allowed_ip_ranges,
      allow_email_sans: profile.allow_email_sans, allow_uri_sans: profile.allow_uri_sans,
      policy_json: JSON.stringify(profile.policy ?? {}, null, 2), enabled: profile.enabled,
    } : { default_days: 90, max_days: 397, key_usages: ['signing', 'key encipherment'], extended_key_usages: ['server auth'], allowed_dns_patterns: [], allowed_ip_ranges: [], allow_email_sans: false, allow_uri_sans: false, policy_json: '{}', enabled: true });
    setProfileOpen(true);
  };
  const submitProfile = (values: ProfileValues) => {
    const { default_days, max_days, policy_json, ...rest } = values;
    let policy: Record<string, unknown>;
    try { policy = JSON.parse(policy_json) as Record<string, unknown>; } catch { profileForm.setFields([{ name: 'policy_json', errors: ['请输入有效 JSON'] }]); return; }
    profileMutation.mutate({ profileID: editingProfile?.id, input: { ...rest, policy, default_validity_seconds: default_days * 86400, max_validity_seconds: max_days * 86400 } });
  };

  const profileColumns: ColumnsType<SigningProfile> = [
    { title: '策略', render: (_, item) => <div><Text strong>{item.name}</Text><div><Text type="secondary">{item.description || '无说明'}</Text></div></div> },
    { title: '默认/最大有效期', render: (_, item) => `${formatDuration(item.default_validity_seconds)} / ${formatDuration(item.max_validity_seconds)}` },
    { title: '用途', responsive: ['lg'], render: (_, item) => <Space wrap>{[...item.key_usages, ...item.extended_key_usages].slice(0, 4).map((usage) => <Tag key={usage}>{usage}</Tag>)}</Space> },
    { title: '状态', dataIndex: 'enabled', render: (enabled: boolean) => <StatusTag status={enabled ? 'active' : 'disabled'} /> },
    { title: '操作', align: 'right', render: (_, item) => can(user?.role, 'manage_profiles') ? <Space><Button onClick={() => openProfile(item)}>编辑</Button><Button danger icon={<DeleteOutlined />} onClick={() => { modal.confirm({ title: `删除策略 ${item.name}？`, content: '默认策略或已被证书申请引用的策略无法删除。', okButtonProps: { danger: true }, onOk: async () => { await consoleAPI.deleteProfile(id, item.id); await queryClient.invalidateQueries({ queryKey: ['profiles', id] }); message.success('策略已删除'); } }); }}>删除</Button></Space> : null },
  ];
  const grantColumns: ColumnsType<CAGrant> = [
    { title: '运维人员', dataIndex: 'user_id', render: (value: string) => operatorUsers.find((item) => item.id === value)?.username ?? shortID(value) },
    { title: '权限', dataIndex: 'permission', render: (value: string) => <Tag>{value}</Tag> },
    { title: '授权时间', dataIndex: 'created_at', render: formatDate },
    { title: '操作', align: 'right', render: (_, item) => <Button danger type="text" onClick={() => void consoleAPI.deleteGrant(id, item.user_id, item.permission).then(() => queryClient.invalidateQueries({ queryKey: ['grants', id] }))}>撤销</Button> },
  ];
  const timestampAuthorityColumns: ColumnsType<TimestampAuthority> = [
    { title: '签名单元', render: (_, item) => <div><Text strong>{item.name}</Text><div><Text type="secondary">{item.slug}</Text></div></div> },
    { title: '策略 OID', dataIndex: 'policy_oid', render: (value: string) => <Text code copyable>{value}</Text> },
    { title: '摘要算法', responsive: ['lg'], render: (_, item) => <Space wrap>{item.allowed_hashes.map((hash) => <Tag key={hash}>{hash}</Tag>)}</Space> },
    { title: '到期时间', dataIndex: 'not_after', responsive: ['md'], render: formatDate },
    { title: '状态', dataIndex: 'status', render: (status: string) => <StatusTag status={status} /> },
    { title: 'RFC 3161 地址', align: 'right', render: (_, item) => <Text copyable={{ text: timestampEndpoint(ca, item.slug) }} code>{timestampEndpoint(ca, item.slug)}</Text> },
  ];

  return (
    <>
      <PageHeader eyebrow={ca.kind === 'root' ? 'ROOT OF TRUST' : 'ISSUING AUTHORITY'} title={ca.name} description={`${ca.subject.common_name} · ${ca.slug}`} actions={<><StatusTag status={ca.kind} /><StatusTag status={ca.status} />{can(user?.role, 'export_ca_key') ? <Button danger icon={<KeyOutlined />} onClick={() => setExportOpen(true)}>导出私钥</Button> : null}</>} />
      <Tabs
        defaultActiveKey="overview"
        items={[
          { key: 'overview', label: '概览', children: <Row gutter={[18, 18]}><Col xs={24} xl={15}><Card className="content-card"><Descriptions column={{ xs: 1, sm: 2 }} items={[
            { key: 'kind', label: '类型', children: <StatusTag status={ca.kind} /> }, { key: 'serial', label: '序列号', children: <Text copyable code>{ca.serial}</Text> },
            { key: 'created', label: '创建时间', children: formatDate(ca.created_at) }, { key: 'expires', label: '到期时间', children: formatDate(ca.not_after) },
            { key: 'path', label: '最大下级深度', children: ca.path_length < 0 ? '无限制' : ca.path_length }, { key: 'parent', label: '上级 CA', children: ca.parent_ca_id ? <Link to={`/authorities/${ca.parent_ca_id}`}>{shortID(ca.parent_ca_id)}</Link> : '自签名信任根' },
          ]} /></Card></Col><Col xs={24} xl={9}><Card className="endpoint-card" title="公开发布端点"><Endpoint icon={<DownloadOutlined />} label="Issuer" value={ca.issuer_url} /><Endpoint icon={<LinkOutlined />} label="CRL" value={ca.crl_url} /><Endpoint icon={<SafetyOutlined />} label="OCSP" value={ca.ocsp_url} /></Card></Col></Row> },
          { key: 'certificate', label: 'CA 证书', children: <Space orientation="vertical" size="large" className="full-width"><PEMViewer value={ca.certificate_pem} filename={`${ca.slug}.pem`} />{ca.chain_pem !== ca.certificate_pem ? <PEMViewer value={ca.chain_pem} filename={`${ca.slug}-chain.pem`} /> : null}</Space> },
          { key: 'profiles', label: `签发策略 (${profileItems.length})`, children: <Card className="content-card" title="签发策略" extra={can(user?.role, 'manage_profiles') ? <Button type="primary" icon={<PlusOutlined />} onClick={() => openProfile()}>新建策略</Button> : null}><Table rowKey="id" columns={profileColumns} dataSource={profileItems} scroll={{ x: 800 }} pagination={false} /></Card> },
          ...(ca.kind === 'intermediate' ? [{ key: 'timestamp-authorities', label: `时间戳服务 (${timestampAuthorityItems.length})`, children: <Card className="content-card" title="RFC 3161 时间戳服务" extra={can(user?.role, 'manage_tsa') ? <Button type="primary" icon={<ClockCircleOutlined />} onClick={() => { timestampAuthorityForm.setFieldsValue({ validity_days: 730 }); setTimestampAuthorityOpen(true); }}>新建签名单元</Button> : null}><Paragraph type="secondary">每个签名单元使用独立 RSA-3072 私钥和只包含 critical timestamping EKU 的证书。服务支持 SHA-256/384/512，并在时间源不健康或落账失败时拒绝签发。</Paragraph><Table rowKey="id" columns={timestampAuthorityColumns} dataSource={timestampAuthorityItems} scroll={{ x: 980 }} pagination={false} /></Card> }] : []),
          ...(can(user?.role, 'manage_grants') && ca.kind === 'intermediate' ? [{ key: 'grants', label: '运维授权', children: <Card className="content-card" title="CA 级权限" extra={<Button type="primary" icon={<UserAddOutlined />} onClick={() => setGrantOpen(true)}>添加授权</Button>}><Paragraph type="secondary">授权仅适用于当前中间 CA，根 CA 权限不可委派。</Paragraph><Table rowKey={(item) => `${item.user_id}:${item.permission}`} columns={grantColumns} dataSource={grants.data?.items ?? []} pagination={false} /></Card> }] : []),
        ]}
      />
      <Modal title={editingProfile ? '编辑签发策略' : '新建签发策略'} open={profileOpen} width={760} onCancel={() => setProfileOpen(false)} onOk={() => profileForm.submit()} confirmLoading={profileMutation.isPending} okText="保存" destroyOnHidden>
        <Form form={profileForm} layout="vertical" requiredMark={false} onFinish={submitProfile}>
          <Row gutter={12}><Col xs={24} md={14}><Form.Item name="name" label="策略名称" tooltip="申请人选择策略时看到的稳定名称，例如 internal-server。" rules={[{ required: true }, { max: 128 }]}><Input /></Form.Item></Col><Col xs={24} md={10}><Form.Item name="enabled" label="允许签发" tooltip="关闭后不能再用于新申请，已有证书不受影响。" valuePropName="checked"><Switch /></Form.Item></Col></Row>
          <Form.Item name="description" label="说明" tooltip="说明该策略面向的证书类型、使用范围和审批要求。"><Input /></Form.Item>
          <Row gutter={12}><Col xs={24} md={12}><Form.Item name="default_days" label="默认有效期（天）" tooltip="申请人不指定有效期时使用的值，必须小于或等于最大有效期。" rules={[{ required: true }]}><InputNumber min={1 / 24} max={397} className="full-width" /></Form.Item></Col><Col xs={24} md={12}><Form.Item name="max_days" label="最大有效期（天）" tooltip="该策略允许签发的硬上限；申请超过此值会被拒绝。" rules={[{ required: true }]}><InputNumber min={1 / 24} max={397} className="full-width" /></Form.Item></Col></Row>
          <Form.Item name="key_usages" label="密钥用途" tooltip="写入 X.509 Key Usage，约束密钥可执行的密码学操作。TLS 服务器常用 digital signature 和 key encipherment。" rules={[{ required: true }]}><Select mode="multiple" options={['signing', 'digital signature', 'key encipherment', 'key agreement', 'data encipherment', 'content commitment'].map((value) => ({ value }))} /></Form.Item>
          <Form.Item name="extended_key_usages" label="扩展密钥用途" tooltip="写入 Extended Key Usage，进一步限制证书用于服务器、客户端、代码签名或邮件等场景。"><Select mode="multiple" options={['server auth', 'client auth', 'code signing', 'email protection', 'timestamping'].map((value) => ({ value }))} /></Form.Item>
          <Form.Item name="allowed_dns_patterns" label="允许的 DNS 模式" tooltip="仅允许匹配这些模式的 DNS SAN。使用明确的内部域名后缀，避免过宽的通配符。" extra="每输入一项后按回车确认，例如 *.example.internal。"><Select mode="tags" tokenSeparators={[',']} placeholder="*.example.internal" /></Form.Item>
          <Form.Item name="allowed_ip_ranges" label="允许的 IP 网段" tooltip="仅允许落在这些 CIDR 网段内的 IP SAN。" extra="每输入一项后按回车确认，例如 10.0.0.0/8。"><Select mode="tags" tokenSeparators={[',']} placeholder="10.0.0.0/8" /></Form.Item>
          <Row gutter={12}><Col xs={24} md={12}><Form.Item name="allow_email_sans" label="允许 Email SAN" tooltip="允许证书包含电子邮箱身份；非邮件证书通常应关闭。" valuePropName="checked"><Switch /></Form.Item></Col><Col xs={24} md={12}><Form.Item name="allow_uri_sans" label="允许 URI SAN" tooltip="允许 SPIFFE 等 URI 身份；仅在业务明确需要时开启。" valuePropName="checked"><Switch /></Form.Item></Col></Row>
          <Form.Item name="policy_json" label="扩展策略 JSON" tooltip="传递给 CFSSL 的高级签发限制。除非需要标准表单未覆盖的能力，否则保持为空对象。" extra="必须是有效 JSON；错误配置可能导致申请被拒绝。"><Input.TextArea className="code-input" rows={5} spellCheck={false} /></Form.Item>
        </Form>
      </Modal>
      <Modal title="添加运维授权" open={grantOpen} onCancel={() => setGrantOpen(false)} onOk={() => grantForm.submit()} confirmLoading={grantMutation.isPending} okText="授权" destroyOnHidden>
        <Form form={grantForm} layout="vertical" onFinish={(values) => grantMutation.mutate(values)} requiredMark={false}>
          <Form.Item name="user_id" label="运维人员" tooltip="授权只作用于当前中间 CA，不会授予其他 CA 或根 CA 权限。" rules={[{ required: true }]}><Select options={operatorUsers.map((item: User) => ({ value: item.id, label: `${item.username}${item.email ? ` · ${item.email}` : ''}` }))} /></Form.Item>
          <Form.Item name="permission" label="权限" tooltip="查看、审批、签发和吊销彼此独立；按最小权限原则分别授予。" rules={[{ required: true }]}><Select options={[{ value: 'view_requests', label: '查看申请与证书' }, { value: 'approve', label: '审批申请' }, { value: 'issue', label: '执行签发' }, { value: 'revoke', label: '吊销证书' }]} /></Form.Item>
        </Form>
      </Modal>
      <Modal title="新建 RFC 3161 时间戳签名单元" open={timestampAuthorityOpen} onCancel={() => setTimestampAuthorityOpen(false)} onOk={() => timestampAuthorityForm.submit()} confirmLoading={timestampAuthorityMutation.isPending} okText="创建" destroyOnHidden>
        <Paragraph type="secondary">签名单元必须挂在活动的中间 CA 下。创建后，客户端通过公开地址提交 application/timestamp-query DER 请求。</Paragraph>
        <Form form={timestampAuthorityForm} layout="vertical" requiredMark={false} onFinish={(values) => timestampAuthorityMutation.mutate(values)}>
          <Form.Item name="name" label="签名单元名称" rules={[{ required: true }, { max: 128 }]}><Input placeholder="Release Time-Stamping Unit" /></Form.Item>
          <Form.Item name="slug" label="公开路径标识" extra="最终地址为 /tsa/{slug}，创建后应保持稳定。" rules={[{ required: true }, { pattern: /^[a-z0-9][a-z0-9-]{1,62}$/, message: '请输入 2-63 位小写字母、数字或连字符' }]}><Input placeholder="release-tsa" /></Form.Item>
          <Form.Item name="policy_oid" label="TSA 策略 OID" tooltip="应使用组织拥有的 OID 分支；请求指定其他策略时服务会返回 unacceptedPolicy。" rules={[{ required: true }, { pattern: /^[0-2](?:\.[0-9]+)+$/, message: '请输入点分十进制 OID' }]}><Input className="code-input" placeholder="1.3.6.1.4.1.你的企业号.1.1" /></Form.Item>
          <Form.Item name="validity_days" label="签名证书有效期（天）" rules={[{ required: true }]}><InputNumber min={1} max={1095} className="full-width" /></Form.Item>
        </Form>
      </Modal>
      <Modal title="导出 CA 私钥" open={exportOpen} onCancel={() => setExportOpen(false)} onOk={() => exportForm.submit()} confirmLoading={exportMutation.isPending} okText="验证并下载" okButtonProps={{ danger: true }} destroyOnHidden>
        <Paragraph type="danger">这是最高风险操作。响应不会缓存，操作会写入审计链；下载后请立即转移到受控安全介质。</Paragraph>
        <Form form={exportForm} layout="vertical" onFinish={(values) => exportMutation.mutate(values)} requiredMark={false}>
          <Form.Item name="password" label="重新输入超级管理员密码" tooltip="用于本次高风险操作的重新认证，不会被记录到日志。" rules={[{ required: true }]}><Input.Password autoComplete="current-password" /></Form.Item>
          <Form.Item name="totp" label="新的六位 TOTP" tooltip="必须使用当前时间窗口内且从未用于其他敏感操作的验证码。" rules={[{ required: true }, { pattern: /^\d{6}$/ }]}><Input maxLength={6} inputMode="numeric" autoComplete="one-time-code" /></Form.Item>
        </Form>
      </Modal>
    </>
  );
}

function Endpoint({ icon, label, value }: { icon: ReactNode; label: string; value?: string | null }) {
  return <div className="endpoint-row"><span>{icon}</span><div><Text type="secondary">{label}</Text>{value ? <Typography.Link href={value} target="_blank" rel="noreferrer">{value}</Typography.Link> : <Text>未配置</Text>}</div></div>;
}

function timestampEndpoint(authority: CertificateAuthority, slug: string): string {
  const publicationURL = authority.issuer_url ?? authority.ocsp_url ?? authority.crl_url;
  if (!publicationURL) return `/tsa/${slug}`;
  try {
    return new URL(`/tsa/${slug}`, publicationURL).toString();
  } catch {
    return `/tsa/${slug}`;
  }
}

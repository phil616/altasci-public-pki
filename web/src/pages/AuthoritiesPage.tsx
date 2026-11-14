import { BankOutlined, BranchesOutlined, PlusOutlined, SafetyCertificateOutlined, UploadOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { App, Button, Card, Col, Form, Input, InputNumber, Modal, Radio, Row, Select, Space, Typography } from 'antd';
import { useState } from 'react';
import { Link } from 'react-router-dom';

import { useAuth } from '@/auth';
import { ErrorAlert, LoadingScreen, PageHeader, StatusTag } from '@/components/common';
import { ImportCAModal } from '@/components/ImportCAModal';
import { consoleAPI, type CreateCAInput } from '@/lib/api';
import { formatDate } from '@/lib/format';
import { can } from '@/lib/permissions';

const { Paragraph, Text, Title } = Typography;
interface CAFormValues extends CreateCAInput { kind: 'root' | 'intermediate' }

export function AuthoritiesPage() {
  const { user } = useAuth();
  const { message } = App.useApp();
  const queryClient = useQueryClient();
  const authorities = useQuery({ queryKey: ['authorities'], queryFn: consoleAPI.authorities });
  const [open, setOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [form] = Form.useForm<CAFormValues>();
  const kind = Form.useWatch('kind', form);
  const create = useMutation({
    mutationFn: (values: CAFormValues) => {
      const { kind: selectedKind, ...input } = values;
      return selectedKind === 'root' ? consoleAPI.createRoot({ ...input, parent_ca_id: undefined }) : consoleAPI.createIntermediate(input);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['authorities'] });
      setOpen(false); form.resetFields(); message.success('证书机构创建完成');
    },
    onError: (error) => message.error(error.message),
  });
  if (authorities.isPending) return <LoadingScreen />;
  if (authorities.error) return <ErrorAlert error={authorities.error} />;
  const items = authorities.data?.items ?? [];
  const roots = items.filter((item) => item.kind === 'root');

  return (
    <>
      <PageHeader
        eyebrow="TRUST ANCHORS"
        title="证书机构"
        description="查看根 CA 与签发中间 CA 的信任层级、有效期和发布端点。"
        actions={can(user?.role, 'create_ca') ? <Space wrap>
          <Button aria-label="导入 CA" icon={<UploadOutlined />} onClick={() => setImportOpen(true)}>导入 CA</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => { form.setFieldsValue({ kind: 'intermediate', path_length: 0 }); setOpen(true); }}>创建 CA</Button>
        </Space> : undefined}
      />
      <div className="trust-overview">
        <div><BankOutlined /><span><strong>{roots.length}</strong><small>根信任锚</small></span></div>
        <div><BranchesOutlined /><span><strong>{items.length - roots.length}</strong><small>中间签发机构</small></span></div>
        <div><SafetyCertificateOutlined /><span><strong>{items.filter((item) => item.status === 'active').length}</strong><small>有效机构</small></span></div>
      </div>
      <Row gutter={[18, 18]}>
        {items.map((ca) => (
          <Col xs={24} md={12} xl={8} key={ca.id}>
            <Link to={`/authorities/${ca.id}`} className="card-link">
              <Card className="ca-card" hoverable>
                <Space orientation="vertical" size="middle" className="full-width">
                  <Space className="full-width" style={{ justifyContent: 'space-between' }}>
                    <div className={`ca-emblem ${ca.kind}`}><BankOutlined /></div>
                    <Space><StatusTag status={ca.kind} /><StatusTag status={ca.status} /></Space>
                  </Space>
                  <div><Title level={4}>{ca.name}</Title><Text code>{ca.slug}</Text></div>
                  <Paragraph ellipsis={{ rows: 2 }} type="secondary">{ca.subject.organization || '—'} · {ca.subject.common_name}</Paragraph>
                  <div className="date-rail"><span>生效于 <strong>{formatDate(ca.not_before)}</strong></span><span>到期于 <strong>{formatDate(ca.not_after)}</strong></span></div>
                </Space>
              </Card>
            </Link>
          </Col>
        ))}
        {!items.length ? <Col span={24}><Card className="empty-authority"><SafetyCertificateOutlined /><Title level={3}>尚未建立信任根</Title><Text type="secondary">超级管理员可以创建或导入根 CA，再创建或导入其下的中间 CA。</Text></Card></Col> : null}
      </Row>
      <Modal title="创建证书机构" open={open} width={680} onCancel={() => setOpen(false)} onOk={() => form.submit()} confirmLoading={create.isPending} okText="创建并生成密钥" cancelText="取消" destroyOnHidden>
        <Form form={form} layout="vertical" requiredMark={false} onFinish={(values) => create.mutate(values)} initialValues={{ kind: 'intermediate', path_length: 0 }}>
          <Form.Item name="kind" label="机构类型" tooltip="根 CA 是信任链起点并自签名；中间 CA 由上级 CA 签发，通常用于日常签发。" rules={[{ required: true }]}><Radio.Group optionType="button" buttonStyle="solid" options={[{ value: 'root', label: '根 CA' }, { value: 'intermediate', label: '中间 CA' }]} /></Form.Item>
          {kind === 'intermediate' ? <Form.Item name="parent_ca_id" label="上级 CA" tooltip="新 CA 的证书将由此根机构签发。仅有效且仍允许下级 CA 的根机构可选。" rules={[{ required: true }]}><Select placeholder="选择可签发中间 CA 的根机构" options={items.filter((ca) => ca.kind === 'root' && ca.status === 'active' && ca.path_length !== 0).map((ca) => ({ value: ca.id, label: `${ca.name} (${ca.slug})` }))} /></Form.Item> : null}
          <Row gutter={12}>
            <Col xs={24} md={14}><Form.Item name="name" label="显示名称" tooltip="供控制台和公开 CA 目录展示，建议使用能表达环境和用途的名称。" rules={[{ required: true }]}><Input placeholder="Enterprise Issuing CA" /></Form.Item></Col>
            <Col xs={24} md={10}><Form.Item name="slug" label="公开标识" tooltip="稳定、URL 安全的唯一名称，将出现在 Issuer、CRL 和 OCSP 等公开地址中。" extra="创建后应视为永久标识，例如 enterprise-issuing。" rules={[{ required: true }, { pattern: /^[a-z0-9][a-z0-9-]{1,62}$/, message: '仅允许小写字母、数字和连字符' }]}><Input placeholder="enterprise-issuing" /></Form.Item></Col>
          </Row>
          <Form.Item name="path_length" label="最大下级 CA 深度" tooltip="对应 X.509 Basic Constraints 的 pathLenConstraint：此 CA 之后最多还能出现多少层中间 CA。" extra="0 表示只能签发终端证书，不能再签发中间 CA；1 表示最多再允许一层中间 CA。" rules={[{ required: true }]}><InputNumber min={0} max={5} className="full-width" /></Form.Item>
          <Title level={5}>X.509 主题</Title>
          <Form.Item name={['subject', 'common_name']} label="通用名称（CN）" tooltip="写入证书 Subject 的 Common Name，用于标识该 CA。" extra="建议包含组织、环境和层级，例如 Greenshade Test Issuing CA 01。" rules={[{ required: true }]}><Input /></Form.Item>
          <Row gutter={12}>
            <Col xs={24} md={12}><Form.Item name={['subject', 'organization']} label="组织（O）" tooltip="证书所属的法定组织或企业名称。"><Input /></Form.Item></Col>
            <Col xs={24} md={12}><Form.Item name={['subject', 'organizational_unit']} label="组织单位（OU）" tooltip="负责运营该 CA 的部门或团队，例如 Security Engineering。"><Input /></Form.Item></Col>
            <Col xs={24} md={8}><Form.Item name={['subject', 'country']} label="国家（C）" tooltip="两位 ISO 3166-1 国家或地区代码，例如 CN、US。"><Input maxLength={2} placeholder="CN" /></Form.Item></Col>
            <Col xs={24} md={8}><Form.Item name={['subject', 'province']} label="省/州（ST）" tooltip="组织注册或运营所在地的省、州。"><Input /></Form.Item></Col>
            <Col xs={24} md={8}><Form.Item name={['subject', 'locality']} label="城市（L）" tooltip="组织注册或运营所在地的城市。"><Input /></Form.Item></Col>
          </Row>
          <AlertCAWarning kind={kind} />
        </Form>
      </Modal>
      <ImportCAModal open={importOpen} onClose={() => setImportOpen(false)} authorities={items} />
    </>
  );
}

function AlertCAWarning({ kind }: { kind?: string }) {
  return <Card size="small" className="inline-warning"><Text strong>{kind === 'root' ? '根 CA 密钥属于最高敏感级别。' : '中间 CA 将由所选上级 CA 立即签发。'}</Text><br /><Text type="secondary">私钥会使用环境主密钥进行 AES-256-GCM 信封加密后存入 PostgreSQL。</Text></Card>;
}

import { FileSearchOutlined, PartitionOutlined, ToolOutlined } from '@ant-design/icons';
import { useMutation } from '@tanstack/react-query';
import { App, Button, Card, Col, Form, Input, Radio, Row, Select, Space, Tabs, Typography } from 'antd';
import { useState } from 'react';

import { PageHeader, PEMViewer } from '@/components/common';
import { consoleAPI } from '@/lib/api';
import type { Subject } from '@/types';

const { Text } = Typography;

export function UtilitiesPage() {
  return (
    <>
      <PageHeader eyebrow="CFSSL TOOLKIT" title="PKI 工具" description="通过受认证的标准接口解析证书、生成 CSR 与优化证书链。" />
      <Card className="content-card"><Tabs items={[
        { key: 'certinfo', label: <Space><FileSearchOutlined />证书解析</Space>, children: <CertInfoTool /> },
        { key: 'csr', label: <Space><ToolOutlined />CSR 生成</Space>, children: <CSRTool /> },
        { key: 'bundle', label: <Space><PartitionOutlined />证书链优化</Space>, children: <BundleTool /> },
      ]} /></Card>
    </>
  );
}

function CertInfoTool() {
  const { message } = App.useApp();
  const [result, setResult] = useState<Record<string, unknown>>();
  const mutation = useMutation({ mutationFn: consoleAPI.certInfo, onSuccess: setResult, onError: (error) => message.error(error.message) });
  return <Row gutter={[24, 24]}><Col xs={24} lg={12}><Form layout="vertical" onFinish={({ pem }: { pem: string }) => mutation.mutate(pem)}><Form.Item name="pem" label="X.509 证书 PEM" tooltip="粘贴包含 BEGIN CERTIFICATE 和 END CERTIFICATE 边界的完整 PEM 证书。" rules={[{ required: true }]}><Input.TextArea className="code-input" rows={16} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" /></Form.Item><Button type="primary" htmlType="submit" loading={mutation.isPending}>解析证书</Button></Form></Col><Col xs={24} lg={12}>{result ? <pre className="json-block result-block">{JSON.stringify(result, null, 2)}</pre> : <ToolPlaceholder text="解析结果会显示在这里" />}</Col></Row>;
}

function CSRTool() {
  const { message } = App.useApp();
  const [result, setResult] = useState<{ csr_pem: string; private_key_pem: string }>();
  const [algorithm, setAlgorithm] = useState('rsa');
  const mutation = useMutation({ mutationFn: consoleAPI.generateCSR, onSuccess: setResult, onError: (error) => message.error(error.message) });
  return <Space orientation="vertical" size="large" className="full-width"><Form layout="vertical" initialValues={{ algorithm: 'rsa', key_size: 3072 }} onFinish={(values: { subject: Subject; sans?: string[]; algorithm: string; key_size: number }) => mutation.mutate({ ...values, sans: values.sans ?? [] })}>
    <Row gutter={12}><Col xs={24} md={12}><Form.Item name={['subject', 'common_name']} label="通用名称（CN）" tooltip="CSR Subject 中的主要名称；TLS 主机名还必须加入 SAN。" rules={[{ required: true }]}><Input /></Form.Item></Col><Col xs={24} md={12}><Form.Item name={['subject', 'organization']} label="组织（O）" tooltip="申请者所属的组织或企业名称。"><Input /></Form.Item></Col></Row>
    <Form.Item name="sans" label="主题备用名称（SAN）" tooltip="希望写入证书的 DNS 名、IP、邮箱或 URI；每项输入后按回车确认。"><Select mode="tags" tokenSeparators={[',']} /></Form.Item>
    <Row gutter={12}><Col xs={24} md={12}><Form.Item name="algorithm" label="密钥算法" tooltip="RSA 兼容性更广；ECDSA 密钥和签名更小，但使用方必须支持相应曲线。"><Radio.Group value={algorithm} onChange={(event) => setAlgorithm(event.target.value as string)} options={[{ value: 'rsa', label: 'RSA' }, { value: 'ecdsa', label: 'ECDSA' }]} /></Form.Item></Col><Col xs={24} md={12}><Form.Item name="key_size" label="密钥参数" tooltip="RSA 推荐至少 3072 位；ECDSA P-256 适合大多数现代客户端，P-384 提供更高安全余量。"><Select options={(algorithm === 'rsa' ? [3072, 4096] : [256, 384]).map((value) => ({ value, label: algorithm === 'rsa' ? `${value} bits` : `P-${value}` }))} /></Form.Item></Col></Row>
    <Button type="primary" htmlType="submit" loading={mutation.isPending}>生成 CSR 与私钥</Button>
  </Form>{result ? <><PEMViewer value={result.csr_pem} filename="request.csr.pem" /><PEMViewer value={result.private_key_pem} filename="private-key.pem" /></> : null}</Space>;
}

function BundleTool() {
  const { message } = App.useApp();
  const [result, setResult] = useState<Record<string, unknown>>();
  const mutation = useMutation({ mutationFn: consoleAPI.bundle, onSuccess: setResult, onError: (error) => message.error(error.message) });
  return <Space orientation="vertical" size="large" className="full-width"><Form layout="vertical" initialValues={{ flavor: 'optimal', roots_pem: '', intermediates_pem: '' }} onFinish={(values) => mutation.mutate(values as { certificates_pem: string; roots_pem: string; intermediates_pem: string; flavor: string })}>
    <Form.Item name="certificates_pem" label="待优化证书" tooltip="需要构建或重排证书链的叶证书及已有链，使用 PEM 格式。" rules={[{ required: true }]}><Input.TextArea className="code-input" rows={8} /></Form.Item>
    <Row gutter={12}><Col xs={24} lg={12}><Form.Item name="intermediates_pem" label="中间证书（可选）" tooltip="用于补全链的候选中间 CA 证书，可包含多张 PEM。" extra="请一并提供缺失的中间证书，系统不会自动下载证书。"><Input.TextArea className="code-input" rows={6} /></Form.Item></Col><Col xs={24} lg={12}><Form.Item name="roots_pem" label="信任根（可选）" tooltip="构建链时允许信任的根 CA 集合；省略时使用服务端配置的信任来源。"><Input.TextArea className="code-input" rows={6} /></Form.Item></Col></Row>
    <Form.Item name="flavor" label="优化模式" tooltip="optimal 选择较短且现代的链；ubiquitous 偏向广泛客户端兼容；force 强制返回可构建结果。"><Select options={[{ value: 'optimal', label: 'optimal · 现代最优链' }, { value: 'ubiquitous', label: 'ubiquitous · 广泛兼容' }, { value: 'force', label: 'force · 强制构建' }]} /></Form.Item>
    <Button type="primary" htmlType="submit" loading={mutation.isPending}>生成优化链</Button>
  </Form>{result ? <pre className="json-block result-block">{JSON.stringify(result, null, 2)}</pre> : null}</Space>;
}

function ToolPlaceholder({ text }: { text: string }) { return <div className="tool-placeholder"><ToolOutlined /><Text type="secondary">{text}</Text></div>; }

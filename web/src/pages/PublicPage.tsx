import { ArrowRightOutlined, BankOutlined, CheckCircleFilled, DownloadOutlined, GlobalOutlined, SafetyCertificateFilled, SearchOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Card, Col, Descriptions, Flex, Form, Input, Radio, Row, Space, Tag, Typography } from 'antd';
import { useState } from 'react';
import { Link, Outlet, useParams } from 'react-router-dom';

import { ErrorAlert, LoadingScreen, PEMViewer, StatusTag } from '@/components/common';
import { publicAPI } from '@/lib/api';
import { formatDate } from '@/lib/format';
import type { Certificate, CertificateStatus } from '@/types';

const { Paragraph, Text, Title } = Typography;

export function PublicLayout() {
  return (
    <div className="public-shell">
      <header className="public-nav">
        <Link to="/" className="public-brand"><span><SafetyCertificateFilled /></span><div>PKI-Console<small>Public PKI Web Service</small></div></Link>
        <nav><Link to="/">信任机构</Link><Link to="/lookup">证书查询</Link><a href="/health/live" target="_blank" rel="noreferrer">服务状态</a><Link to="/about">关于 PKI</Link></nav>
      </header>
      <Outlet />
      <footer className="public-footer"><div><SafetyCertificateFilled /> PKI-Console</div><Text>公开信息仅支持精确查询，不提供叶证书目录枚举。</Text><Text>CRL · OCSP · AIA</Text></footer>
    </div>
  );
}

export function PublicHomePage() {
  const authorities = useQuery({ queryKey: ['public-authorities'], queryFn: publicAPI.authorities, staleTime: 60_000 });
  return (
    <main>
      <section className="public-hero">
        <div className="public-hero-copy">
          <Text className="eyebrow light">AltasCI Public PKI</Text>
          <Title>AltasCI PKI<br /><span>公共密钥基础设施</span></Title>
          <Paragraph>查询证书状态、下载签发机构证书与吊销列表，或将本服务作为证书中的 AIA、CRL 与 OCSP 公开端点。</Paragraph>
          <Space wrap><Button type="primary" size="large" icon={<SearchOutlined />} href="/lookup">精确查询证书</Button><Button size="large" href="#authorities">浏览 CA 证书</Button></Space>
          <div className="public-proof"><span><CheckCircleFilled /> 精确查询</span><span><CheckCircleFilled /> RFC 5280 CRL</span><span><CheckCircleFilled /> RFC 6960 OCSP</span></div>
        </div>
        <div className="public-service-note">
          <SafetyCertificateFilled />
          <div><Text strong>公开 PKI 验证服务</Text><Paragraph>提供签发者证书、CRL、OCSP 和证书精确查询。叶证书不可枚举。</Paragraph></div>
        </div>
      </section>
      <section id="authorities" className="public-section">
        <Flex justify="space-between" align="end" wrap gap="large" className="section-heading"><div><Text className="eyebrow">TRUST ANCHORS</Text><Title level={2}>证书机构目录</Title><Paragraph>下载 DER 编码的签发者证书和最新证书吊销列表。</Paragraph></div><Tag color="green" icon={<GlobalOutlined />}>公开可访问</Tag></Flex>
        {authorities.isPending ? <LoadingScreen compact /> : authorities.error ? <ErrorAlert error={authorities.error} /> : <Row gutter={[18, 18]}>{(authorities.data?.items ?? []).map((ca) => <Col xs={24} md={12} key={ca.id}><Card className="public-ca-card"><Flex gap="large" align="flex-start"><div className={`public-ca-icon ${ca.kind}`}><BankOutlined /></div><div className="grow"><Flex justify="space-between" gap="small" wrap><Title level={4}>{ca.name}</Title><StatusTag status={ca.kind} /></Flex><Text code>{ca.slug}</Text><Paragraph type="secondary">{ca.subject.common_name}<br />有效期至 {formatDate(ca.not_after)}</Paragraph><Space wrap><Button icon={<DownloadOutlined />} href={`/issuers/${ca.slug}.cer`}>Issuer DER</Button><Button icon={<DownloadOutlined />} href={`/crl/${ca.slug}.crl`}>CRL</Button></Space></div></Flex></Card></Col>)}</Row>}
      </section>
      <section className="public-explainer"><div><Text className="eyebrow light">PRIVACY BY DESIGN</Text><Title level={2}>AltasCI提供PKI基础设施</Title></div><Paragraph>本目录不会暴露可遍历的叶证书列表。只有持有 SHA-256 指纹，或明确知道签发者与序列号的请求方才能获取证书记录。</Paragraph><Button href="/lookup" icon={<ArrowRightOutlined />}>开始精确查询</Button></section>
    </main>
  );
}

export function PublicAboutPage() {
  return (
    <main className="lookup-page public-about-page">
      <div className="lookup-heading">
        <Text className="eyebrow">ABOUT PKI-CONSOLE</Text>
        <Title>关于 PKI</Title>
      </div>
      <Card className="lookup-card public-about-card">
        <Paragraph>AltasCI PKI是基于 Cloudflare CFSSL 源码构建的企业级 PKI 系统，提供证书签发、查询、吊销和公开验证服务。</Paragraph>
        <Paragraph>AltasCI Public PKI作为主要公钥基础设施向AltasCI其他应用和场景提供公钥基础设施服务.</Paragraph>
        <a className="public-about-link" href="https://example.com" target="_blank" rel="noreferrer">了解更多关于AltasCI PKI <ArrowRightOutlined /></a>
        <br></br>
        <a className="public-about-link" href="https://example.com" target="_blank" rel="noreferrer">了解更多关于Cloudflare CFSSL <ArrowRightOutlined /></a>
      </Card>
    </main>
  );
}

interface LookupValues { method: 'fingerprint' | 'serial'; fingerprint?: string; issuer?: string; serial?: string }

export function PublicLookupPage() {
  const [form] = Form.useForm<LookupValues>();
  const method = Form.useWatch('method', form);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>();
  const [certificate, setCertificate] = useState<Certificate>();
  const [status, setStatus] = useState<CertificateStatus>();
  const submit = async (values: LookupValues) => {
    setLoading(true); setError(undefined); setCertificate(undefined); setStatus(undefined);
    try {
      if (values.method === 'fingerprint') setCertificate(await publicAPI.byFingerprint(values.fingerprint!.replaceAll(':', '')));
      else {
        const [cert, state] = await Promise.all([publicAPI.bySerial(values.issuer!, values.serial!), publicAPI.status(values.issuer!, values.serial!)]);
        setCertificate(cert); setStatus(state);
      }
    } catch (reason) { setError(reason); } finally { setLoading(false); }
  };
  return (
    <main className="lookup-page">
      <div className="lookup-heading"><Text className="eyebrow">EXACT CERTIFICATE LOOKUP</Text><Title>证书与状态查询</Title><Paragraph>使用证书 SHA-256 指纹，或签发机构标识与十进制序列号进行精确匹配。</Paragraph></div>
      <Card className="lookup-card">
        <Form form={form} layout="vertical" initialValues={{ method: 'fingerprint' }} onFinish={(values) => void submit(values)} requiredMark={false}>
          <Form.Item name="method" label="查询方式" tooltip="指纹可唯一定位证书；签发者与序列号适合从证书内容或审计记录中查询。"><Radio.Group optionType="button" buttonStyle="solid" options={[{ value: 'fingerprint', label: 'SHA-256 指纹' }, { value: 'serial', label: '签发者 + 序列号' }]} /></Form.Item>
          {method === 'serial' ? <Row gutter={12}><Col xs={24} md={12}><Form.Item name="issuer" label="签发机构公开标识" tooltip="签发 CA 的稳定 slug，可从证书机构目录或 AIA/CRL 地址中取得。" rules={[{ required: true }]}><Input placeholder="enterprise-issuing" /></Form.Item></Col><Col xs={24} md={12}><Form.Item name="serial" label="十进制序列号" tooltip="证书 Serial Number 转换为十进制后的完整值，不要省略前导有效数字。" rules={[{ required: true }, { pattern: /^\d+$/, message: '仅允许十进制数字' }]}><Input /></Form.Item></Col></Row> : <Form.Item name="fingerprint" label="SHA-256 指纹" tooltip="证书 DER 数据的 SHA-256 摘要，接受连续 64 位十六进制或冒号分隔格式。" rules={[{ required: true }, { validator: (_, value: string) => /^[a-fA-F0-9:]{64,95}$/.test(value ?? '') ? Promise.resolve() : Promise.reject(new Error('请输入 64 位十六进制 SHA-256 指纹')) }]}><Input className="fingerprint-input" placeholder="9f:2a:…" /></Form.Item>}
          <Button type="primary" htmlType="submit" icon={<SearchOutlined />} loading={loading}>查询</Button>
        </Form>
      </Card>
      {error ? <ErrorAlert error={error} title="未找到匹配证书" /> : null}
      {certificate ? <PublicCertificateResult certificate={certificate} status={status} /> : null}
    </main>
  );
}

export function PublicCertificatePage() {
  const { fingerprint = '' } = useParams();
  const certificate = useQuery({ queryKey: ['public-certificate', fingerprint], queryFn: () => publicAPI.byFingerprint(fingerprint), enabled: Boolean(fingerprint) });
  if (certificate.isPending) return <main className="lookup-page"><LoadingScreen /></main>;
  if (certificate.error) return <main className="lookup-page"><ErrorAlert error={certificate.error} title="证书不存在" /></main>;
  return <main className="lookup-page"><PublicCertificateResult certificate={certificate.data} /></main>;
}

function PublicCertificateResult({ certificate, status }: { certificate: Certificate; status?: CertificateStatus }) {
  const effectiveStatus = status?.status ?? certificate.status;
  return <Space orientation="vertical" size="large" className="lookup-result"><Alert showIcon type={effectiveStatus === 'good' ? 'success' : effectiveStatus === 'revoked' ? 'error' : 'warning'} title={`证书状态：${effectiveStatus.toUpperCase()}`} description={effectiveStatus === 'good' ? '该证书当前处于有效状态。调用方仍应验证证书链、用途和有效期。' : '请勿继续信任该证书。'} /><Card><Flex justify="space-between" align="start" wrap gap="middle"><div><Text className="eyebrow">CERTIFICATE RECORD</Text><Title level={3}>{certificate.subject?.common_name || certificate.serial}</Title></div><StatusTag status={effectiveStatus} /></Flex><Descriptions column={{ xs: 1, md: 2 }} items={[
    { key: 'serial', label: '序列号', children: certificate.serial }, { key: 'issuer', label: '签发机构 ID', children: certificate.issuer_ca_id },
    { key: 'before', label: '生效时间', children: formatDate(certificate.not_before) }, { key: 'after', label: '到期时间', children: formatDate(certificate.not_after) },
    { key: 'sans', label: 'SAN', span: 2, children: certificate.sans?.join(', ') || '—' }, { key: 'fingerprint', label: 'SHA-256 指纹', span: 2, children: <Text code copyable className="break-all">{certificate.fingerprint_sha256}</Text> },
  ]} /></Card><PEMViewer value={certificate.certificate_pem} filename={`${certificate.serial}.pem`} /></Space>;
}

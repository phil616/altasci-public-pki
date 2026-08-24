import { ArrowRightOutlined, BankOutlined, CheckCircleFilled, ClockCircleOutlined, FileProtectOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Button, Card, Col, Empty, Flex, Progress, Row, Space, Statistic, Tag, Typography } from 'antd';
import { Link } from 'react-router-dom';

import { useAuth } from '@/auth';
import { ErrorAlert, LoadingScreen, PageHeader, StatusTag } from '@/components/common';
import { consoleAPI } from '@/lib/api';
import { formatDate, roleLabels, shortID } from '@/lib/format';

const { Text, Title } = Typography;

export function DashboardPage() {
  const { user } = useAuth();
  const authorities = useQuery({ queryKey: ['authorities'], queryFn: consoleAPI.authorities });
  const requests = useQuery({ queryKey: ['requests'], queryFn: consoleAPI.requests, refetchInterval: 10_000 });
  const certificates = useQuery({ queryKey: ['certificates'], queryFn: consoleAPI.certificates, refetchInterval: 15_000 });
  const version = useQuery({ queryKey: ['version'], queryFn: consoleAPI.version, staleTime: Infinity });
  if (authorities.isPending || requests.isPending || certificates.isPending) return <LoadingScreen />;
  if (authorities.error || requests.error || certificates.error) return <ErrorAlert error={authorities.error ?? requests.error ?? certificates.error} />;

  const cas = authorities.data?.items ?? [];
  const requestItems = requests.data?.items ?? [];
  const certs = certificates.data?.items ?? [];
  const pending = requestItems.filter((item) => item.status === 'pending').length;
  const revoked = certs.filter((item) => item.status === 'revoked').length;
  const healthyRatio = certs.length ? Math.round(((certs.length - revoked) / certs.length) * 100) : 100;

  return (
    <>
      <PageHeader
        eyebrow="OVERVIEW"
        title={`欢迎回来，${user?.username ?? ''}`}
        description={`${user ? roleLabels[user.role] : ''}视图 · 证书基础设施实时概览`}
        actions={<Tag color="green" icon={<CheckCircleFilled />}>系统在线 · {version.data?.version ?? 'dev'}</Tag>}
      />
      <Row gutter={[18, 18]}>
        <Col xs={24} sm={12} xl={6}><Card className="stat-card mint"><Statistic title="证书机构" value={cas.length} prefix={<BankOutlined />} suffix={<Text type="secondary">个</Text>} /><Text type="secondary">根 CA {cas.filter((ca) => ca.kind === 'root').length} · 中间 CA {cas.filter((ca) => ca.kind === 'intermediate').length}</Text></Card></Col>
        <Col xs={24} sm={12} xl={6}><Card className="stat-card blue"><Statistic title="待处理申请" value={pending} prefix={<ClockCircleOutlined />} suffix={<Text type="secondary">项</Text>} /><Link to="/requests">查看审批队列 <ArrowRightOutlined /></Link></Card></Col>
        <Col xs={24} sm={12} xl={6}><Card className="stat-card amber"><Statistic title="可见证书" value={certs.length} prefix={<SafetyCertificateOutlined />} suffix={<Text type="secondary">张</Text>} /><Text type="secondary">吊销 {revoked} 张</Text></Card></Col>
        <Col xs={24} sm={12} xl={6}><Card className="stat-card violet"><Statistic title="证书健康度" value={healthyRatio} suffix="%" /><Progress percent={healthyRatio} showInfo={false} strokeColor="#6f5bd3" /></Card></Col>
      </Row>
      <Row gutter={[18, 18]} className="dashboard-grid">
        <Col xs={24} xl={14}>
          <Card className="content-card" title={<Space><FileProtectOutlined />最近证书申请</Space>} extra={<Link to="/requests">全部申请</Link>}>
            {requestItems.length ? (
              <ul className="dashboard-request-list">
                {requestItems.slice(0, 6).map((item) => (
                  <li key={item.id}>
                    <div className="list-icon"><FileProtectOutlined /></div>
                    <div className="grow">
                      <Flex gap="small" align="center" wrap><Text strong>{item.requested_subject?.common_name || 'CSR 证书申请'}</Text><StatusTag status={item.status} /></Flex>
                      <Text type="secondary">{formatDate(item.submitted_at)} · {item.key_generation_mode === 'server_generated' ? '服务端生成密钥' : '客户端 CSR'} · {shortID(item.id)}</Text>
                    </div>
                    <Link to={`/requests/${item.id}`}>查看</Link>
                  </li>
                ))}
              </ul>
            ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无证书申请" />}
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card className="content-card" title="信任层级" extra={<Link to="/authorities">管理 CA</Link>}>
            <div className="trust-stack">
              {cas.slice(0, 5).map((ca) => (
                <Link className="trust-row" to={`/authorities/${ca.id}`} key={ca.id}>
                  <div className={`trust-node ${ca.kind}`}><BankOutlined /></div>
                  <div className="trust-copy"><Text strong>{ca.name}</Text><Text type="secondary">{ca.slug} · 至 {formatDate(ca.not_after)}</Text></div>
                  <StatusTag status={ca.kind} />
                </Link>
              ))}
              {!cas.length ? <Flex vertical align="center" gap="middle" className="empty-compact"><Text type="secondary">尚未创建 CA</Text><Button type="primary" href="/authorities">开始建立信任根</Button></Flex> : null}
            </div>
          </Card>
          <Card className="security-note" variant="borderless">
            <Space align="start"><SafetyCertificateOutlined /><div><Title level={5}>密钥始终加密封装</Title><Text>CA 与 OCSP 私钥使用版本化 AES-256-GCM 信封存储，主密钥仅存在于进程环境。</Text></div></Space>
          </Card>
        </Col>
      </Row>
    </>
  );
}

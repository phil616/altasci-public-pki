import { CloudServerOutlined, LockOutlined, MailOutlined, SafetyCertificateFilled, SafetyOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Checkbox, Flex, Form, Input, Space, Typography } from 'antd';
import { useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '@/auth';
import { APIError } from '@/lib/api';

const { Paragraph, Text, Title } = Typography;

interface LoginValues { login: string; password: string; totp?: string; rootLogin?: boolean }

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [rootLogin, setRootLogin] = useState(false);
  const [error, setError] = useState<string>();
  const [submitting, setSubmitting] = useState(false);
  if (user) return <Navigate to="/" replace />;

  const submit = async (values: LoginValues) => {
    setSubmitting(true);
    setError(undefined);
    try {
      await login({ login: values.login, password: values.password, totp: rootLogin ? values.totp : undefined });
      const target = (location.state as { from?: string } | null)?.from ?? '/';
      void navigate(target, { replace: true });
    } catch (reason) {
      setError(reason instanceof APIError ? reason.message : '登录失败，请稍后重试');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="login-shell">
      <section className="login-story">
        <div className="login-brand"><SafetyCertificateFilled /><span>PKI-Console</span></div>
        <div className="login-story-copy">
          <Text className="eyebrow light">AltasCI PKI Managemeng Console(Web Version)</Text>
          <Title>AltasCI PKI Web管理平台</Title>
          <Paragraph>基于 CFSSL 源码构建的企业级证书控制平面，覆盖 CA 生命周期、审批、吊销、OCSP 与审计链。</Paragraph>
        </div>
        <div className="security-strip">
          <div><SafetyOutlined /><span><strong>可信入口</strong><small>受到Cloudflare的Access保护</small></span></div>
          <div><CloudServerOutlined /><span><strong>ZTA安全</strong><small>未经授权不得访问PKI设施</small></span></div>
        </div>
      </section>
      <section className="login-panel">
        <Card className="login-card" variant="borderless">
          <Space orientation="vertical" size={4} className="login-heading">
            <Text className="eyebrow">SECURE SIGN IN</Text>
            <Title level={2}>登录控制台</Title>
            <Text type="secondary">使用 PKI-Console 本地账户继续</Text>
          </Space>
          {error ? <Alert type="error" showIcon title="认证未通过" description={error} closable onClose={() => setError(undefined)} /> : null}
          <Form<LoginValues> layout="vertical" requiredMark={false} onFinish={(values) => void submit(values)} size="large">
            <Form.Item label="用户名或邮箱" name="login" rules={[{ required: true, message: '请输入用户名或邮箱' }]}>
              <Input autoComplete="username" prefix={<MailOutlined />} placeholder="alice@example.com" autoFocus />
            </Form.Item>
            <Form.Item label="密码" name="password" rules={[{ required: true, message: '请输入密码' }]}>
              <Input.Password autoComplete="current-password" prefix={<LockOutlined />} placeholder="输入账户密码" />
            </Form.Item>
            <Checkbox checked={rootLogin} onChange={(event) => setRootLogin(event.target.checked)}>超级管理员登录</Checkbox>
            {rootLogin ? (
              <>
                <Form.Item label="六位动态验证码" name="totp" rules={[{ required: true, pattern: /^\d{6}$/, message: '请输入六位 TOTP 验证码' }]}>
                  <Input inputMode="numeric" autoComplete="one-time-code" maxLength={6} prefix={<SafetyOutlined />} placeholder="000000" />
                </Form.Item>
                <Alert type="info" showIcon title="Cloudflare Access 验证由接入层注入，邮箱必须与根账户一致。" />
              </>
            ) : null}
            <Button block type="primary" htmlType="submit" loading={submitting}>安全登录</Button>
          </Form>
          <Flex justify="center"><Text type="secondary" className="login-footnote">受保护的操作会写入不可变审计链</Text></Flex>
        </Card>
      </section>
    </main>
  );
}

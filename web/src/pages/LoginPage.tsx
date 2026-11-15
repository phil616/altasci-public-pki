import { CloudServerOutlined, LockOutlined, MailOutlined, SafetyCertificateFilled, SafetyOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Flex, Form, Input, Space, Typography } from 'antd';
import { useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '@/auth';
import { APIError } from '@/lib/api';

const { Paragraph, Text, Title } = Typography;

interface LoginValues { login: string; password: string }

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState<string>();
  const [submitting, setSubmitting] = useState(false);
  if (user) return <Navigate to="/" replace />;

  const submit = async (values: LoginValues) => {
    setSubmitting(true);
    setError(undefined);
    try {
      await login({ login: values.login, password: values.password });
      const target = (location.state as { from?: string } | null)?.from ?? '/';
      void navigate(target, { replace: true });
    } catch (reason) {
      const messages: Record<string, string> = {
        invalid_credentials: '用户名或密码不正确，或账户已被禁用。',
        account_locked: '密码正确，但账户仍在锁定期。请停止重试，等待锁定到期后再使用新验证码。',
        authentication_unavailable: '认证服务暂时不可用，请稍后重试，并通过请求编号检查服务端日志。',
        origin_not_allowed: '访问地址与服务端配置的管理地址不一致，请使用正确的管理域名。',
        rate_limited: '登录尝试过于频繁，请稍后重试。',
      };
      setError(reason instanceof APIError
        ? `${messages[reason.code] ?? reason.message}${reason.requestID ? `（请求编号：${reason.requestID}）` : ''}`
        : '登录失败，请检查网络连接后重试');
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
          <div><SafetyOutlined /><span><strong>本地认证</strong><small>所有账户统一使用用户名与密码</small></span></div>
          <div><CloudServerOutlined /><span><strong>权限控制</strong><small>未经授权不得访问PKI设施</small></span></div>
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
            <Button block type="primary" htmlType="submit" loading={submitting}>安全登录</Button>
          </Form>
          <Flex justify="center"><Text type="secondary" className="login-footnote">受保护的操作会写入不可变审计链</Text></Flex>
        </Card>
      </section>
    </main>
  );
}

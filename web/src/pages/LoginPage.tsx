import { CloudServerOutlined, LockOutlined, MailOutlined, SafetyCertificateFilled, SafetyOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Flex, Form, Input, Space, Typography } from 'antd';
import { useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '@/auth';
import { APIError } from '@/lib/api';

const { Paragraph, Text, Title } = Typography;

interface LoginValues { login: string; password: string; totp?: string }

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
      await login({ login: values.login, password: values.password, totp: values.totp || undefined });
      const target = (location.state as { from?: string } | null)?.from ?? '/';
      void navigate(target, { replace: true });
    } catch (reason) {
      const messages: Record<string, string> = {
        invalid_credentials: '账户、密码或动态验证码不正确，或账户仍处于锁定期。超级管理员请使用 SHA-256、6 位、30 秒的未使用验证码。',
        second_factor_required: '密码校验已通过，请填写超级管理员动态验证码：SHA-256、6 位、30 秒。',
        account_locked: '密码正确，但账户仍在锁定期。请停止重试，等待锁定到期后再使用新验证码。',
        totp_replayed: '这个动态验证码已经使用过，请等待验证器生成新验证码后再试。',
        totp_clock_behind: '当前验证码正确，但服务器保存的验证码时间步位于未来。请联系管理员检查服务器时钟和认证状态。',
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
          <div><SafetyOutlined /><span><strong>本地认证</strong><small>密码与超级管理员动态验证码</small></span></div>
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
            <Form.Item label="动态验证码（超级管理员必填）" name="totp" extra="普通用户和运维账户可留空。" rules={[{ pattern: /^\d{6}$/, message: '请输入六位 TOTP 验证码' }]}>
              <Input inputMode="numeric" autoComplete="one-time-code" maxLength={6} prefix={<SafetyOutlined />} placeholder="000000" />
            </Form.Item>
            <Alert type="info" showIcon title="使用本地超级管理员密码和 TOTP 动态验证码登录（SHA-256，6 位，30 秒）。" />
            <Button block type="primary" htmlType="submit" loading={submitting}>安全登录</Button>
          </Form>
          <Flex justify="center"><Text type="secondary" className="login-footnote">受保护的操作会写入不可变审计链</Text></Flex>
        </Card>
      </section>
    </main>
  );
}

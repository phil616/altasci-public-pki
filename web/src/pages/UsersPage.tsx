import { KeyOutlined, PlusOutlined, StopOutlined, UnlockOutlined, UserOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { App, Avatar, Button, Card, Form, Input, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { useState } from 'react';
import type { ColumnsType } from 'antd/es/table';

import { ErrorAlert, LoadingScreen, PageHeader, StatusTag } from '@/components/common';
import { consoleAPI } from '@/lib/api';
import { formatDate, roleLabels } from '@/lib/format';
import type { User } from '@/types';

const { Text } = Typography;
interface CreateValues { username: string; email?: string; role: 'operator' | 'user'; password: string }

export function UsersPage() {
  const { message, modal } = App.useApp();
  const queryClient = useQueryClient();
  const users = useQuery({ queryKey: ['users'], queryFn: consoleAPI.users });
  const [createOpen, setCreateOpen] = useState(false);
  const [passwordUser, setPasswordUser] = useState<User>();
  const [createForm] = Form.useForm<CreateValues>();
  const [passwordForm] = Form.useForm<{ password: string }>();
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['users'] });

  const create = useMutation({
    mutationFn: consoleAPI.createUser,
    onSuccess: () => { void refresh(); setCreateOpen(false); createForm.resetFields(); message.success('用户已创建'); },
    onError: (error) => message.error(error.message),
  });
  const status = useMutation({
    mutationFn: ({ id, value }: { id: string; value: 'active' | 'disabled' }) => consoleAPI.setUserStatus(id, value),
    onSuccess: () => { void refresh(); message.success('用户状态已更新'); },
    onError: (error) => message.error(error.message),
  });
  const password = useMutation({
    mutationFn: ({ id, value }: { id: string; value: string }) => consoleAPI.resetPassword(id, value),
    onSuccess: () => { setPasswordUser(undefined); passwordForm.resetFields(); message.success('密码已重置，已有会话均已撤销'); },
    onError: (error) => message.error(error.message),
  });

  if (users.isPending) return <LoadingScreen />;
  if (users.error) return <ErrorAlert error={users.error} />;
  const columns: ColumnsType<User> = [
    { title: '用户', key: 'identity', render: (_, item) => <Space><Avatar icon={<UserOutlined />} /><div><Text strong>{item.username}</Text><div><Text type="secondary">{item.email ?? '未设置邮箱'}</Text></div></div></Space> },
    { title: '角色', dataIndex: 'role', render: (role: User['role']) => <Tag>{roleLabels[role]}</Tag> },
    { title: '状态', dataIndex: 'status', render: (value: string) => <StatusTag status={value} /> },
    { title: '创建时间', dataIndex: 'created_at', responsive: ['lg'], render: formatDate },
    { title: '操作', key: 'actions', align: 'right', render: (_, item) => item.role === 'super_admin' ? <Text type="secondary">受保护账户</Text> : <Space wrap>
      <Button icon={<KeyOutlined />} onClick={() => setPasswordUser(item)}>重置密码</Button>
      <Button
        danger={item.status === 'active'}
        icon={item.status === 'active' ? <StopOutlined /> : <UnlockOutlined />}
        onClick={() => { modal.confirm({
          title: item.status === 'active' ? `停用 ${item.username}？` : `启用 ${item.username}？`,
          content: item.status === 'active' ? '停用会立即撤销该用户全部会话。' : '启用后用户可以重新登录。',
          okText: '确认', cancelText: '取消', okButtonProps: { danger: item.status === 'active' },
          onOk: () => status.mutateAsync({ id: item.id, value: item.status === 'active' ? 'disabled' : 'active' }),
        }); }}
      >{item.status === 'active' ? '停用' : '启用'}</Button>
    </Space> },
  ];

  return (
    <>
      <PageHeader eyebrow="IDENTITY & ACCESS" title="用户管理" description="创建运维与普通用户，控制账户状态并撤销凭据。" actions={<Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>创建用户</Button>} />
      <Card className="content-card"><Table rowKey="id" columns={columns} dataSource={users.data?.items ?? []} scroll={{ x: 840 }} pagination={{ pageSize: 20, hideOnSinglePage: true }} /></Card>
      <Modal title="创建用户" open={createOpen} onCancel={() => setCreateOpen(false)} onOk={() => createForm.submit()} confirmLoading={create.isPending} okText="创建" cancelText="取消" destroyOnHidden>
        <Form form={createForm} layout="vertical" onFinish={(values) => create.mutate(values)} initialValues={{ role: 'user' }} requiredMark={false}>
          <Form.Item name="username" label="用户名" tooltip="本地登录标识，建议使用稳定且能明确对应到个人的名称。" extra="长度为 3–128 个字符，创建后用于登录和审计归属。" rules={[{ required: true }, { min: 3, max: 128 }]}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="email" label="邮箱（可选）" tooltip="用于展示、联系和账户登录。" rules={[{ type: 'email' }]}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="role" label="角色" tooltip="运维人员可在获得 CA 级授权后审批或操作申请；普通用户只能提交申请并访问自己的证书。" rules={[{ required: true }]}><Select options={[{ value: 'operator', label: '运维人员' }, { value: 'user', label: '普通用户' }]} /></Form.Item>
          <Form.Item name="password" label="初始密码" extra="15–128 个字符，建议使用密码管理器生成。" rules={[{ required: true }, { min: 15, max: 128 }]}><Input.Password autoComplete="new-password" /></Form.Item>
        </Form>
      </Modal>
      <Modal title={`重置 ${passwordUser?.username ?? ''} 的密码`} open={Boolean(passwordUser)} onCancel={() => setPasswordUser(undefined)} onOk={() => passwordForm.submit()} confirmLoading={password.isPending} okText="重置并撤销会话" cancelText="取消" destroyOnHidden>
        <Form form={passwordForm} layout="vertical" onFinish={(values) => passwordUser && password.mutate({ id: passwordUser.id, value: values.password })} requiredMark={false}>
          <Form.Item name="password" label="新密码" extra="15–128 个字符。重置后该用户的现有会话会立即失效。" rules={[{ required: true }, { min: 15, max: 128 }]}><Input.Password autoComplete="new-password" /></Form.Item>
        </Form>
      </Modal>
    </>
  );
}

import { CheckOutlined, CloseOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { App, Button, Card, Descriptions, Input, Modal, Steps, Typography } from 'antd';
import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { useAuth } from '@/auth';
import { ErrorAlert, LoadingScreen, PageHeader, PEMViewer, StatusTag } from '@/components/common';
import { consoleAPI } from '@/lib/api';
import { formatDate, shortID } from '@/lib/format';
import { can } from '@/lib/permissions';

const { Paragraph, Text } = Typography;

export function RequestDetailPage() {
  const { id = '' } = useParams();
  const { user } = useAuth();
  const { message } = App.useApp();
  const queryClient = useQueryClient();
  const [decision, setDecision] = useState<'approve' | 'reject'>();
  const [comment, setComment] = useState('');
  const request = useQuery({
    queryKey: ['request', id], queryFn: () => consoleAPI.request(id), enabled: Boolean(id),
    refetchInterval: (query) => ['approved', 'issuing'].includes(query.state.data?.status ?? '') ? 2_000 : false,
  });
  const decide = useMutation({
    mutationFn: () => decision ? consoleAPI.decideRequest(id, decision, comment) : Promise.reject(new Error('未选择审批决定')),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['request', id] }); void queryClient.invalidateQueries({ queryKey: ['requests'] }); setDecision(undefined); setComment(''); message.success(decision === 'approve' ? '申请已进入签发队列' : '申请已拒绝'); },
    onError: (error) => message.error(error.message),
  });
  if (request.isPending) return <LoadingScreen />;
  if (request.error) return <ErrorAlert error={request.error} />;
  const item = request.data;
  const workflowCurrent = item.status === 'issued' ? 3
    : ['approved', 'issuing', 'failed'].includes(item.status) ? 2
      : item.status === 'cancelled' ? 0 : 1;
  const workflowFailed = ['rejected', 'failed', 'cancelled'].includes(item.status);
  return (
    <>
      <PageHeader
        eyebrow="CERTIFICATE REQUEST"
        title={item.requested_subject?.common_name || 'CSR 证书申请'}
        description={`申请编号 ${item.id}`}
        actions={<><StatusTag status={item.status} />{can(user?.role, 'decide_requests') && item.status === 'pending' ? <><Button type="primary" icon={<CheckOutlined />} onClick={() => setDecision('approve')}>批准</Button><Button danger icon={<CloseOutlined />} onClick={() => setDecision('reject')}>拒绝</Button></> : null}</>}
      />
      <Card className="workflow-card">
        <Steps
          current={workflowCurrent}
          status={workflowFailed ? 'error' : item.status === 'issued' ? 'finish' : 'process'}
          responsive
          size="small"
          items={[
            { title: '提交申请', content: formatDate(item.submitted_at) },
            {
              title: item.status === 'rejected' ? '审批未通过' : '审批处理',
              content: item.status === 'pending' ? '等待有权限的运维人员审批'
                : item.status === 'rejected' ? item.rejection_reason || '申请已被拒绝'
                  : item.status === 'cancelled' ? '申请已取消' : formatDate(item.approved_at),
            },
            {
              title: item.status === 'failed' ? '签发失败' : '证书签发',
              content: item.status === 'issuing' ? '后台签发任务正在执行'
                : item.status === 'approved' ? '已进入异步签发队列'
                  : item.status === 'failed' ? item.error_code || '签发任务执行失败'
                    : item.status === 'issued' ? '证书已生成' : '尚未开始',
            },
            { title: '完成', content: item.status === 'issued' ? formatDate(item.issued_at) : '等待签发完成' },
          ]}
        />
      </Card>
      <Card className="content-card">
        <Descriptions column={{ xs: 1, md: 2 }} items={[
          { key: 'requester', label: '申请人 ID', children: <Text copyable>{shortID(item.requester_id, 12)}</Text> },
          { key: 'ca', label: '签发 CA', children: <Link to={`/authorities/${item.ca_id}`}>{shortID(item.ca_id, 12)}</Link> },
          { key: 'profile', label: '策略 ID', children: shortID(item.profile_id, 12) },
          { key: 'mode', label: '密钥方式', children: item.key_generation_mode === 'server_generated' ? '服务端生成（一次性下载）' : '客户端 CSR' },
          { key: 'submitted', label: '提交时间', children: formatDate(item.submitted_at) },
          { key: 'approved', label: '审批时间', children: formatDate(item.approved_at) },
          { key: 'validity', label: '申请有效期', children: item.requested_validity_seconds ? `${item.requested_validity_seconds} 秒` : '策略默认值' },
          { key: 'sans', label: 'SAN', children: item.requested_sans?.join(', ') || '—' },
        ]} />
        {item.rejection_reason ? <Paragraph type="danger">拒绝原因：{item.rejection_reason}</Paragraph> : null}
        {item.error_code ? <Paragraph type="danger">签发错误：{item.error_code}</Paragraph> : null}
      </Card>
      {item.csr_pem ? <PEMViewer value={item.csr_pem} filename={`${item.id}.csr.pem`} /> : null}
      <Modal title={decision === 'approve' ? '批准证书申请' : '拒绝证书申请'} open={Boolean(decision)} onCancel={() => setDecision(undefined)} onOk={() => decide.mutate()} confirmLoading={decide.isPending} okText={decision === 'approve' ? '批准并进入队列' : '确认拒绝'} okButtonProps={{ danger: decision === 'reject' }}>
        <Paragraph>{decision === 'approve' ? '批准后，后台工作进程将按照绑定策略签发证书。申请人不能审批自己的申请。' : '请说明拒绝原因，便于申请人修正后重新提交。'}</Paragraph>
        <Input.TextArea value={comment} onChange={(event) => setComment(event.target.value)} rows={4} maxLength={2000} showCount placeholder="审批意见" />
      </Modal>
    </>
  );
}

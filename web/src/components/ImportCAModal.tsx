import { UploadOutlined } from '@ant-design/icons';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Alert, App, Button, Form, Input, Modal, Radio, Select, Upload } from 'antd';
import { useRef } from 'react';

import { consoleAPI, type ImportCAInput } from '@/lib/api';
import type { CertificateAuthority } from '@/types';

export function ImportCAModal({ open, onClose, authorities }: {
  open: boolean;
  onClose: () => void;
  authorities: CertificateAuthority[];
}) {
  const { message } = App.useApp();
  const queryClient = useQueryClient();
  const [form] = Form.useForm<ImportCAInput>();
  const readGeneration = useRef(0);
  const kind = Form.useWatch('kind', form);
  const importing = useMutation({
    mutationFn: (input: ImportCAInput) => consoleAPI.importCA({
      ...input, parent_ca_id: input.kind === 'intermediate' ? input.parent_ca_id : undefined,
    }),
    gcTime: 0,
    onSuccess: () => {
      readGeneration.current++;
      void queryClient.invalidateQueries({ queryKey: ['authorities'] });
      form.resetFields();
      importing.reset();
      onClose();
      message.success('证书机构导入完成');
    },
    onError: (error) => message.error(error.message),
  });
  const close = () => {
    if (importing.isPending) return;
    readGeneration.current++;
    form.resetFields();
    importing.reset();
    onClose();
  };
  const readPEM = async (file: File, field: 'certificate_pem' | 'private_key_pem') => {
    const generation = readGeneration.current;
    if (file.size > 256 * 1024) {
      message.error('单个 PEM 文件不能超过 256 KiB');
      return Upload.LIST_IGNORE;
    }
    try {
      const text = await file.text();
      if (generation !== readGeneration.current) return Upload.LIST_IGNORE;
      form.setFieldValue(field, text);
      await form.validateFields([field]);
    } catch {
      message.error('无法读取有效的 PEM 文件，请检查文件内容');
    }
    return Upload.LIST_IGNORE;
  };

  return (
    <Modal title="导入证书机构" open={open} width={720} onCancel={close}
      onOk={() => form.submit()} confirmLoading={importing.isPending} okText="验证并导入"
      cancelText="取消" cancelButtonProps={{ disabled: importing.isPending }} destroyOnHidden>
      <Form form={form} layout="vertical" requiredMark={false} initialValues={{ kind: 'root' }}
        disabled={importing.isPending} onFinish={(values) => importing.mutate(values)}>
        <Alert type="info" showIcon title="导入现有 CA 证书及其匹配私钥"
          description="证书的主题、有效期和最大下级深度保持原样。支持 RSA-2048/3072/4096、ECDSA-P256/P384，以及未加密的 PKCS#8、PKCS#1、SEC1 PEM 私钥。" />
        <Form.Item name="kind" label="机构类型" rules={[{ required: true }]}>
          <Radio.Group optionType="button" buttonStyle="solid" options={[{ value: 'root', label: '根 CA' }, { value: 'intermediate', label: '中间 CA' }]} />
        </Form.Item>
        {kind === 'intermediate' ? <Form.Item name="parent_ca_id" label="上级 CA" preserve={false}
          extra="先导入上级 CA，再选择实际签发此证书的机构；系统会校验完整证书链。" rules={[{ required: true, message: '请选择上级 CA' }]}>
          <Select placeholder="选择已存在的上级 CA" options={authorities.filter((ca) => ca.status === 'active' && ca.path_length !== 0).map((ca) => ({ value: ca.id, label: `${ca.name} (${ca.slug})` }))} />
        </Form.Item> : null}
        <Form.Item name="name" label="显示名称" rules={[{ required: true, whitespace: true, message: '请输入显示名称' }]}>
          <Input placeholder="Existing Enterprise CA" />
        </Form.Item>
        <Form.Item name="slug" label="公开标识" extra="用于本站的 Issuer、CRL 和 OCSP 发布地址，导入后应保持稳定。"
          rules={[{ required: true }, { pattern: /^[a-z0-9][a-z0-9-]{1,62}$/, message: '使用 2–63 位小写字母、数字和连字符，并以字母或数字开头' }]}>
          <Input placeholder="existing-enterprise-ca" />
        </Form.Item>
        <Upload accept=".pem,.crt,.cer" showUploadList={false} beforeUpload={(file) => readPEM(file, 'certificate_pem')}>
          <Button aria-label="选择证书文件" icon={<UploadOutlined />}>选择证书文件</Button>
        </Upload>
        <Form.Item name="certificate_pem" label="CA 证书（PEM）" rules={[{ required: true, message: '请上传或粘贴 CA 证书' }]}>
          <Input.TextArea rows={5} maxLength={262144} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" />
        </Form.Item>
        <Upload accept=".pem,.key" showUploadList={false} beforeUpload={(file) => readPEM(file, 'private_key_pem')}>
          <Button aria-label="选择私钥文件" icon={<UploadOutlined />}>选择私钥文件</Button>
        </Upload>
        <Form.Item name="private_key_pem" label="CA 私钥（PEM）" rules={[{ required: true, message: '请上传或粘贴匹配的 CA 私钥' }]}>
          <Input.TextArea rows={5} maxLength={262144} spellCheck={false} autoComplete="off" placeholder="-----BEGIN PRIVATE KEY-----" />
        </Form.Item>
        <Alert type="warning" showIcon title="私钥将加密保存，用于签发证书、CRL 和 OCSP"
          description="导入不包含历史签发和吊销记录，也不修改原证书中的发布地址。请另行迁移历史记录，并保持原 AIA、CRL 和 OCSP 服务可用。" />
      </Form>
    </Modal>
  );
}

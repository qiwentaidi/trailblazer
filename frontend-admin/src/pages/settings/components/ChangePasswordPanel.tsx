import { Button, Card, Form, Input, message, Space } from 'antd';
import { useState } from 'react';

import { changePassword } from '@/services/auth';

interface ChangePasswordFormValues {
  oldPassword: string;
  newPassword: string;
  confirmPassword: string;
}

type ChangePasswordPanelProps = {
  embedded?: boolean;
  submitText?: string;
  onSuccess?: () => void;
};

export default function ChangePasswordPanel({
  embedded = false,
  submitText = '修改密码',
  onSuccess,
}: ChangePasswordPanelProps) {
  const [form] = Form.useForm<ChangePasswordFormValues>();
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (values: ChangePasswordFormValues) => {
    setSubmitting(true);
    try {
      await changePassword({
        oldPassword: values.oldPassword,
        newPassword: values.newPassword,
      });
      message.success('密码修改成功，请使用新密码继续登录');
      form.resetFields();
      onSuccess?.();
    } catch (error) {
      message.error(
        (error as { data?: { error?: string } })?.data?.error || '修改密码失败',
      );
    } finally {
      setSubmitting(false);
    }
  };

  const formNode = (
    <Form
      form={form}
      layout="vertical"
      onFinish={handleSubmit}
      requiredMark={false}
    >
      <Form.Item
        name="oldPassword"
        label="当前密码"
        rules={[{ required: true, message: '请输入当前密码' }]}
      >
        <Input.Password autoComplete="current-password" />
      </Form.Item>

      <Form.Item
        name="newPassword"
        label="新密码"
        rules={[
          { required: true, message: '请输入新密码' },
          { min: 8, message: '密码至少需要 8 个字符' },
        ]}
      >
        <Input.Password autoComplete="new-password" />
      </Form.Item>

      <Form.Item
        name="confirmPassword"
        label="确认新密码"
        dependencies={['newPassword']}
        rules={[
          { required: true, message: '请再次输入新密码' },
          ({ getFieldValue }) => ({
            validator(_, value) {
              if (!value || getFieldValue('newPassword') === value) {
                return Promise.resolve();
              }
              return Promise.reject(new Error('两次输入的新密码不一致'));
            },
          }),
        ]}
      >
        <Input.Password autoComplete="new-password" />
      </Form.Item>

      <Space>
        <Button type="primary" htmlType="submit" loading={submitting}>
          {submitText}
        </Button>
      </Space>
    </Form>
  );

  if (embedded) {
    return formNode;
  }

  return (
    <Card title="账号安全" bordered={false}>
      {formNode}
    </Card>
  );
}

import { LockOutlined, UserOutlined } from '@ant-design/icons';
import { Button, Card, Form, Input, message, Typography } from 'antd';
import { useEffect } from 'react';
import { history } from 'umi';

import adminService from '@/services/admin';
import { checkESHealth } from '@/services/auth';
import useGlobalStore from '@/store/useGlobalStore';
import { useAuthStore } from '@/stores/auth';
import type { LoginRequest } from '@/types/auth';
import config from '@/utils/config';
import { readStoredAuthToken } from '@/utils/session';
import styles from './index.module.less';

export default function Login() {
  const [form] = Form.useForm<LoginRequest>();
  const login = useAuthStore((state) => state.login);
  const loading = useAuthStore((state) => state.loading);
  const token = useAuthStore((state) => state.token);

  useEffect(() => {
    if (!token) return;

    let active = true;

    (async () => {
      const ok = await useAuthStore.getState().initialize();
      if (active && ok) {
        history.replace('/tasks');
      }
    })();

    return () => {
      active = false;
    };
  }, [token]);

  const handleSubmit = async (values: LoginRequest) => {
    const ok = await login(values);
    if (!ok) {
      message.error('登录失败，请检查用户名和密码');
      return;
    }

    const storedToken = localStorage.getItem('auth_token');
    if (storedToken) {
      useGlobalStore.getState().login(storedToken);
    }
    const sessionToken = readStoredAuthToken();

    try {
      const currentAdmin = await adminService.currentAdmin();
      if (currentAdmin && readStoredAuthToken() === sessionToken) {
        useGlobalStore.getState().setCurrentUser(currentAdmin);
      }
    } catch {
      // Login succeeded; legacy admin bootstrap is best-effort only.
    }

    message.success('登录成功');

    try {
      const es = await checkESHealth();
      if (!es.connected) {
        message.warning(
          `数据库连接异常：${es.message || 'Elasticsearch unavailable'}`,
        );
      }
    } catch {
      message.warning('无法检查数据库连接状态');
    }

    history.push('/tasks');
  };

  return (
    <div className={styles.page}>
      <div className={styles.form}>
        <Card bordered={false} style={{ boxShadow: 'none' }}>
          <div className={styles.logo}>
            <img src={config.logoPath} alt={config.siteName} />
            <Typography.Title level={3} style={{ margin: 0 }}>
              {config.siteName}
            </Typography.Title>
          </div>

          <Typography.Paragraph
            style={{ textAlign: 'center', marginBottom: 24 }}
          >
            请使用您的账户登录
          </Typography.Paragraph>

          <Form
            form={form}
            layout="vertical"
            onFinish={handleSubmit}
            requiredMark={false}
          >
            <Form.Item
              name="username"
              label="用户名"
              rules={[{ required: true, message: '请输入用户名' }]}
            >
              <Input prefix={<UserOutlined />} autoComplete="username" />
            </Form.Item>

            <Form.Item
              name="password"
              label="密码"
              rules={[{ required: true, message: '请输入密码' }]}
            >
              <Input.Password
                prefix={<LockOutlined />}
                autoComplete="current-password"
              />
            </Form.Item>

            <Button type="primary" htmlType="submit" block loading={loading}>
              登录
            </Button>
          </Form>
        </Card>
      </div>
    </div>
  );
}

import { LockOutlined, UserOutlined } from '@ant-design/icons';
import { Button, Card, Form, Input, message, Spin, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { history } from 'umi';

import {
  checkESHealth,
  getAuthStatus,
  initializeAccount,
} from '@/services/auth';
import { useAuthStore } from '@/stores/auth';
import type { InitAccountRequest, LoginRequest } from '@/types/auth';
import config from '@/utils/config';
import styles from './index.module.less';

export default function Login() {
  const [loginForm] = Form.useForm<LoginRequest>();
  const [initForm] = Form.useForm<
    InitAccountRequest & { confirmPassword: string }
  >();
  const login = useAuthStore((state) => state.login);
  const loading = useAuthStore((state) => state.loading);
  const token = useAuthStore((state) => state.token);
  const [statusLoading, setStatusLoading] = useState(true);
  const [initialized, setInitialized] = useState(true);

  const loadAuthStatus = async () => {
    setStatusLoading(true);
    try {
      const status = await getAuthStatus();
      setInitialized(status.initialized);
    } catch {
      message.error('无法获取账号初始化状态');
    } finally {
      setStatusLoading(false);
    }
  };

  useEffect(() => {
    void loadAuthStatus();
  }, []);

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

  const handleInitialize = async (
    values: InitAccountRequest & { confirmPassword: string },
  ) => {
    if (values.password !== values.confirmPassword) {
      message.error('两次输入的密码不一致');
      return;
    }

    try {
      await initializeAccount({
        username: values.username.trim(),
        password: values.password,
      });
      message.success('管理员账号初始化成功，请使用新账号登录');
      setInitialized(true);
      initForm.resetFields();
      loginForm.setFieldValue('username', values.username.trim());
      await handleSubmit({
        username: values.username.trim(),
        password: values.password,
      });
    } catch (error) {
      message.error(
        (error as { data?: { error?: string } })?.data?.error ||
          '初始化账号失败',
      );
      void loadAuthStatus();
    }
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
            {initialized
              ? '请使用您的账户登录'
              : '首次使用请先初始化管理员账号'}
          </Typography.Paragraph>

          <Spin spinning={statusLoading}>
            {initialized ? (
              <Form
                form={loginForm}
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

                <Button
                  type="primary"
                  htmlType="submit"
                  block
                  loading={loading}
                >
                  登录
                </Button>
              </Form>
            ) : (
              <Form
                form={initForm}
                layout="vertical"
                onFinish={handleInitialize}
                requiredMark={false}
              >
                <Form.Item
                  name="username"
                  label="管理员账号"
                  rules={[
                    { required: true, message: '请输入管理员账号' },
                    { min: 3, message: '用户名至少需要 3 个字符' },
                  ]}
                >
                  <Input prefix={<UserOutlined />} autoComplete="username" />
                </Form.Item>

                <Form.Item
                  name="password"
                  label="管理员密码"
                  rules={[
                    { required: true, message: '请输入管理员密码' },
                    { min: 8, message: '密码至少需要 8 个字符' },
                  ]}
                >
                  <Input.Password
                    prefix={<LockOutlined />}
                    autoComplete="new-password"
                  />
                </Form.Item>

                <Form.Item
                  name="confirmPassword"
                  label="确认密码"
                  dependencies={['password']}
                  rules={[
                    { required: true, message: '请再次输入密码' },
                    ({ getFieldValue }) => ({
                      validator(_, value) {
                        if (!value || getFieldValue('password') === value) {
                          return Promise.resolve();
                        }
                        return Promise.reject(
                          new Error('两次输入的密码不一致'),
                        );
                      },
                    }),
                  ]}
                >
                  <Input.Password
                    prefix={<LockOutlined />}
                    autoComplete="new-password"
                  />
                </Form.Item>

                <Button type="primary" htmlType="submit" block>
                  初始化并登录
                </Button>
              </Form>
            )}
          </Spin>
        </Card>
      </div>
    </div>
  );
}

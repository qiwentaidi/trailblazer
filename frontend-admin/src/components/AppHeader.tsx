import {
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  PlusOutlined,
  UserOutlined,
} from '@ant-design/icons';
import {
  Avatar,
  Button,
  Divider,
  Input,
  Popover,
  Space,
  Typography,
} from 'antd';
import { useEffect, useState } from 'react';
import { history } from 'umi';

import ChangePasswordPanel from '@/pages/settings/components/ChangePasswordPanel';
import CreateTaskModal from '@/pages/tasks/components/CreateTaskModal';
import { useAuthStore } from '@/stores/auth';

type AppHeaderProps = {
  collapsed: boolean;
  onToggleCollapse: () => void;
};

export default function AppHeader({
  collapsed,
  onToggleCollapse,
}: AppHeaderProps) {
  const user = useAuthStore((state) => state.user);
  const logout = useAuthStore((state) => state.logout);
  const [createOpen, setCreateOpen] = useState(false);
  const [userCardOpen, setUserCardOpen] = useState(false);
  const [locale, setLocale] = useState<'zh-CN' | 'en-US'>(() => {
    if (typeof window === 'undefined') {
      return 'zh-CN';
    }
    return window.localStorage.getItem('umi_locale') === 'en-US'
      ? 'en-US'
      : 'zh-CN';
  });

  const changeLocale = (nextLocale: string) => {
    try {
      window.localStorage.setItem('umi_locale', nextLocale);
      setLocale(nextLocale === 'en-US' ? 'en-US' : 'zh-CN');
      window.dispatchEvent(
        new CustomEvent('localechange', { detail: nextLocale }),
      );
    } catch {
      window.location.reload();
    }
  };

  useEffect(() => {
    const syncLocale = (nextLocale?: string | null) => {
      setLocale(nextLocale === 'en-US' ? 'en-US' : 'zh-CN');
    };

    const onStorage = (event: StorageEvent) => {
      if (event.key === 'umi_locale') {
        syncLocale(event.newValue);
      }
    };

    const onLocaleChange = (event: Event) => {
      const detail =
        event instanceof CustomEvent ? String(event.detail || '') : null;
      syncLocale(detail);
    };

    window.addEventListener('storage', onStorage);
    window.addEventListener('localechange', onLocaleChange as EventListener);

    return () => {
      window.removeEventListener('storage', onStorage);
      window.removeEventListener(
        'localechange',
        onLocaleChange as EventListener,
      );
    };
  }, []);

  const nextLocale = locale === 'en-US' ? 'zh-CN' : 'en-US';
  const localeToggleLabel =
    locale === 'en-US' ? '切换为简体中文' : 'Switch to English';

  const handleGlobalSearch = (value: string) => {
    const keyword = value.trim();
    if (!keyword) {
      history.push('/search');
      return;
    }

    history.push(`/search?keyword=${encodeURIComponent(keyword)}`);
  };

  const handleLogout = () => {
    setUserCardOpen(false);
    logout();
    history.push('/login');
  };

  const userCardContent = (
    <div className="app-header-user-card">
      <div className="app-header-user-card-head">
        <Avatar
          size={40}
          className="app-header-user-avatar"
          icon={!user?.username ? <UserOutlined /> : undefined}
        >
          {user?.username?.slice(0, 1).toUpperCase()}
        </Avatar>
        <div className="app-header-user-card-meta">
          <Typography.Text strong className="app-header-user-card-name">
            {(user?.username || 'unknown').toUpperCase()}
          </Typography.Text>
          <Typography.Text type="secondary">已登录账号</Typography.Text>
        </div>
      </div>

      <Divider style={{ margin: '16px 0' }} />

      <Typography.Text strong style={{ display: 'block', marginBottom: 12 }}>
        修改密码
      </Typography.Text>
      <ChangePasswordPanel
        embedded
        submitText="确认修改"
        onSuccess={() => setUserCardOpen(false)}
      />

      <Divider style={{ margin: '16px 0 12px' }} />

      <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
        <Button icon={<LogoutOutlined />} onClick={handleLogout}>
          退出登录
        </Button>
      </Space>
    </div>
  );

  return (
    <>
      <div className="app-header-inner">
        <div className="app-header-left">
          <Button
            ghost
            type="text"
            className="app-header-collapse"
            aria-label={collapsed ? '展开侧边栏' : '折叠侧边栏'}
            icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
            onClick={onToggleCollapse}
          />
        </div>

        <div className="app-header-center">
          <Input.Search
            allowClear
            size="middle"
            className="app-header-search"
            placeholder="搜索任务、资产、域名"
            enterButton={false}
            onSearch={handleGlobalSearch}
          />
        </div>

        <div className="app-header-actions">
          <Button
            type="default"
            icon={<PlusOutlined />}
            className="app-header-create-button"
            onClick={() => setCreateOpen(true)}
          >
            创建任务
          </Button>

          <Button
            type="text"
            className="app-header-locale-toggle"
            aria-label={localeToggleLabel}
            title={localeToggleLabel}
            onClick={() => changeLocale(nextLocale)}
          >
            <span
              className={`app-header-locale-option ${
                locale === 'zh-CN' ? 'is-active' : ''
              }`}
            >
              中
            </span>
            <span className="app-header-locale-separator">/</span>
            <span
              className={`app-header-locale-option ${
                locale === 'en-US' ? 'is-active' : ''
              }`}
            >
              EN
            </span>
          </Button>

          <Popover
            content={userCardContent}
            placement="bottomRight"
            trigger="click"
            open={userCardOpen}
            onOpenChange={setUserCardOpen}
            overlayClassName="app-header-user-popover"
          >
            <button type="button" className="app-header-user">
              <Avatar
                size={32}
                className="app-header-user-avatar"
                icon={!user?.username ? <UserOutlined /> : undefined}
              >
                {user?.username?.slice(0, 1).toUpperCase()}
              </Avatar>
              <div className="app-header-user-meta">
                <Typography.Text strong className="app-header-user-name">
                  {(user?.username || 'unknown').toUpperCase()}
                </Typography.Text>
              </div>
            </button>
          </Popover>
        </div>
      </div>
      <CreateTaskModal
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
      />
    </>
  );
}

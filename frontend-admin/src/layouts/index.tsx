import { Layout } from 'antd';
import type { CSSProperties } from 'react';
import { useEffect, useState } from 'react';
import { Outlet, useLocation } from 'umi';

import AppHeader from '@/components/AppHeader';
import AppSidebar from '@/components/AppSidebar';
import { CodecWorkbenchProvider } from '@/components/codec';
import { useAuthStore } from '@/stores/auth';

import './index.less';

const { Sider, Header, Content } = Layout;
const APP_SIDER_WIDTH = 232;
const APP_SIDER_COLLAPSED_WIDTH = 88;

export function shouldRenderAppShell(pathname: string, token: string | null) {
  if (pathname === '/login') {
    return false;
  }

  return Boolean(token);
}

export default function AppLayout() {
  const location = useLocation();
  const token = useAuthStore((state) => state.token);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    try {
      setCollapsed(
        window.localStorage.getItem('app-layout-collapsed') === 'true',
      );
    } catch {
      setCollapsed(false);
    }
  }, []);

  if (!shouldRenderAppShell(location.pathname, token)) {
    return <Outlet />;
  }

  const siderWidth = collapsed ? APP_SIDER_COLLAPSED_WIDTH : APP_SIDER_WIDTH;
  const shellStyle = {
    '--app-shell-offset': `${siderWidth}px`,
  } as CSSProperties;

  const handleToggleCollapse = () => {
    setCollapsed((current) => {
      const next = !current;
      try {
        window.localStorage.setItem('app-layout-collapsed', String(next));
      } catch {
        // Best effort only.
      }
      return next;
    });
  };

  return (
    <CodecWorkbenchProvider>
      <Layout className="app-shell" style={shellStyle}>
        <Sider
          theme="light"
          collapsible
          trigger={null}
          collapsed={collapsed}
          width={APP_SIDER_WIDTH}
          collapsedWidth={APP_SIDER_COLLAPSED_WIDTH}
          className="app-sider"
        >
          <AppSidebar collapsed={collapsed} />
        </Sider>
        <Layout className="app-main-layout" style={{ marginLeft: siderWidth }}>
          <Header className="app-header">
            <AppHeader
              collapsed={collapsed}
              onToggleCollapse={handleToggleCollapse}
            />
          </Header>
          <Content className="app-content">
            <Outlet />
          </Content>
        </Layout>
      </Layout>
    </CodecWorkbenchProvider>
  );
}

import { Menu, Typography } from 'antd';
import { history, useLocation } from 'umi';

import { appNavigation } from '@/constants/navigation';
import config from '@/utils/config';

type AppSidebarProps = {
  collapsed: boolean;
};

export default function AppSidebar({ collapsed }: AppSidebarProps) {
  const location = useLocation();
  const selectedKey =
    appNavigation.find((item) => location.pathname.startsWith(item.path))
      ?.key || 'dashboard';

  return (
    <div className="app-sidebar-inner">
      <div
        className={`app-sidebar-logo ${collapsed ? 'app-sidebar-logo-collapsed' : ''}`}
        onClick={() => history.push('/dashboard')}
      >
        <img src={config.logoPath} alt={config.siteName} />
        {!collapsed ? (
          <div className="app-sidebar-logo-text">
            <Typography.Text strong>{config.siteName}</Typography.Text>
            <Typography.Text type="secondary">
              Attack Surface Hub
            </Typography.Text>
          </div>
        ) : null}
      </div>
      <Menu
        mode="inline"
        inlineCollapsed={collapsed}
        selectedKeys={[selectedKey]}
        items={appNavigation.map((item) => ({
          key: item.key,
          label: item.label,
          icon: item.icon ? <item.icon /> : undefined,
          onClick: () => history.push(item.path),
        }))}
      />
    </div>
  );
}

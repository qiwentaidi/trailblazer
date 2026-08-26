import {
  ApartmentOutlined,
  DashboardOutlined,
  ProfileOutlined,
  RobotOutlined,
  SearchOutlined,
  SettingOutlined,
} from '@ant-design/icons';

export const appNavigation = [
  {
    key: 'dashboard',
    label: '仪表盘',
    path: '/dashboard',
    icon: DashboardOutlined,
  },
  {
    key: 'tasks',
    label: '任务中心',
    path: '/tasks',
    icon: ProfileOutlined,
  },
  {
    key: 'browserSessions',
    label: '受控会话',
    path: '/browser-sessions',
    icon: ApartmentOutlined,
  },
  {
    key: 'search',
    label: '数据检索',
    path: '/search',
    icon: SearchOutlined,
  },
  {
    key: 'collaborativeTesting',
    label: '人机协同测试',
    path: '/collaborative-testing',
    icon: RobotOutlined,
  },
  {
    key: 'settings',
    label: '配置中心',
    path: '/settings',
    icon: SettingOutlined,
  },
] as const;

type AppNavigationEntry = (typeof appNavigation)[number];

const PAGE_DESCRIPTIONS: Record<AppNavigationEntry['key'], string> = {
  dashboard: '总览任务态势、风险分布与近期活动。',
  tasks: '管理扫描任务、执行状态与版本结果。',
  browserSessions: '管理受控浏览器窗口、单站点测试会话与加密线索。',
  search: '检索协议分析内容与自定义规则。',
  collaborativeTesting: '由 AI 整理接口线索，并在人工审批下完成安全测试。',
  settings: '维护扫描参数、系统设置与基础配置。',
};

export type AppShellContext = {
  section: AppNavigationEntry;
  title: string;
  description: string;
  breadcrumbItems: Array<{
    key: string;
    title: string;
    path?: string;
  }>;
};

function matchNavigation(pathname: string) {
  return appNavigation.find(
    (item) => pathname === item.path || pathname.startsWith(`${item.path}/`),
  );
}

export function resolveAppShellContext(pathname: string): AppShellContext {
  const section = matchNavigation(pathname) || appNavigation[0];
  const breadcrumbItems: AppShellContext['breadcrumbItems'] = [
    {
      key: section.key,
      title: section.label,
      path: section.path,
    },
  ];

  let title: string = section.label;
  let description: string = PAGE_DESCRIPTIONS[section.key];

  if (section.key === 'tasks' && pathname !== section.path) {
    title = '任务详情';
    description = '查看任务版本、资产风险与协议分析结果。';
    breadcrumbItems.push({
      key: 'task-detail',
      title,
    });
  }

  if (section.key === 'browserSessions' && pathname !== section.path) {
    title = '会话详情';
    description = '查看受控会话内的流量历史、链路轨迹与会话材料。';
    breadcrumbItems.push({
      key: 'browser-session-detail',
      title,
    });
  }

  return {
    section,
    title,
    description,
    breadcrumbItems,
  };
}

import {
  DashboardOutlined,
  ProfileOutlined,
  SearchOutlined,
  SettingOutlined,
} from '@ant-design/icons'

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
    key: 'search',
    label: '数据检索',
    path: '/search',
    icon: SearchOutlined,
  },
  {
    key: 'settings',
    label: '配置中心',
    path: '/settings',
    icon: SettingOutlined,
  },
] as const

type AppNavigationEntry = (typeof appNavigation)[number]

const PAGE_DESCRIPTIONS: Record<AppNavigationEntry['key'], string> = {
  dashboard: '总览任务态势、风险分布与近期活动。',
  tasks: '管理扫描任务、执行状态与版本结果。',
  search: '检索协议分析内容与自定义规则。',
  settings: '维护扫描参数、系统设置与基础配置。',
}

export type AppShellContext = {
  section: AppNavigationEntry
  title: string
  description: string
  breadcrumbItems: Array<{
    key: string
    title: string
    path?: string
  }>
}

function matchNavigation(pathname: string) {
  return appNavigation.find(
    (item) => pathname === item.path || pathname.startsWith(`${item.path}/`),
  )
}

export function resolveAppShellContext(pathname: string): AppShellContext {
  const section = matchNavigation(pathname) || appNavigation[0]
  const breadcrumbItems: AppShellContext['breadcrumbItems'] = [
    {
      key: section.key,
      title: section.label,
      path: section.path,
    },
  ]

  let title: string = section.label
  let description: string = PAGE_DESCRIPTIONS[section.key]

  if (section.key === 'tasks' && pathname !== section.path) {
    title = '任务详情'
    description = '查看任务版本、资产风险与协议分析结果。'
    breadcrumbItems.push({
      key: 'task-detail',
      title,
    })
  }

  return {
    section,
    title,
    description,
    breadcrumbItems,
  }
}

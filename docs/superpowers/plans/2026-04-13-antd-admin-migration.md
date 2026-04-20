# Antd Admin Frontend Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a new `frontend-admin` application on top of `zuiidea/antd-admin` and make it the active frontend for login, task flow, and settings.

**Architecture:** Keep the existing Vue app under `frontend/` as read-only reference during migration, but build the new product in a separate `frontend-admin/` workspace so replacement can happen without breaking the current UI mid-flight. Reuse the current backend APIs through a typed service layer, strip `antd-admin` down to shell infrastructure, and rebuild the approved business routes: login, task list, task detail, and settings.

**Tech Stack:** React, Ant Design 6, Umi 4, TypeScript, `antd-admin`, existing backend REST APIs

---

## File Map

### Reference-only current frontend

- Read: `frontend/src/stores/auth.ts`
  - Source of current token storage, login, logout, and user-info behavior.
- Read: `frontend/src/config/env.ts`
  - Source of current API base URL resolution behavior.
- Read: `frontend/src/views/Login.vue`
  - Source of current login success flow and ES health check.
- Read: `frontend/src/views/task/TaskDetail.vue`
  - Source of current task detail data loading, polling, risks, tree, and assets.
- Read: `frontend/src/views/task/TaskList.vue`
  - Source of current task list columns and actions.
- Read: `frontend/src/views/Settings.vue`
  - Source of current settings groups and backend endpoints.

### New frontend app scaffold

- Create: `frontend-admin/`
  - New active frontend workspace cloned from `zuiidea/antd-admin`.
- Modify: `frontend-admin/package.json`
  - Lock scripts and dependencies required for the product build.
- Modify: `frontend-admin/.umirc.ts`
  - Replace demo routing and proxy defaults with the project routes and API proxy behavior.
- Modify: `frontend-admin/src/layouts/index.tsx`
  - Slim the shell to `任务中心` and `配置中心`.
- Modify: `frontend-admin/src/pages/login/index.tsx`
  - Replace demo login with the real auth flow.

### Shared frontend infrastructure

- Create: `frontend-admin/src/utils/apiBase.ts`
  - Port the current API base URL resolution logic.
- Create: `frontend-admin/src/utils/request.ts`
  - Central request wrapper with auth token injection and 401 handling.
- Create: `frontend-admin/src/models/auth.ts` or `frontend-admin/src/stores/auth.ts`
  - Auth state for token, user info, login, logout, and boot-time initialization.
- Create: `frontend-admin/src/services/auth.ts`
  - Login and user-info API bindings.
- Create: `frontend-admin/src/types/auth.ts`
  - Shared auth types.

### Task center

- Create: `frontend-admin/src/pages/tasks/index.tsx`
  - Task list page.
- Create: `frontend-admin/src/pages/tasks/components/CreateTaskModal.tsx`
  - Task creation entry surface if the backend endpoint already exists.
- Create: `frontend-admin/src/pages/tasks/detail/[id].tsx`
  - Task detail page container.
- Create: `frontend-admin/src/pages/tasks/detail/components/TaskOverview.tsx`
  - Task summary tab.
- Create: `frontend-admin/src/pages/tasks/detail/components/SiteTreePanel.tsx`
  - Site tree tab.
- Create: `frontend-admin/src/pages/tasks/detail/components/RiskWorkbench.tsx`
  - Risk list and detail side panel.
- Create: `frontend-admin/src/pages/tasks/detail/components/AssetsPanel.tsx`
  - Asset aggregation tab.
- Create: `frontend-admin/src/services/tasks.ts`
  - Task list and task detail API bindings.
- Create: `frontend-admin/src/types/task.ts`
  - Shared task, risk, tree, and asset types.

### Settings

- Create: `frontend-admin/src/pages/settings/index.tsx`
  - Settings landing page.
- Create: `frontend-admin/src/pages/settings/components/AIConfigForm.tsx`
  - AI config group.
- Create: `frontend-admin/src/pages/settings/components/VulnRulesPanel.tsx`
  - Vulnerability rules group.
- Create: `frontend-admin/src/pages/settings/components/SystemStatusPanel.tsx`
  - Elasticsearch health group.
- Create: `frontend-admin/src/services/settings.ts`
  - Settings and health API bindings.
- Create: `frontend-admin/src/types/settings.ts`
  - Shared settings types.

### Cutover and docs

- Modify: `docs/superpowers/specs/2026-04-13-antd-admin-migration-design.md`
  - Only if the implementation reveals a required deviation.
- Create: `frontend-admin/README.md`
  - Local run/build notes for the new frontend.

---

### Task 1: Scaffold `frontend-admin` From `antd-admin`

**Files:**
- Create: `frontend-admin/`
- Modify: `frontend-admin/package.json`
- Modify: `frontend-admin/.umirc.ts`
- Test: `frontend-admin`

- [ ] **Step 1: Clone the approved template into a new workspace**

Run:

```bash
git clone https://github.com/zuiidea/antd-admin.git frontend-admin
```

Expected: a new `frontend-admin/.git` directory exists and the template files are present.

- [ ] **Step 2: Install dependencies and capture a baseline build**

Run:

```bash
pnpm -C frontend-admin install
pnpm -C frontend-admin build
```

Expected: install succeeds and the untouched template build passes.

- [ ] **Step 3: Replace the template metadata with product metadata**

Update `frontend-admin/package.json` so the app identity is no longer the demo template:

```json
{
  "name": "trailblazer-admin",
  "private": true,
  "scripts": {
    "dev": "umi dev",
    "build": "umi build",
    "lint": "eslint . --ext .ts,.tsx",
    "typecheck": "tsc --noEmit"
  }
}
```

Keep template-required dependencies, but remove package fields that only describe the public demo.

- [ ] **Step 4: Replace the route shell with the approved product routes**

Update `frontend-admin/.umirc.ts` so the route map is reduced to:

```ts
export default defineConfig({
  routes: [
    { path: '/login', component: '@/pages/login' },
    {
      path: '/',
      component: '@/layouts/index',
      wrappers: ['@/wrappers/auth'],
      routes: [
        { path: '/', redirect: '/tasks' },
        { path: '/tasks', component: '@/pages/tasks' },
        { path: '/tasks/:id', component: '@/pages/tasks/detail/[id]' },
        { path: '/settings', component: '@/pages/settings' },
      ],
    },
  ],
})
```

This establishes the approved IA before business pages are built.

- [ ] **Step 5: Run the build and record the expected failure for missing pages**

Run:

```bash
pnpm -C frontend-admin build
```

Expected: FAIL with route component resolution errors for the new task or settings pages that do not exist yet.

- [ ] **Step 6: Commit the scaffold checkpoint**

```bash
git -C frontend-admin add package.json .umirc.ts
git -C frontend-admin commit -m "chore: scaffold trailblazer admin shell routes"
```

### Task 2: Build Shared Request, Auth, and App Boot Infrastructure

**Files:**
- Create: `frontend-admin/src/utils/apiBase.ts`
- Create: `frontend-admin/src/utils/request.ts`
- Create: `frontend-admin/src/stores/auth.ts`
- Create: `frontend-admin/src/services/auth.ts`
- Create: `frontend-admin/src/types/auth.ts`
- Create: `frontend-admin/src/wrappers/auth.tsx`
- Modify: `frontend-admin/src/pages/login/index.tsx`
- Test: `frontend-admin`

- [ ] **Step 1: Port the current API base URL logic into a reusable helper**

Create `frontend-admin/src/utils/apiBase.ts`:

```ts
export const getApiBaseURL = () => {
  const params = new URLSearchParams(window.location.search)
  const backendPort = params.get('backend_port')
  const envPort = process.env.UMI_APP_BACKEND_PORT || '9092'
  const protocol = window.location.protocol
  const host = window.location.hostname

  if (process.env.NODE_ENV === 'development' && backendPort) {
    return `${protocol}//${host}:${backendPort}`
  }

  if (process.env.NODE_ENV === 'development') {
    return `${protocol}//${host}:${envPort}`
  }

  return `${protocol}//${window.location.host}`
}
```

- [ ] **Step 2: Define the shared auth types and service contract**

Create `frontend-admin/src/types/auth.ts`:

```ts
export interface User {
  id: number
  username: string
  role: string
  is_active: boolean
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  token: string
  username: string
  role: string
  message: string
}
```

Create `frontend-admin/src/services/auth.ts`:

```ts
import request from '@/utils/request'
import type { LoginRequest, LoginResponse, User } from '@/types/auth'

export const login = (payload: LoginRequest) =>
  request.post<LoginResponse>('/api/auth/login', payload)

export const fetchUserInfo = () =>
  request.get<User>('/api/user/info')

export const checkESHealth = () =>
  request.get<{ connected: boolean; message?: string }>('/api/health/es')
```

- [ ] **Step 3: Build the request wrapper with token injection**

Create `frontend-admin/src/utils/request.ts`:

```ts
import { extend } from 'umi-request'
import { getApiBaseURL } from './apiBase'

const request = extend({
  prefix: getApiBaseURL(),
  timeout: 15000,
})

request.interceptors.request.use((url, options) => {
  const token = localStorage.getItem('auth_token')
  return {
    url,
    options: {
      ...options,
      headers: {
        ...(options.headers || {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    },
  }
})

request.interceptors.response.use(async (response) => {
  if (response.status === 401) {
    localStorage.removeItem('auth_token')
    window.location.href = '/login'
  }
  return response
})

export default request
```

- [ ] **Step 4: Implement the auth store and guard wrapper**

Create `frontend-admin/src/stores/auth.ts`:

```ts
import { create } from 'zustand'
import type { LoginRequest, User } from '@/types/auth'
import * as authService from '@/services/auth'

interface AuthState {
  token: string | null
  user: User | null
  loading: boolean
  initialize: () => Promise<boolean>
  login: (payload: LoginRequest) => Promise<boolean>
  logout: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  token: localStorage.getItem('auth_token'),
  user: null,
  loading: false,
  initialize: async () => {
    const token = localStorage.getItem('auth_token')
    if (!token) return false
    try {
      const user = await authService.fetchUserInfo()
      set({ token, user })
      return true
    } catch {
      localStorage.removeItem('auth_token')
      set({ token: null, user: null })
      return false
    }
  },
  login: async (payload) => {
    set({ loading: true })
    try {
      const result = await authService.login(payload)
      localStorage.setItem('auth_token', result.token)
      set({
        token: result.token,
        user: { id: 0, username: result.username, role: result.role, is_active: true },
        loading: false,
      })
      return true
    } catch {
      set({ loading: false })
      return false
    }
  },
  logout: () => {
    localStorage.removeItem('auth_token')
    set({ token: null, user: null })
  },
}))
```

Create `frontend-admin/src/wrappers/auth.tsx`:

```tsx
import { Navigate, Outlet, useLocation } from 'umi'
import { useEffect, useState } from 'react'
import { Spin } from 'antd'
import { useAuthStore } from '@/stores/auth'

export default function AuthWrapper() {
  const location = useLocation()
  const initialize = useAuthStore((state) => state.initialize)
  const token = useAuthStore((state) => state.token)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    initialize().finally(() => setReady(true))
  }, [initialize])

  if (!ready) return <Spin fullscreen />
  if (!token && location.pathname !== '/login') return <Navigate to="/login" />
  return <Outlet />
}
```

- [ ] **Step 5: Replace the demo login page with the product login flow**

Update `frontend-admin/src/pages/login/index.tsx` so submit logic follows the current product behavior:

```tsx
const handleSubmit = async (values: LoginRequest) => {
  const ok = await login(values)
  if (!ok) {
    message.error('登录失败，请检查用户名和密码')
    return
  }

  message.success('登录成功')
  try {
    const es = await checkESHealth()
    if (!es.connected) {
      message.warning(`数据库连接异常：${es.message || 'Elasticsearch unavailable'}`)
    }
  } catch {
    message.warning('无法检查数据库连接状态')
  }

  history.push('/tasks')
}
```

- [ ] **Step 6: Run verification**

Run:

```bash
pnpm -C frontend-admin typecheck
pnpm -C frontend-admin build
```

Expected: FAIL only because task and settings pages are not created yet, not because auth utilities are broken.

- [ ] **Step 7: Commit the auth foundation**

```bash
git -C frontend-admin add src/utils src/stores src/services src/types src/wrappers src/pages/login
git -C frontend-admin commit -m "feat: add auth and request foundation"
```

### Task 3: Replace Template Layout With the Product Shell

**Files:**
- Modify: `frontend-admin/src/layouts/index.tsx`
- Create: `frontend-admin/src/components/AppSidebar.tsx`
- Create: `frontend-admin/src/components/AppHeader.tsx`
- Create: `frontend-admin/src/constants/navigation.ts`
- Test: `frontend-admin`

- [ ] **Step 1: Define the approved navigation model**

Create `frontend-admin/src/constants/navigation.ts`:

```ts
export const appNavigation = [
  { key: 'tasks', label: '任务中心', path: '/tasks' },
  { key: 'settings', label: '配置中心', path: '/settings' },
]
```

- [ ] **Step 2: Build a focused sidebar component**

Create `frontend-admin/src/components/AppSidebar.tsx`:

```tsx
import { Menu } from 'antd'
import { history, useLocation } from 'umi'
import { appNavigation } from '@/constants/navigation'

export default function AppSidebar() {
  const location = useLocation()
  return (
    <Menu
      mode="inline"
      selectedKeys={[appNavigation.find((item) => location.pathname.startsWith(item.path))?.key || 'tasks']}
      items={appNavigation.map((item) => ({
        key: item.key,
        label: item.label,
        onClick: () => history.push(item.path),
      }))}
    />
  )
}
```

- [ ] **Step 3: Build a compact header with logout**

Create `frontend-admin/src/components/AppHeader.tsx`:

```tsx
import { Button, Space, Typography } from 'antd'
import { history } from 'umi'
import { useAuthStore } from '@/stores/auth'

export default function AppHeader() {
  const user = useAuthStore((state) => state.user)
  const logout = useAuthStore((state) => state.logout)

  return (
    <Space style={{ width: '100%', justifyContent: 'space-between' }}>
      <Typography.Title level={4} style={{ margin: 0 }}>Trailblazer</Typography.Title>
      <Space>
        <span>{user?.username || 'unknown'}</span>
        <Button
          onClick={() => {
            logout()
            history.push('/login')
          }}
        >
          退出登录
        </Button>
      </Space>
    </Space>
  )
}
```

- [ ] **Step 4: Replace the demo shell layout**

Update `frontend-admin/src/layouts/index.tsx`:

```tsx
import { Layout } from 'antd'
import { Outlet } from 'umi'
import AppSidebar from '@/components/AppSidebar'
import AppHeader from '@/components/AppHeader'

const { Sider, Header, Content } = Layout

export default function AppLayout() {
  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider width={220} theme="light">
        <AppSidebar />
      </Sider>
      <Layout>
        <Header style={{ background: '#fff', padding: '0 24px' }}>
          <AppHeader />
        </Header>
        <Content style={{ padding: 24 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
```

- [ ] **Step 5: Run verification**

Run:

```bash
pnpm -C frontend-admin typecheck
pnpm -C frontend-admin build
```

Expected: FAIL only because business pages are still missing.

- [ ] **Step 6: Commit the shell reduction**

```bash
git -C frontend-admin add src/layouts src/components src/constants
git -C frontend-admin commit -m "feat: replace demo shell with trailblazer layout"
```

### Task 4: Implement Task List and Task Services

**Files:**
- Create: `frontend-admin/src/types/task.ts`
- Create: `frontend-admin/src/services/tasks.ts`
- Create: `frontend-admin/src/pages/tasks/index.tsx`
- Create: `frontend-admin/src/pages/tasks/components/CreateTaskModal.tsx`
- Test: `frontend-admin`

- [ ] **Step 1: Define the shared task types**

Create `frontend-admin/src/types/task.ts`:

```ts
export interface TaskSummary {
  id: string
  name: string
  status: string
  targets?: string[] | null
  vulnCount?: number
  createdAt: string
}

export interface Risk {
  id: string
  title: string
  level: 'high' | 'medium' | 'low' | 'info'
  type: string
  url: string
  method?: string
  request?: string
  response?: string
  responseLength?: number
  description: string
  createdAt: string
  aiVerified?: boolean
}

export interface TreeNode {
  id: string
  label: string
  children?: TreeNode[]
  url?: string
  code?: string
  statusCode?: number
  headers?: Record<string, string>
}

export interface AssetData {
  taskId: string
  taskName: string
  email: string[]
  idCard: string[]
  phone: string[]
  ipUrl: string[]
  apiRoot: string[]
  apiRouter: string[]
  createdAt: string
}
```

- [ ] **Step 2: Add task list and detail service functions**

Create `frontend-admin/src/services/tasks.ts`:

```ts
import request from '@/utils/request'
import type { AssetData, Risk, TaskSummary, TreeNode } from '@/types/task'

export const fetchTasks = () =>
  request.get<{ data: TaskSummary[] }>('/api/task/list')

export const fetchTaskTree = (id: string) =>
  request.get<{ data: TreeNode[] }>(`/api/task/${id}/tree`)

export const fetchTaskRisks = (id: string) =>
  request.get<{ data: any[] }>(`/api/task/${id}/vulns`)

export const fetchTaskAssets = (id: string) =>
  request.get<{ data: AssetData }>(`/api/task/${id}/assets`)

export const normalizeRisks = (items: any[]): Risk[] =>
  items.map((v) => ({
    id: v.vuln_id,
    title: v.title,
    level: v.level,
    type: v.type,
    url: v.url,
    method: v.method,
    request: v.request,
    response: v.response,
    responseLength: v.response_length || 0,
    description: v.description,
    createdAt: v.created_at,
    aiVerified: v.ai_verified || false,
  }))
```

- [ ] **Step 3: Build the task list page**

Create `frontend-admin/src/pages/tasks/index.tsx`:

```tsx
import { useMemo, useState } from 'react'
import { Button, Card, Input, Select, Space, Table } from 'antd'
import { history } from 'umi'
import { useRequest } from 'ahooks'
import { fetchTasks } from '@/services/tasks'

export default function TasksPage() {
  const [keyword, setKeyword] = useState('')
  const [status, setStatus] = useState<string | undefined>()
  const { data, loading, refresh } = useRequest(fetchTasks)

  const rows = useMemo(() => {
    const list = data?.data || []
    return list.filter((task) => {
      const keywordMatch = !keyword || task.name.includes(keyword)
      const statusMatch = !status || task.status === status
      return keywordMatch && statusMatch
    })
  }, [data, keyword, status])

  return (
    <Card title="任务中心" extra={<Button type="primary">创建任务</Button>}>
      <Space style={{ marginBottom: 16 }}>
        <Input placeholder="搜索任务名称" value={keyword} onChange={(e) => setKeyword(e.target.value)} />
        <Select allowClear placeholder="状态" value={status} onChange={setStatus} style={{ width: 160 }} />
        <Button onClick={() => refresh()}>刷新</Button>
      </Space>
      <Table
        rowKey="id"
        loading={loading}
        dataSource={rows}
        columns={[
          { title: '任务名', dataIndex: 'name' },
          { title: '目标', render: (_, record) => (record.targets || []).join(', ') || '-' },
          { title: '状态', dataIndex: 'status' },
          { title: '风险数', dataIndex: 'vulnCount', render: (value) => value ?? '-' },
          { title: '创建时间', dataIndex: 'createdAt' },
          {
            title: '操作',
            render: (_, record) => (
              <Button type="link" onClick={() => history.push(`/tasks/${record.id}`)}>
                查看详情
              </Button>
            ),
          },
        ]}
      />
    </Card>
  )
}
```

- [ ] **Step 4: Add the create-task modal shell without blocking the main list**

Create `frontend-admin/src/pages/tasks/components/CreateTaskModal.tsx`:

```tsx
import { Modal } from 'antd'

interface Props {
  open: boolean
  onCancel: () => void
}

export default function CreateTaskModal({ open, onCancel }: Props) {
  return (
    <Modal title="创建任务" open={open} footer={null} onCancel={onCancel}>
      创建任务表单在后续增量中接入，当前阶段先保留入口和弹层结构。
    </Modal>
  )
}
```

Keep the page route usable even if the modal is not yet connected to a full backend mutation flow.

- [ ] **Step 5: Run verification**

Run:

```bash
pnpm -C frontend-admin typecheck
pnpm -C frontend-admin build
```

Expected: FAIL only because task detail and settings pages are still missing.

- [ ] **Step 6: Commit the task list slice**

```bash
git -C frontend-admin add src/types/task.ts src/services/tasks.ts src/pages/tasks
git -C frontend-admin commit -m "feat: add task list page"
```

### Task 5: Implement Task Detail With Overview, Site Tree, Risks, and Assets

**Files:**
- Create: `frontend-admin/src/pages/tasks/detail/[id].tsx`
- Create: `frontend-admin/src/pages/tasks/detail/components/TaskOverview.tsx`
- Create: `frontend-admin/src/pages/tasks/detail/components/SiteTreePanel.tsx`
- Create: `frontend-admin/src/pages/tasks/detail/components/RiskWorkbench.tsx`
- Create: `frontend-admin/src/pages/tasks/detail/components/AssetsPanel.tsx`
- Modify: `frontend-admin/src/services/tasks.ts`
- Test: `frontend-admin`

- [ ] **Step 1: Add the overview tab component**

Create `frontend-admin/src/pages/tasks/detail/components/TaskOverview.tsx`:

```tsx
import { Card, Col, Row, Statistic } from 'antd'
import type { AssetData, Risk, TaskSummary, TreeNode } from '@/types/task'

interface Props {
  task: TaskSummary | null
  treeData: TreeNode[]
  risks: Risk[]
  assets: AssetData | null
}

export default function TaskOverview({ task, treeData, risks, assets }: Props) {
  const highCount = risks.filter((item) => item.level === 'high').length
  return (
    <Row gutter={16}>
      <Col span={6}><Card><Statistic title="任务状态" value={task?.status || '-'} /></Card></Col>
      <Col span={6}><Card><Statistic title="风险总数" value={risks.length} /></Card></Col>
      <Col span={6}><Card><Statistic title="高风险" value={highCount} /></Card></Col>
      <Col span={6}><Card><Statistic title="站点节点" value={treeData.length} /></Card></Col>
    </Row>
  )
}
```

- [ ] **Step 2: Add the site-tree and assets panels**

Create `frontend-admin/src/pages/tasks/detail/components/SiteTreePanel.tsx`:

```tsx
import { Card, Tree } from 'antd'
import type { TreeNode } from '@/types/task'

export default function SiteTreePanel({ treeData }: { treeData: TreeNode[] }) {
  return (
    <Card bodyStyle={{ maxHeight: 640, overflow: 'auto' }}>
      <Tree treeData={treeData as any} fieldNames={{ title: 'label', key: 'id', children: 'children' }} />
    </Card>
  )
}
```

Create `frontend-admin/src/pages/tasks/detail/components/AssetsPanel.tsx`:

```tsx
import { Card, Descriptions } from 'antd'
import type { AssetData } from '@/types/task'

export default function AssetsPanel({ assets }: { assets: AssetData | null }) {
  if (!assets) return <Card>暂无资产数据</Card>
  return (
    <Card>
      <Descriptions column={1}>
        <Descriptions.Item label="邮箱">{assets.email.join(', ') || '-'}</Descriptions.Item>
        <Descriptions.Item label="手机号">{assets.phone.join(', ') || '-'}</Descriptions.Item>
        <Descriptions.Item label="身份证">{assets.idCard.join(', ') || '-'}</Descriptions.Item>
        <Descriptions.Item label="IP/URL">{assets.ipUrl.join(', ') || '-'}</Descriptions.Item>
        <Descriptions.Item label="API Root">{assets.apiRoot.join(', ') || '-'}</Descriptions.Item>
        <Descriptions.Item label="API Router">{assets.apiRouter.join(', ') || '-'}</Descriptions.Item>
      </Descriptions>
    </Card>
  )
}
```

- [ ] **Step 3: Build the risk workbench component**

Create `frontend-admin/src/pages/tasks/detail/components/RiskWorkbench.tsx`:

```tsx
import { useMemo, useState } from 'react'
import { Card, Drawer, Input, List, Select, Space, Tag } from 'antd'
import type { Risk } from '@/types/task'

export default function RiskWorkbench({ risks }: { risks: Risk[] }) {
  const [keyword, setKeyword] = useState('')
  const [level, setLevel] = useState<string | undefined>()
  const [selected, setSelected] = useState<Risk | null>(null)

  const rows = useMemo(() => {
    return risks.filter((risk) => {
      const keywordMatch = !keyword || risk.title.includes(keyword) || risk.url.includes(keyword)
      const levelMatch = !level || risk.level === level
      return keywordMatch && levelMatch
    })
  }, [keyword, level, risks])

  return (
    <>
      <Card>
        <Space style={{ marginBottom: 16 }}>
          <Input placeholder="搜索风险" value={keyword} onChange={(e) => setKeyword(e.target.value)} />
          <Select allowClear placeholder="风险等级" value={level} onChange={setLevel} style={{ width: 160 }} />
        </Space>
        <List
          dataSource={rows}
          renderItem={(risk) => (
            <List.Item onClick={() => setSelected(risk)} style={{ cursor: 'pointer' }}>
              <List.Item.Meta
                title={<Space><Tag color="red">{risk.level}</Tag><span>{risk.title}</span>{risk.aiVerified ? <Tag color="blue">AI</Tag> : null}</Space>}
                description={`${risk.type} | ${risk.method || '-'} | ${risk.url}`}
              />
            </List.Item>
          )}
        />
      </Card>
      <Drawer width={720} open={!!selected} onClose={() => setSelected(null)} title={selected?.title}>
        <pre>{selected?.request || 'No request'}</pre>
        <pre>{selected?.response || 'No response'}</pre>
      </Drawer>
    </>
  )
}
```

- [ ] **Step 4: Build the task detail container with polling**

Create `frontend-admin/src/pages/tasks/detail/[id].tsx`:

```tsx
import { useMemo } from 'react'
import { Button, Card, Space, Tabs } from 'antd'
import { useParams } from 'umi'
import { useRequest } from 'ahooks'
import { fetchTaskAssets, fetchTaskRisks, fetchTaskTree, normalizeRisks } from '@/services/tasks'
import TaskOverview from './components/TaskOverview'
import SiteTreePanel from './components/SiteTreePanel'
import RiskWorkbench from './components/RiskWorkbench'
import AssetsPanel from './components/AssetsPanel'

export default function TaskDetailPage() {
  const params = useParams<{ id: string }>()
  const taskId = params.id || ''
  const { data: treeData = [], loading: treeLoading } = useRequest(async () => (await fetchTaskTree(taskId)).data, { refreshDeps: [taskId] })
  const { data: riskPayload = [], loading: riskLoading, refresh: refreshRisks } = useRequest(async () => (await fetchTaskRisks(taskId)).data, {
    refreshDeps: [taskId],
    pollingInterval: 5000,
  })
  const { data: assets = null, loading: assetsLoading } = useRequest(async () => (await fetchTaskAssets(taskId)).data, { refreshDeps: [taskId] })

  const risks = useMemo(() => normalizeRisks(riskPayload), [riskPayload])

  return (
    <Card
      title={`任务详情 #${taskId}`}
      extra={<Space><Button onClick={() => refreshRisks()}>刷新风险</Button><Button type="primary">导出报告</Button></Space>}
      loading={treeLoading || riskLoading || assetsLoading}
    >
      <Tabs
        items={[
          { key: 'overview', label: '概览', children: <TaskOverview task={null} treeData={treeData} risks={risks} assets={assets} /> },
          { key: 'tree', label: '站点树', children: <SiteTreePanel treeData={treeData} /> },
          { key: 'risks', label: '风险', children: <RiskWorkbench risks={risks} /> },
          { key: 'assets', label: '资产', children: <AssetsPanel assets={assets} /> },
        ]}
      />
    </Card>
  )
}
```

This gets the approved four-tab IA running before any secondary refinements.

- [ ] **Step 5: Run verification**

Run:

```bash
pnpm -C frontend-admin typecheck
pnpm -C frontend-admin build
```

Expected: FAIL only if settings page is still missing; otherwise PASS for the task routes.

- [ ] **Step 6: Commit the task detail slice**

```bash
git -C frontend-admin add src/pages/tasks/detail src/services/tasks.ts
git -C frontend-admin commit -m "feat: add task detail flow"
```

### Task 6: Implement Settings for AI Config, Vulnerability Rules, and System Status

**Files:**
- Create: `frontend-admin/src/types/settings.ts`
- Create: `frontend-admin/src/services/settings.ts`
- Create: `frontend-admin/src/pages/settings/index.tsx`
- Create: `frontend-admin/src/pages/settings/components/AIConfigForm.tsx`
- Create: `frontend-admin/src/pages/settings/components/VulnRulesPanel.tsx`
- Create: `frontend-admin/src/pages/settings/components/SystemStatusPanel.tsx`
- Test: `frontend-admin`

- [ ] **Step 1: Define settings types and service functions**

Create `frontend-admin/src/types/settings.ts`:

```ts
export interface AIConfig {
  enabled: boolean
  api_key: string
  base_url: string
  model: string
}

export interface ESHealth {
  connected: boolean
  message?: string
}
```

Create `frontend-admin/src/services/settings.ts`:

```ts
import request from '@/utils/request'
import type { AIConfig, ESHealth } from '@/types/settings'

export const fetchOpenAIConfig = () =>
  request.get<{ data: AIConfig }>('/api/config/openai')

export const saveOpenAIConfig = (payload: AIConfig) =>
  request.post('/api/config/openai', payload)

export const fetchSettingsHealth = () =>
  request.get<ESHealth>('/api/health/es')

export const fetchSearchRules = () =>
  request.get<{ data: any[] }>('/api/search/js/rules')
```

- [ ] **Step 2: Build the AI config form**

Create `frontend-admin/src/pages/settings/components/AIConfigForm.tsx`:

```tsx
import { Button, Card, Form, Input, Switch } from 'antd'
import type { AIConfig } from '@/types/settings'

interface Props {
  initialValues?: AIConfig
  loading?: boolean
  onSubmit: (values: AIConfig) => Promise<void>
}

export default function AIConfigForm({ initialValues, loading, onSubmit }: Props) {
  return (
    <Card title="AI 配置">
      <Form layout="vertical" initialValues={initialValues} onFinish={onSubmit}>
        <Form.Item label="启用 AI 辅助检测" name="enabled" valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item label="API Key" name="api_key">
          <Input.Password />
        </Form.Item>
        <Form.Item label="Base URL" name="base_url">
          <Input />
        </Form.Item>
        <Form.Item label="模型" name="model">
          <Input />
        </Form.Item>
        <Button htmlType="submit" type="primary" loading={loading}>保存配置</Button>
      </Form>
    </Card>
  )
}
```

- [ ] **Step 3: Build the vulnerability-rules and system-status panels**

Create `frontend-admin/src/pages/settings/components/VulnRulesPanel.tsx`:

```tsx
import { Card, List, Tag } from 'antd'

export default function VulnRulesPanel({ rules }: { rules: Array<{ id?: number; label: string; value: string }> }) {
  return (
    <Card title="漏洞检测规则">
      <List
        dataSource={rules}
        renderItem={(rule) => (
          <List.Item>
            <Tag>{rule.label}</Tag>
            <span>{rule.value}</span>
          </List.Item>
        )}
      />
    </Card>
  )
}
```

Create `frontend-admin/src/pages/settings/components/SystemStatusPanel.tsx`:

```tsx
import { Alert, Card, Tag } from 'antd'
import type { ESHealth } from '@/types/settings'

export default function SystemStatusPanel({ health }: { health: ESHealth | null }) {
  return (
    <Card title="系统状态">
      <div style={{ marginBottom: 12 }}>
        Elasticsearch:
        <Tag color={health?.connected ? 'green' : 'red'} style={{ marginLeft: 8 }}>
          {health?.connected ? '已连接' : '未连接'}
        </Tag>
      </div>
      {!health?.connected ? <Alert type="warning" message={health?.message || '数据库连接异常'} showIcon /> : null}
    </Card>
  )
}
```

- [ ] **Step 4: Assemble the settings page**

Create `frontend-admin/src/pages/settings/index.tsx`:

```tsx
import { message, Space } from 'antd'
import { useRequest } from 'ahooks'
import { fetchOpenAIConfig, fetchSearchRules, fetchSettingsHealth, saveOpenAIConfig } from '@/services/settings'
import AIConfigForm from './components/AIConfigForm'
import VulnRulesPanel from './components/VulnRulesPanel'
import SystemStatusPanel from './components/SystemStatusPanel'

export default function SettingsPage() {
  const openAI = useRequest(async () => (await fetchOpenAIConfig()).data)
  const rules = useRequest(async () => (await fetchSearchRules()).data)
  const health = useRequest(fetchSettingsHealth)

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <AIConfigForm
        initialValues={openAI.data}
        loading={openAI.loading}
        onSubmit={async (values) => {
          await saveOpenAIConfig(values)
          message.success('配置已保存')
          openAI.refresh()
        }}
      />
      <VulnRulesPanel rules={rules.data || []} />
      <SystemStatusPanel health={health.data || null} />
    </Space>
  )
}
```

- [ ] **Step 5: Run final verification**

Run:

```bash
pnpm -C frontend-admin typecheck
pnpm -C frontend-admin build
```

Expected: PASS

- [ ] **Step 6: Commit the settings slice**

```bash
git -C frontend-admin add src/types/settings.ts src/services/settings.ts src/pages/settings
git -C frontend-admin commit -m "feat: add settings center"
```

### Task 7: Final Cutover Checks and Local Documentation

**Files:**
- Create: `frontend-admin/README.md`
- Modify: `docs/superpowers/specs/2026-04-13-antd-admin-migration-design.md` (only if implementation forced a change)
- Test: `frontend-admin`

- [ ] **Step 1: Write local run and build instructions**

Create `frontend-admin/README.md`:

```md
# Trailblazer Admin

## Run

```bash
pnpm install
pnpm dev
```

Use `?backend_port=9092` in development when the backend is running on a custom port.

## Build

```bash
pnpm build
```
```

- [ ] **Step 2: Smoke-test the approved operator flow**

Run the frontend locally and verify:

1. `/login` can submit valid credentials.
2. Successful login redirects to `/tasks`.
3. Task list can navigate to `/tasks/:id`.
4. Task detail loads tree, risks, and assets.
5. Settings can load AI config and ES health.

Expected: the main operator path works without touching the old Vue UI.

- [ ] **Step 3: Reconcile implementation with the approved spec**

If implementation required deviations, update:

```md
docs/superpowers/specs/2026-04-13-antd-admin-migration-design.md
```

Only document real deviations, such as a different route layout forced by `antd-admin` conventions.

- [ ] **Step 4: Commit the handoff state**

```bash
git -C frontend-admin add README.md
git -C frontend-admin commit -m "docs: add frontend admin runbook"
```

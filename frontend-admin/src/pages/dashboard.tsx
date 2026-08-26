import {
  ArrowRightOutlined,
  FileSearchOutlined,
  PlusOutlined,
  ProfileOutlined,
  RiseOutlined,
  SettingOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { Tiny } from '@ant-design/plots'
import {
  Avatar,
  Button,
  Card,
  Col,
  Empty,
  Row,
  Skeleton,
  Space,
  Statistic,
  Tag,
  Typography,
  message,
} from 'antd'
import { startTransition, useDeferredValue, useEffect, useState } from 'react'

import useIsMounted from '@/hooks/useIsMounted'
import type { Risk, TaskSummary } from '@/types/task'
import { formatDateTime } from '@/utils/datetime'
import { history } from 'umi'
import dashboardService, { type DashboardSnapshot } from '../services/dashboard'
import CreateTaskModal from './tasks/components/CreateTaskModal'

const STATUS_COLORS: Record<string, string> = {
  pending: 'default',
  running: 'processing',
  completed: 'success',
  failed: 'error',
  stopped: 'warning',
}

const STATUS_LABELS: Record<string, string> = {
  pending: '待执行',
  running: '执行中',
  completed: '已完成',
  failed: '失败',
  stopped: '已停止',
}

const RISK_COLORS: Record<string, string> = {
  high: 'error',
  medium: 'warning',
  low: 'success',
  info: 'default',
}

const RISK_LABELS: Record<string, string> = {
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

const DASHBOARD_TARGET_PREVIEW_LIMIT = 3
const COMPACT_LIST_LIMIT = 4
const TREND_CHART_HEIGHT = 44
const PANEL_HEIGHT = 388

const levelDotColorMap: Record<string, string> = {
  high: '#ff4d4f',
  medium: '#faad14',
  low: '#52c41a',
  info: '#8c8c8c',
}

const renderTargetPreview = (targets?: string[] | null) => {
  const items = targets || []
  if (!items.length) {
    return <Typography.Text type="secondary">-</Typography.Text>
  }

  const visibleTargets = items.slice(0, DASHBOARD_TARGET_PREVIEW_LIMIT)
  const hiddenCount = Math.max(0, items.length - visibleTargets.length)

  return (
    <Space size={[6, 6]} wrap>
      {visibleTargets.map((target) => (
        <Tag key={target} color="blue">
          {target}
        </Tag>
      ))}
      {hiddenCount > 0 ? <Tag>{`+${hiddenCount} 个`}</Tag> : null}
    </Space>
  )
}

const goToTaskDetail = (taskId: string) => {
  history.push(`/tasks/${taskId}`)
}

function TrendMiniChart({
  title,
  color,
  points,
}: {
  title: string
  color: string
  points: DashboardSnapshot['trends']['tasks']
}) {
  const chartData = points.length
    ? points.map((point) => ({
        label: point.label,
        count: point.count,
      }))
    : [{ label: '暂无数据', count: 0 }]
  const values = chartData.map((point) => point.count)
  const latest = values.at(-1) || 0
  const total = values.reduce((sum, value) => sum + value, 0)

  return (
    <div
      style={{
        padding: '14px 16px',
        borderRadius: 16,
        border: '1px solid #f0f0f0',
        background: 'linear-gradient(180deg, #ffffff 0%, #fafcff 100%)',
        minHeight: 126,
      }}
    >
      <Space direction="vertical" size={10} style={{ width: '100%' }}>
        <Space align="start" style={{ justifyContent: 'space-between', width: '100%' }}>
          <div>
            <Typography.Text style={{ fontSize: 13, color: '#8c8c8c' }}>{title}</Typography.Text>
            <div style={{ fontSize: 24, fontWeight: 600, lineHeight: 1.2, marginTop: 4 }}>{total}</div>
          </div>
          <Tag bordered={false} color="blue">
            今日 {latest}
          </Tag>
        </Space>

        <div
          style={{
            height: TREND_CHART_HEIGHT + 12,
            width: '100%',
            overflow: 'visible',
          }}
        >
          <Tiny.Area
            data={chartData}
            xField="label"
            yField="count"
            height={TREND_CHART_HEIGHT + 12}
            padding={0}
            margin={0}
            tooltip={{ title: false }}
            scale={{ y: { domainMin: 0 } }}
            style={{
              fill: color,
              fillOpacity: 0.16,
            }}
            line={{
              style: {
                stroke: color,
                lineWidth: 2.5,
              },
            }}
          />
        </div>

        <Space size={10} style={{ width: '100%', justifyContent: 'space-between' }}>
          {chartData.map((point) => (
            <Typography.Text key={point.label} style={{ fontSize: 11, color: '#bfbfbf' }}>
              {point.label}
            </Typography.Text>
          ))}
        </Space>
      </Space>
    </div>
  )
}

function TaskCompactRow({ task }: { task: TaskSummary }) {
  const status = task.latestStatus || task.status

  return (
    <div
      style={{
        padding: '14px 0',
        borderBottom: '1px solid #f5f5f5',
        display: 'grid',
        gap: 10,
        minHeight: 92,
        alignContent: 'start',
      }}
    >
      <Space align="start" style={{ justifyContent: 'space-between', width: '100%' }}>
        <div style={{ minWidth: 0 }}>
          <Button
            type="link"
            style={{ padding: 0, fontWeight: 600, maxWidth: '100%' }}
            onClick={() => goToTaskDetail(task.id)}
          >
            <Typography.Text ellipsis style={{ maxWidth: 320 }}>
              {task.name || '-'}
            </Typography.Text>
          </Button>
          <Typography.Text
            type="secondary"
            style={{ display: 'block', marginTop: 4, fontSize: 12 }}
          >
            {formatDateTime(task.createdAt)}
          </Typography.Text>
        </div>
        <Tag color={STATUS_COLORS[status] || 'default'} style={{ marginInlineEnd: 0 }}>
          {STATUS_LABELS[status] || status}
        </Tag>
      </Space>

      {renderTargetPreview(task.targets)}
    </div>
  )
}

function RiskCompactRow({ risk }: { risk: Risk & { taskId: string; taskName: string } }) {
  return (
    <div
      style={{
        padding: '14px 0',
        borderBottom: '1px solid #f5f5f5',
        display: 'grid',
        gap: 8,
        minHeight: 92,
        alignContent: 'start',
      }}
    >
      <Space align="start" style={{ justifyContent: 'space-between', width: '100%' }}>
        <Space size={10} align="start" style={{ minWidth: 0 }}>
          <Avatar
            size={28}
            style={{
              background: `${levelDotColorMap[risk.level] || '#8c8c8c'}18`,
              color: levelDotColorMap[risk.level] || '#8c8c8c',
              flex: 'none',
            }}
            icon={<WarningOutlined />}
          />
          <div style={{ minWidth: 0 }}>
            <Typography.Text strong ellipsis style={{ display: 'block', maxWidth: 340 }}>
              {risk.title || '-'}
            </Typography.Text>
            <Typography.Text type="secondary" ellipsis style={{ display: 'block', fontSize: 12, marginTop: 2 }}>
              {risk.url || '-'}
            </Typography.Text>
          </div>
        </Space>
        <Tag color={RISK_COLORS[risk.level] || 'default'} style={{ marginInlineEnd: 0 }}>
          {RISK_LABELS[risk.level] || risk.level}
        </Tag>
      </Space>

      <Space size={12} wrap>
        <Button
          type="link"
          style={{ padding: 0, height: 'auto', fontSize: 12 }}
          onClick={() => goToTaskDetail(risk.taskId)}
        >
          所属任务：{risk.taskName}
        </Button>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {formatDateTime(risk.createdAt)}
        </Typography.Text>
      </Space>
    </div>
  )
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardSnapshot>({
    stats: {
      totalTasks: 0,
      totalRisks: 0,
      totalJS: 0,
      highRiskTasks: 0,
    },
    recentTasks: [],
    recentRisks: [],
    trends: {
      tasks: [],
      risks: [],
    },
  })
  const [loading, setLoading] = useState(true)
  const [createOpen, setCreateOpen] = useState(false)

  const deferredData = useDeferredValue(data)

  const isMounted = useIsMounted()

  const loadDashboard = async () => {
    setLoading(true)
    try {
      const resp = await dashboardService.getDashboardSnapshot()
      if (isMounted()) {
        startTransition(() => setData(resp))
      }
    } catch (error) {
      console.error(error)
      message.error('加载仪表盘失败')
    } finally {
      if (isMounted()) {
        setLoading(false)
      }
    }
  }

  useEffect(() => {
    void loadDashboard()
  }, [])

  return (
    <div style={{ display: 'grid', gap: 20 }}>
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic title="总任务数" value={deferredData.stats.totalTasks} prefix={<ProfileOutlined />} />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic title="风险发现" value={deferredData.stats.totalRisks} prefix={<WarningOutlined />} />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic title="JS 文件" value={deferredData.stats.totalJS} prefix={<FileSearchOutlined />} />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic title="高风险任务" value={deferredData.stats.highRiskTasks} prefix={<WarningOutlined />} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card
            title="近 7 天趋势"
            extra={
              <Space size={6} style={{ color: '#8c8c8c', fontSize: 12 }}>
                <RiseOutlined />
                任务创建与风险发现
              </Space>
            }
            styles={{ body: { padding: 16 } }}
          >
            <Skeleton loading={loading} active paragraph={{ rows: 2 }}>
              <Row gutter={[16, 16]}>
                <Col xs={24} md={12}>
                  <TrendMiniChart title="新增任务" color="#1677ff" points={deferredData.trends.tasks} />
                </Col>
                <Col xs={24} md={12}>
                  <TrendMiniChart title="发现风险" color="#ff7a45" points={deferredData.trends.risks} />
                </Col>
              </Row>
            </Skeleton>
          </Card>
        </Col>

        <Col xs={24} xl={12}>
          <Card
            title="最近任务"
            extra={
              <Button type="link" onClick={() => history.push('/tasks')}>
                查看全部 <ArrowRightOutlined />
              </Button>
            }
            style={{ height: '100%' }}
            styles={{ body: { padding: '4px 20px 8px', height: PANEL_HEIGHT, overflow: 'auto' } }}
          >
            <Skeleton loading={loading} active paragraph={{ rows: 5 }}>
              {deferredData.recentTasks.length ? (
                deferredData.recentTasks.slice(0, COMPACT_LIST_LIMIT).map((task, index, array) => (
                  <div key={task.id} style={index === array.length - 1 ? { borderBottom: 'none' } : undefined}>
                    <TaskCompactRow task={task} />
                  </div>
                ))
              ) : (
                <Empty description="暂无任务">
                  <Button type="primary" onClick={() => setCreateOpen(true)}>
                    创建第一个任务
                  </Button>
                </Empty>
              )}
            </Skeleton>
          </Card>
        </Col>

        <Col xs={24} xl={12}>
          <Card
            title="最新风险"
            extra={
              <Button type="link" onClick={() => history.push('/tasks')}>
                查看全部 <ArrowRightOutlined />
              </Button>
            }
            style={{ height: '100%' }}
            styles={{ body: { padding: '4px 20px 8px', height: PANEL_HEIGHT, overflow: 'auto' } }}
          >
            <Skeleton loading={loading} active paragraph={{ rows: 5 }}>
              {deferredData.recentRisks.length ? (
                deferredData.recentRisks.slice(0, COMPACT_LIST_LIMIT).map((risk, index, array) => (
                  <div key={risk.id} style={index === array.length - 1 ? { borderBottom: 'none' } : undefined}>
                    <RiskCompactRow risk={risk} />
                  </div>
                ))
              ) : (
                <Empty description="暂无风险发现" />
              )}
            </Skeleton>
          </Card>
        </Col>
      </Row>

      <Card title="快捷操作">
        <Row gutter={[16, 16]}>
          <Col xs={24} sm={12} lg={6}>
            <Button block icon={<PlusOutlined />} size="large" onClick={() => setCreateOpen(true)}>
              创建任务
            </Button>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <Button block icon={<ProfileOutlined />} size="large" onClick={() => history.push('/tasks')}>
              任务管理
            </Button>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <Button block icon={<FileSearchOutlined />} size="large" onClick={() => history.push('/search')}>
              数据检索
            </Button>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <Button block icon={<SettingOutlined />} size="large" onClick={() => history.push('/settings')}>
              系统设置
            </Button>
          </Col>
        </Row>
      </Card>

      <CreateTaskModal
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onCreated={() => void loadDashboard()}
      />
    </div>
  )
}

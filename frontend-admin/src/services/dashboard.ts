import type { Risk, TaskSummary } from '@/types/task'

import { fetchTaskJS, fetchTaskRisks, fetchTasks, normalizeRisks } from './tasks'

export interface DashboardSnapshot {
  stats: {
    totalTasks: number
    totalRisks: number
    totalJS: number
    highRiskTasks: number
  }
  recentTasks: TaskSummary[]
  recentRisks: Array<Risk & { taskId: string; taskName: string }>
  trends: {
    tasks: DashboardTrendPoint[]
    risks: DashboardTrendPoint[]
  }
}

export interface DashboardTrendPoint {
  date: string
  label: string
  count: number
}

const sortByCreatedAtDesc = <T extends { createdAt?: string }>(items: T[]) =>
  [...items].sort((left, right) => {
    const leftTime = new Date(left.createdAt || '').getTime() || 0
    const rightTime = new Date(right.createdAt || '').getTime() || 0
    return rightTime - leftTime
  })

const DAY_WINDOW = 7
const RECENT_TASK_LIMIT = 5
const RECENT_RISK_LIMIT = 5

const formatTrendDate = (date: Date) => {
  const year = date.getFullYear()
  const month = `${date.getMonth() + 1}`.padStart(2, '0')
  const day = `${date.getDate()}`.padStart(2, '0')

  return `${year}-${month}-${day}`
}

const formatTrendLabel = (date: string) => date.slice(5)

const createEmptyTrend = (): DashboardTrendPoint[] => {
  const points: DashboardTrendPoint[] = []
  const baseDate = new Date()
  baseDate.setHours(0, 0, 0, 0)

  for (let index = DAY_WINDOW - 1; index >= 0; index -= 1) {
    const current = new Date(baseDate)
    current.setDate(baseDate.getDate() - index)
    const date = formatTrendDate(current)

    points.push({
      date,
      label: formatTrendLabel(date),
      count: 0,
    })
  }

  return points
}

const buildTrend = (timestamps: Array<string | undefined>) => {
  const trend = createEmptyTrend()
  const indexMap = new Map(trend.map((item, index) => [item.date, index]))

  timestamps.forEach((value) => {
    if (!value) {
      return
    }

    const parsed = new Date(value.replace(' ', 'T'))
    if (Number.isNaN(parsed.getTime())) {
      return
    }

    const bucket = formatTrendDate(parsed)
    const trendIndex = indexMap.get(bucket)
    if (trendIndex === undefined) {
      return
    }

    trend[trendIndex] = {
      ...trend[trendIndex],
      count: trend[trendIndex].count + 1,
    }
  })

  return trend
}

export async function getDashboardSnapshot(): Promise<DashboardSnapshot> {
  const response = await fetchTasks(1, 100)
  const tasks = sortByCreatedAtDesc(response?.data || [])

  const perTaskData = await Promise.all(
    tasks.map(async (task) => {
      const [risksResponse, jsResponse] = await Promise.allSettled([
        fetchTaskRisks(task.id),
        fetchTaskJS(task.id),
      ])

      const risks =
        risksResponse.status === 'fulfilled'
          ? normalizeRisks(risksResponse.value?.data || [])
          : []
      const jsCount =
        jsResponse.status === 'fulfilled' ? jsResponse.value?.data?.length || 0 : 0

      return {
        task,
        risks,
        jsCount,
      }
    }),
  )

  const allRisks = perTaskData.flatMap((item) =>
    item.risks.map((risk) => ({
      ...risk,
      taskId: item.task.id,
      taskName: item.task.name,
    })),
  )

  return {
    stats: {
      totalTasks: tasks.length,
      totalRisks: perTaskData.reduce((sum, item) => sum + item.risks.length, 0),
      totalJS: perTaskData.reduce((sum, item) => sum + item.jsCount, 0),
      highRiskTasks: tasks.filter((task) => task.highestRiskLevel === 'high').length,
    },
    recentTasks: tasks.slice(0, RECENT_TASK_LIMIT),
    recentRisks: sortByCreatedAtDesc(allRisks).slice(0, RECENT_RISK_LIMIT),
    trends: {
      tasks: buildTrend(tasks.map((task) => task.createdAt)),
      risks: buildTrend(allRisks.map((risk) => risk.createdAt)),
    },
  }
}

export default { getDashboardSnapshot }

import dashboardService from './dashboard'
import { fetchTaskJS, fetchTaskRisks, fetchTasks } from './tasks'

jest.mock('./tasks', () => ({
  __esModule: true,
  fetchTasks: jest.fn(),
  fetchTaskRisks: jest.fn(),
  fetchTaskJS: jest.fn(),
  normalizeRisks: jest.fn((items) => items),
}))

describe('dashboard service', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  test('aggregates dashboard stats, recent tasks and recent risks from task endpoints', async () => {
    ;(fetchTasks as jest.Mock).mockResolvedValue({
      data: [
        {
          id: 'task-1',
          name: '任务一',
          status: 'completed',
          highestRiskLevel: 'high',
          createdAt: '2026-04-14 10:00:00',
        },
        {
          id: 'task-2',
          name: '任务二',
          status: 'completed',
          highestRiskLevel: 'low',
          createdAt: '2026-04-14 09:00:00',
        },
      ],
    })
    ;(fetchTaskRisks as jest.Mock)
      .mockResolvedValueOnce({
        data: [
          {
            id: 'risk-1',
            title: '高危风险',
            level: 'high',
            url: 'https://example.com/a',
            type: 'sqli',
            description: '',
            createdAt: '2026-04-14 11:00:00',
          },
        ],
      })
      .mockResolvedValueOnce({
        data: [
          {
            id: 'risk-2',
            title: '低危风险',
            level: 'low',
            url: 'https://example.com/b',
            type: 'info',
            description: '',
            createdAt: '2026-04-14 08:00:00',
          },
        ],
      })
    ;(fetchTaskJS as jest.Mock)
      .mockResolvedValueOnce({ data: [{}, {}] })
      .mockResolvedValueOnce({ data: [{}] })

    const result = await dashboardService.getDashboardSnapshot()

    expect(result.stats).toEqual({
      totalTasks: 2,
      totalRisks: 2,
      totalJS: 3,
      highRiskTasks: 1,
    })
    expect(result.recentTasks.map((task) => task.id)).toEqual(['task-1', 'task-2'])
    expect(result.recentRisks[0]).toMatchObject({
      id: 'risk-1',
      taskId: 'task-1',
      taskName: '任务一',
    })
    expect(result.trends.tasks).toHaveLength(7)
    expect(result.trends.risks).toHaveLength(7)
  })
})

import {
  buildTaskDetailPath,
  resolveTaskDeletePageTarget,
  resolveTaskActionLabel,
  resolveTaskExecutionProgress,
  resolveTaskExecutionStatus,
  resolveTaskPageTarget,
  resolveTaskScanCount,
} from './index'

describe('resolveTaskPageTarget', () => {
  test('clamps an out-of-range page to the last available page after page size changes', () => {
    expect(resolveTaskPageTarget(95, 10, 50)).toBe(2)
  })

  test('falls back to the first page when there are no records', () => {
    expect(resolveTaskPageTarget(0, 4, 20)).toBe(1)
  })
})

describe('buildTaskDetailPath', () => {
  test('builds the task detail route from a task identifier', () => {
    expect(buildTaskDetailPath('42')).toBe('/tasks/42')
  })

  test('builds a version-aware task detail route when a version is provided', () => {
    expect(buildTaskDetailPath('42', 3)).toBe('/tasks/42?version=3')
  })
})

describe('resolveTaskDeletePageTarget', () => {
  test('moves back one page when deleting the last row on the current page', () => {
    expect(resolveTaskDeletePageTarget(11, 2, 10, 1)).toBe(1)
  })

  test('keeps the current page when rows remain after deletion', () => {
    expect(resolveTaskDeletePageTarget(25, 2, 10, 3)).toBe(2)
  })
})

describe('task execution helpers', () => {
  test('prefers latest version execution status and progress', () => {
    expect(
      resolveTaskExecutionStatus({
        id: 'task-1',
        name: 'Task 1',
        status: 'pending',
        latestStatus: 'running',
        createdAt: '2026-04-14 10:00:00',
      }),
    ).toBe('running')

    expect(
      resolveTaskExecutionProgress({
        id: 'task-1',
        name: 'Task 1',
        status: 'pending',
        progress: 0,
        latestProgress: 42,
        createdAt: '2026-04-14 10:00:00',
      }),
    ).toBe(42)
  })

  test('resolves action labels for running, restarted and fresh tasks', () => {
    expect(
      resolveTaskActionLabel({
        id: 'task-1',
        name: 'Task 1',
        status: 'running',
        createdAt: '2026-04-14 10:00:00',
      }),
    ).toBe('停止')

    expect(
      resolveTaskActionLabel({
        id: 'task-2',
        name: 'Task 2',
        status: 'completed',
        versionCount: 2,
        createdAt: '2026-04-14 10:00:00',
      }),
    ).toBe('重扫')

    expect(
      resolveTaskActionLabel({
        id: 'task-3',
        name: 'Task 3',
        status: 'pending',
        createdAt: '2026-04-14 10:00:00',
      }),
    ).toBe('启动')
  })

  test('prefers version summary fields when resolving scan count', () => {
    expect(
      resolveTaskScanCount({
        id: 'task-4',
        name: 'Task 4',
        status: 'completed',
        latestVersion: 3,
        versionCount: 2,
        createdAt: '2026-04-14 10:00:00',
      }),
    ).toBe(3)
  })
})

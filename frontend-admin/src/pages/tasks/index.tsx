import {
  DeleteOutlined,
  EyeOutlined,
  LoadingOutlined,
  PlusOutlined,
  PauseCircleOutlined,
  PlayCircleOutlined,
  RedoOutlined,
} from '@ant-design/icons';
import {
  Button,
  Card,
  Input,
  Popconfirm,
  Progress,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from 'antd';
import { useEffect, useRef, useState } from 'react';

import {
  deleteTaskRecord,
  fetchTasks,
  type FetchTasksFilters,
  restartTaskScan,
  startTaskScan,
  stopTaskScan,
} from '@/services/tasks';
import type { TaskSummary } from '@/types/task';
import { formatDateTime } from '@/utils/datetime';
import { history } from 'umi';
import CreateTaskModal from './components/CreateTaskModal';

const STATUS_OPTIONS = [
  { label: '全部状态', value: undefined },
  { label: '待执行', value: 'pending' },
  { label: '执行中', value: 'running' },
  { label: '已完成', value: 'completed' },
  { label: '失败', value: 'failed' },
  { label: '已停止', value: 'stopped' },
];

const TASK_DETAIL_SEED_KEY = 'trailblazer_task_detail_seed';

const STATUS_LABELS: Record<string, string> = {
  pending: '待执行',
  running: '执行中',
  completed: '已完成',
  failed: '失败',
  stopped: '已停止',
};

const STATUS_COLORS: Record<string, string> = {
  pending: 'default',
  running: 'processing',
  completed: 'success',
  failed: 'error',
  stopped: 'warning',
};

const RISK_COLORS: Record<string, string> = {
  high: 'error',
  medium: 'warning',
  low: 'success',
  info: 'default',
};

const RISK_LABELS: Record<string, string> = {
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

export function resolveTaskPageTarget(
  total: number,
  requestedPage: number,
  requestedPageSize: number,
) {
  const maxPage = Math.max(
    1,
    Math.ceil(total / Math.max(1, requestedPageSize)),
  );
  return Math.min(Math.max(1, requestedPage), maxPage);
}

export function resolveTaskDeletePageTarget(
  total: number,
  currentPage: number,
  currentPageSize: number,
  remainingRowsOnPage: number,
) {
  const nextTotal = Math.max(0, total - 1);
  const shouldStepBack = remainingRowsOnPage <= 1 && currentPage > 1;
  const requestedPage = shouldStepBack ? currentPage - 1 : currentPage;
  return resolveTaskPageTarget(nextTotal, requestedPage, currentPageSize);
}

export function buildTaskDetailPath(taskId: string | number, version?: number) {
  if (version && version > 0) {
    return `/tasks/${taskId}?version=${version}`;
  }
  return `/tasks/${taskId}`;
}

export function resolveTaskExecutionStatus(task: TaskSummary) {
  return task.latestStatus || task.status || 'pending';
}

export function resolveTaskExecutionProgress(task: TaskSummary) {
  const progress = task.latestProgress ?? task.progress;
  if (typeof progress !== 'number' || Number.isNaN(progress)) {
    return 0;
  }
  return Math.max(0, Math.min(100, progress));
}

export function resolveTaskActionLabel(task: TaskSummary) {
  const status = resolveTaskExecutionStatus(task);
  if (status === 'running') {
    return '停止';
  }
  if (
    (task.versionCount || 0) > 0 ||
    ['completed', 'failed', 'stopped'].includes(status)
  ) {
    return '重扫';
  }
  return '启动';
}

export function resolveTaskScanCount(task: TaskSummary) {
  return Math.max(task.versionCount || 0, task.latestVersion || 0, 0);
}

const renderTaskActions = (
  record: TaskSummary,
  loading: boolean,
  onExecute: () => void,
  onView: () => void,
  onDelete: () => void,
) => {
  const actionButtonStyle = {
    minWidth: 72,
    justifyContent: 'center' as const,
  };

  return (
    <Space size={8}>
      <Button
        size="small"
        type={
          resolveTaskExecutionStatus(record) === 'running'
            ? 'default'
            : 'primary'
        }
        icon={loading ? <LoadingOutlined /> : getTaskActionIcon(record)}
        disabled={!record.targets?.length}
        style={actionButtonStyle}
        onClick={onExecute}
      >
        {resolveTaskActionLabel(record)}
      </Button>
      <Button
        size="small"
        icon={<EyeOutlined />}
        style={actionButtonStyle}
        onClick={onView}
      >
        详情
      </Button>
      <Popconfirm
        title="确认删除该任务吗？"
        description="删除后将无法恢复。"
        okText="删除"
        cancelText="取消"
        okButtonProps={{ danger: true }}
        onConfirm={onDelete}
      >
        <Button
          size="small"
          icon={<DeleteOutlined />}
          danger
          style={actionButtonStyle}
        >
          删除
        </Button>
      </Popconfirm>
    </Space>
  );
};

const getTaskActionIcon = (task: TaskSummary) => {
  const status = resolveTaskExecutionStatus(task);
  if (status === 'running') {
    return <PauseCircleOutlined />;
  }
  if (resolveTaskActionLabel(task) === '重扫') {
    return <RedoOutlined />;
  }
  return <PlayCircleOutlined />;
};

const persistTaskDetailSeed = (task: TaskSummary) => {
  try {
    window.sessionStorage.setItem(TASK_DETAIL_SEED_KEY, JSON.stringify(task));
  } catch {
    // Best effort only.
  }
};

export default function TasksPage() {
  const [tasks, setTasks] = useState<TaskSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [total, setTotal] = useState(0);
  const [createOpen, setCreateOpen] = useState(false);
  const [keywordInput, setKeywordInput] = useState('');
  const [keyword, setKeyword] = useState('');
  const [statusFilter, setStatusFilter] = useState<string | undefined>();
  const requestSeq = useRef(0);
  const isMounted = useRef(false);
  const activeLoadingCount = useRef(0);

  const currentFilters: FetchTasksFilters = {
    keyword: keyword || undefined,
    status: statusFilter,
  };

  const beginLoading = () => {
    activeLoadingCount.current += 1;
    setLoading(true);
  };

  const endLoading = () => {
    activeLoadingCount.current = Math.max(0, activeLoadingCount.current - 1);
    if (isMounted.current && activeLoadingCount.current === 0) {
      setLoading(false);
    }
  };

  const loadTasks = async (
    nextPage = page,
    nextSize = pageSize,
    filters: FetchTasksFilters = currentFilters,
    silent = false,
  ) => {
    const requestId = ++requestSeq.current;
    if (!silent) {
      beginLoading();
    }
    try {
      const resp = await fetchTasks(nextPage, nextSize, filters);
      if (!isMounted.current || requestId !== requestSeq.current) {
        return;
      }
      setTasks(resp?.data || []);
      setTotal(resp?.pagination?.total ?? 0);
    } catch (error) {
      if (!isMounted.current || requestId !== requestSeq.current) {
        return;
      }
      if (!silent) {
        message.error('加载任务列表失败');
      }
    } finally {
      if (!silent) {
        endLoading();
      }
    }
  };

  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
      requestSeq.current += 1;
    };
  }, []);

  useEffect(() => {
    if (!isMounted.current) {
      return;
    }
    void loadTasks(page, pageSize, currentFilters);
  }, [page, pageSize, keyword, statusFilter]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setKeyword((current) =>
        current === keywordInput.trim() ? current : keywordInput.trim(),
      );
      setPage(1);
    }, 300);

    return () => window.clearTimeout(timer);
  }, [keywordInput]);

  useEffect(() => {
    const hasRunningTask = tasks.some(
      (task) => resolveTaskExecutionStatus(task) === 'running',
    );
    if (!hasRunningTask) {
      return;
    }

    const timer = window.setTimeout(() => {
      void loadTasks(page, pageSize, currentFilters, true);
    }, 2000);

    return () => window.clearTimeout(timer);
  }, [page, pageSize, tasks, keyword, statusFilter]);

  const handleTableChange = (pagination: {
    current?: number;
    pageSize?: number;
  }) => {
    const nextPage = pagination.current || 1;
    const nextPageSize = pagination.pageSize || 10;
    const targetPage = resolveTaskPageTarget(total, nextPage, nextPageSize);
    setPage(targetPage);
    setPageSize(nextPageSize);
  };

  const handleDeleteTask = async (record: TaskSummary) => {
    const remainingRowsOnPage = tasks.length;
    const targetPage = resolveTaskDeletePageTarget(
      total,
      page,
      pageSize,
      remainingRowsOnPage,
    );

    beginLoading();
    try {
      await deleteTaskRecord(record.id);
      message.success('任务删除成功');
      setPage(targetPage);
      await loadTasks(targetPage, pageSize, currentFilters);
    } catch (error) {
      message.error('删除任务失败');
    } finally {
      endLoading();
    }
  };

  const handleTaskExecution = async (record: TaskSummary) => {
    const effectiveStatus = resolveTaskExecutionStatus(record);
    const targets = record.targets || [];
    if (!targets.length) {
      message.error('任务缺少目标 URL，无法执行');
      return;
    }

    beginLoading();
    try {
      if (effectiveStatus === 'running') {
        await stopTaskScan(record.id);
        message.success('任务已停止');
      } else if (resolveTaskActionLabel(record) === '重扫') {
        await restartTaskScan(record);
        message.success('任务已重新启动扫描');
      } else {
        await startTaskScan({
          taskId: record.id,
          urls: targets,
        });
        message.success('任务已启动扫描');
      }

      await loadTasks(page, pageSize, currentFilters);
    } catch (error) {
      console.error(error);
      message.error(`${resolveTaskActionLabel(record)}任务失败`);
    } finally {
      endLoading();
    }
  };

  const columns = [
    {
      title: '任务名称',
      dataIndex: 'name',
      render: (value: string, record: TaskSummary) => (
        <Button
          type="link"
          style={{ paddingInline: 0 }}
          onClick={() => {
            persistTaskDetailSeed(record);
            history.push(buildTaskDetailPath(record.id));
          }}
        >
          {value || '-'}
        </Button>
      ),
    },
    {
      title: '执行状态',
      key: 'executionStatus',
      render: (_: unknown, record: TaskSummary) => {
        const status = resolveTaskExecutionStatus(record);
        return (
          <Tag color={STATUS_COLORS[status] || 'default'}>
            {STATUS_LABELS[status] || status}
          </Tag>
        );
      },
    },
    {
      title: '当前进度',
      key: 'executionProgress',
      width: 180,
      render: (_: unknown, record: TaskSummary) => (
        <Progress percent={resolveTaskExecutionProgress(record)} size="small" />
      ),
    },
    {
      title: '扫描次数',
      key: 'scanCount',
      width: 160,
      render: (_: unknown, record: TaskSummary) => {
        const scanCount = resolveTaskScanCount(record);
        if (!scanCount) {
          return '-';
        }

        return (
          <Space direction="vertical" size={0}>
            <Typography.Text strong>{scanCount} 次</Typography.Text>
            <Typography.Text type="secondary">
              最新版本 v{record.latestVersion || scanCount}
            </Typography.Text>
          </Space>
        );
      },
    },
    {
      title: '最高风险',
      dataIndex: 'highestRiskLevel',
      width: 120,
      render: (value: string | undefined) =>
        value ? (
          <Tag color={RISK_COLORS[value] || 'default'}>
            {RISK_LABELS[value] || value}
          </Tag>
        ) : (
          '-'
        ),
    },
    {
      title: '创建时间',
      dataIndex: 'createdAt',
      render: (value: string | undefined) => formatDateTime(value),
    },
    {
      title: '操作',
      key: 'actions',
      width: 280,
      render: (_: unknown, record: TaskSummary) =>
        renderTaskActions(
          record,
          loading,
          () => void handleTaskExecution(record),
          () => {
            persistTaskDetailSeed(record);
            history.push(buildTaskDetailPath(record.id));
          },
          () => void handleDeleteTask(record),
        ),
    },
  ];

  return (
    <Card
      styles={{
        body: {
          padding: 20,
        },
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: 16,
          flexWrap: 'wrap',
          marginBottom: 16,
        }}
      >
        <Space wrap>
          <Input
            allowClear
            value={keywordInput}
            placeholder="按任务名称、任务 ID 或目标筛选"
            style={{ width: 280 }}
            onChange={(event) => setKeywordInput(event.target.value)}
          />
          <Select
            allowClear
            value={statusFilter}
            placeholder="按状态筛选"
            options={STATUS_OPTIONS.filter((option) => option.value !== undefined)}
            style={{ width: 168 }}
            onChange={(value) => {
              setStatusFilter(value);
              setPage(1);
            }}
            onClear={() => {
              setStatusFilter(undefined);
              setPage(1);
            }}
          />
        </Space>

        <div
          style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}
        >
          <Typography.Text type="secondary">
            列表保留分页、执行与删除操作，后续会补齐筛选和批量能力。
          </Typography.Text>
          <Space wrap>
            <Button onClick={() => void loadTasks(page, pageSize, currentFilters)}>
              刷新
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setCreateOpen(true)}
            >
              创建任务
            </Button>
          </Space>
        </div>
      </div>

      <Table
        rowKey="id"
        loading={loading}
        columns={columns}
        dataSource={tasks}
        pagination={{
          current: page,
          pageSize,
          total,
          showSizeChanger: true,
        }}
        onChange={handleTableChange}
      />

      <CreateTaskModal
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onCreated={() => {
          setPage(1);
          void loadTasks(1, pageSize, currentFilters);
        }}
      />
    </Card>
  );
}

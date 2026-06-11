import { useEffect, useMemo, useRef, useState } from 'react';

import {
  Button,
  Card,
  Select,
  Space,
  Spin,
  Tabs,
  Tag,
  Timeline,
  Typography,
  message,
} from 'antd';

import {
  deriveAssetData,
  downloadTaskHTMLReport,
  fetchTaskAPIs,
  fetchTaskAssets,
  fetchTaskDetail,
  fetchTaskJSResources,
  fetchTaskProtocolTraces,
  fetchTaskRisks,
  fetchTaskStaticProtocolAnalysis,
  fetchTaskTree,
  fetchTaskVersions,
  normalizeRisks,
  restartTaskScan,
  startTaskScan,
  stopTaskScan,
} from '@/services/tasks';
import type {
  APIResource,
  AssetData,
  JSResource,
  ProtocolTrace,
  Risk,
  StaticProtocolAnalysis,
  TaskSummary,
  TaskVersionSummary,
  TreeNode,
} from '@/types/task';
import { formatDateTime } from '@/utils/datetime';
import { history, useLocation, useParams } from 'umi';

import AssetsPanel from './components/AssetsPanel';
import ProtocolAnalysisPanel from './components/ProtocolAnalysisPanel';
import RiskWorkbench from './components/RiskWorkbench';
import SiteTreePanel from './components/SiteTreePanel';
import TaskOverview from './components/TaskOverview';

const TASK_DETAIL_SEED_KEY = 'trailblazer_task_detail_seed';

const VERSION_STATUS_LABELS: Record<string, string> = {
  pending: '待执行',
  running: '执行中',
  completed: '已完成',
  failed: '失败',
  stopped: '已停止',
};

const VERSION_STATUS_COLORS: Record<string, string> = {
  pending: 'default',
  running: 'processing',
  completed: 'success',
  failed: 'error',
  stopped: 'warning',
};

const TASK_ACTION_LABELS: Record<string, string> = {
  pending: '启动',
  running: '停止',
  completed: '重扫',
  failed: '重扫',
  stopped: '重扫',
};

const readTaskDetailSeed = (taskId: string): TaskSummary | null => {
  try {
    const raw = window.sessionStorage.getItem(TASK_DETAIL_SEED_KEY);
    if (!raw) {
      return null;
    }

    const parsed = JSON.parse(raw) as TaskSummary | null;
    if (!parsed || parsed.id !== taskId) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
};

export default function TaskDetailPage() {
  const params = useParams<{ id: string }>();
  const location = useLocation();
  const taskId = params.id ? String(params.id) : '';
  const selectedVersion = useMemo(() => {
    const raw = new URLSearchParams(location.search).get('version');
    if (!raw) {
      return undefined;
    }

    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
  }, [location.search]);

  const [task, setTask] = useState<TaskSummary | null>(null);
  const [treeData, setTreeData] = useState<TreeNode[]>([]);
  const [treeNodeCount, setTreeNodeCount] = useState(0);
  const [risks, setRisks] = useState<Risk[]>([]);
  const [assets, setAssets] = useState<AssetData | null>(null);
  const [jsResources, setJSResources] = useState<JSResource[]>([]);
  const [apiResources, setAPIResources] = useState<APIResource[]>([]);
  const [protocolTraces, setProtocolTraces] = useState<ProtocolTrace[]>([]);
  const [staticAnalysis, setStaticAnalysis] =
    useState<StaticProtocolAnalysis | null>(null);
  const [versions, setVersions] = useState<TaskVersionSummary[]>([]);
  const [taskLoading, setTaskLoading] = useState(false);
  const [treeLoading, setTreeLoading] = useState(false);
  const [riskLoading, setRiskLoading] = useState(false);
  const [assetLoading, setAssetLoading] = useState(false);
  const [searchContentLoading, setSearchContentLoading] = useState(false);
  const [protocolLoading, setProtocolLoading] = useState(false);
  const [versionsLoading, setVersionsLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [exportLoading, setExportLoading] = useState(false);
  const [initialLoaded, setInitialLoaded] = useState(false);

  const isMounted = useRef(true);
  const activeTaskIdRef = useRef('');
  const riskLoadingRef = useRef(false);
  const riskLoadingTaskIdRef = useRef('');
  const riskCountRef = useRef(0);

  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  const loadTaskDetail = async () => {
    const requestTaskId = taskId;
    setTaskLoading(true);
    try {
      const detail = await fetchTaskDetail(taskId, {
        version: selectedVersion,
      });
      if (!isMounted.current || activeTaskIdRef.current !== requestTaskId) {
        return;
      }
      setTask(detail || readTaskDetailSeed(taskId));
    } catch (error) {
      console.error(error);
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        setTask(readTaskDetailSeed(taskId));
      }
    } finally {
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        setTaskLoading(false);
      }
    }
  };

  const loadTree = async () => {
    const requestTaskId = taskId;
    setTreeLoading(true);
    try {
      const response = await fetchTaskTree(taskId, {
        version: selectedVersion,
      });
      if (!isMounted.current || activeTaskIdRef.current !== requestTaskId) {
        return;
      }
      setTreeData(response?.data || []);
      setTreeNodeCount(
        typeof response?.totalNodeCount === 'number'
          ? response.totalNodeCount
          : typeof response?.nodeCount === 'number'
            ? response.nodeCount
            : 0,
      );
    } catch (error) {
      console.error(error);
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        message.warning('网站树加载失败');
        setTreeData([]);
        setTreeNodeCount(0);
      }
    } finally {
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        setTreeLoading(false);
      }
    }
  };

  const loadAssets = async () => {
    const requestTaskId = taskId;
    setAssetLoading(true);
    try {
      const response = await fetchTaskAssets(taskId, {
        version: selectedVersion,
      });
      if (!isMounted.current || activeTaskIdRef.current !== requestTaskId) {
        return;
      }
      setAssets(response?.data || null);
    } catch (error) {
      console.error(error);
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        setAssets((current) => current);
      }
    } finally {
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        setAssetLoading(false);
      }
    }
  };

  const loadProtocolAnalysis = async () => {
    const requestTaskId = taskId;
    setProtocolLoading(true);
    try {
      const [traceResponse, staticResponse] = await Promise.all([
        fetchTaskProtocolTraces(taskId, { version: selectedVersion }),
        fetchTaskStaticProtocolAnalysis(taskId, { version: selectedVersion }),
      ]);
      if (!isMounted.current || activeTaskIdRef.current !== requestTaskId) {
        return;
      }
      setProtocolTraces(traceResponse?.data || []);
      setStaticAnalysis(staticResponse?.data || null);
    } catch (error) {
      console.error(error);
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        setProtocolTraces([]);
        setStaticAnalysis(null);
      }
    } finally {
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        setProtocolLoading(false);
      }
    }
  };

  const loadSearchContent = async () => {
    const requestTaskId = taskId;
    setSearchContentLoading(true);
    try {
      const [jsResponse, apiResponse] = await Promise.all([
        fetchTaskJSResources(taskId, { version: selectedVersion }),
        fetchTaskAPIs(taskId, { version: selectedVersion }),
      ]);
      if (!isMounted.current || activeTaskIdRef.current !== requestTaskId) {
        return;
      }
      setJSResources(jsResponse);
      setAPIResources(apiResponse);
    } catch (error) {
      console.error(error);
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        setJSResources([]);
        setAPIResources([]);
      }
    } finally {
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        setSearchContentLoading(false);
      }
    }
  };

  const loadVersions = async () => {
    const requestTaskId = taskId;
    setVersionsLoading(true);
    try {
      const response = await fetchTaskVersions(taskId);
      if (!isMounted.current || activeTaskIdRef.current !== requestTaskId) {
        return;
      }
      setVersions(response);
    } catch (error) {
      console.error(error);
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        setVersions([]);
      }
    } finally {
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        setVersionsLoading(false);
      }
    }
  };

  const loadRisks = async (showLoading = true) => {
    const requestTaskId = taskId;
    if (
      !requestTaskId ||
      (riskLoadingRef.current && riskLoadingTaskIdRef.current === requestTaskId)
    ) {
      return;
    }

    riskLoadingRef.current = true;
    riskLoadingTaskIdRef.current = requestTaskId;
    if (showLoading) {
      setRiskLoading(true);
    }

    try {
      const response = await fetchTaskRisks(taskId, {
        version: selectedVersion,
      });
      if (!isMounted.current || activeTaskIdRef.current !== requestTaskId) {
        return;
      }

      const normalizedRisks = normalizeRisks(response?.data || []);
      const previousCount = riskCountRef.current;
      riskCountRef.current = normalizedRisks.length;
      setRisks(normalizedRisks);

      if (!showLoading && normalizedRisks.length > previousCount) {
        message.success(
          `发现 ${normalizedRisks.length - previousCount} 个新漏洞`,
        );
      }
    } catch (error) {
      console.error(error);
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        if (showLoading) {
          message.warning('风险数据加载失败');
        }
        if (showLoading && riskCountRef.current === 0) {
          setRisks([]);
        }
      }
    } finally {
      if (riskLoadingTaskIdRef.current === requestTaskId) {
        riskLoadingRef.current = false;
        riskLoadingTaskIdRef.current = '';
      }
      if (
        showLoading &&
        isMounted.current &&
        activeTaskIdRef.current === requestTaskId
      ) {
        setRiskLoading(false);
      }
    }
  };

  const pollTaskRuntimeState = async () => {
    await Promise.all([loadTaskDetail(), loadVersions(), loadRisks(false)]);
  };

  useEffect(() => {
    if (!taskId) {
      return;
    }

    const requestTaskId = taskId;
    activeTaskIdRef.current = taskId;
    setInitialLoaded(false);
    setTask(null);
    setTreeData([]);
    setTreeNodeCount(0);
    setRisks([]);
    setAssets(null);
    setJSResources([]);
    setAPIResources([]);
    setProtocolTraces([]);
    setStaticAnalysis(null);
    setVersions([]);
    setTaskLoading(false);
    setTreeLoading(false);
    setRiskLoading(false);
    setAssetLoading(false);
    setSearchContentLoading(false);
    setProtocolLoading(false);
    riskCountRef.current = 0;
    riskLoadingRef.current = false;
    riskLoadingTaskIdRef.current = '';

    const bootstrap = async () => {
      await Promise.all([
        loadTaskDetail(),
        loadTree(),
        loadRisks(true),
        loadAssets(),
        loadSearchContent(),
        loadProtocolAnalysis(),
        loadVersions(),
      ]);
      if (isMounted.current && activeTaskIdRef.current === requestTaskId) {
        setInitialLoaded(true);
      }
    };

    void bootstrap();

    const timer = window.setInterval(() => {
      if (selectedVersion == null) {
        void pollTaskRuntimeState();
        return;
      }

      void loadVersions();
      void loadRisks(false);
    }, 5000);

    return () => {
      window.clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedVersion, taskId]);

  useEffect(() => {
    if (assets || !taskId) {
      return;
    }

    if (treeData.length === 0 && risks.length === 0) {
      return;
    }

    setAssets(deriveAssetData(taskId, task?.name || '', treeData, risks));
  }, [assets, risks, task?.name, taskId, treeData]);

  const headerTitle =
    task?.name || (taskId ? `任务详情 #${taskId}` : '任务详情');
  const hasVersionHistory = versions.length > 1;
  const selectedVersionMeta = selectedVersion
    ? versions.find((item) => item.version === selectedVersion)
    : versions.find((item) => item.isLatest);
  const isViewingLatest =
    selectedVersion == null || Boolean(selectedVersionMeta?.isLatest);
  const executionStatus =
    selectedVersionMeta?.status || task?.status || 'pending';
  const executionProgress = Math.max(
    0,
    Math.min(
      100,
      typeof selectedVersionMeta?.progress === 'number'
        ? selectedVersionMeta.progress
        : typeof task?.progress === 'number'
          ? task.progress
          : 0,
    ),
  );
  const executionActionLabel =
    TASK_ACTION_LABELS[executionStatus] ||
    (versions.length > 0 ||
    ['completed', 'failed', 'stopped'].includes(executionStatus)
      ? '重扫'
      : '启动');
  const selectedVersionValue = selectedVersion
    ? String(selectedVersion)
    : 'latest';
  const versionOptions = hasVersionHistory
    ? [
        {
          label: '最新扫描结果',
          value: 'latest',
        },
        ...versions.map((item) => ({
          label: `第 ${item.version} 次扫描 · ${VERSION_STATUS_LABELS[item.status] || item.status} · ${formatDateTime(item.createdAt)}`,
          value: String(item.version),
        })),
      ]
    : [];
  const overview = useMemo(
    () => (
      <TaskOverview
        task={task}
        treeNodeCount={treeNodeCount}
        risks={risks}
        assets={assets}
        executionStatus={executionStatus}
        executionProgress={executionProgress}
        selectedVersion={selectedVersion}
        selectedVersionMeta={selectedVersionMeta}
        versionCount={versions.length}
      />
    ),
    [
      assets,
      executionProgress,
      executionStatus,
      risks,
      selectedVersion,
      selectedVersionMeta,
      task,
      treeNodeCount,
      versions.length,
    ],
  );

  const jumpToVersion = (version?: number) => {
    history.push(
      version ? `/tasks/${taskId}?version=${version}` : `/tasks/${taskId}`,
    );
  };

  const handleExportReport = async () => {
    if (!task) {
      message.warning('任务详情尚未加载完成');
      return;
    }

    setExportLoading(true);
    try {
      const { blob, filename } = await downloadTaskHTMLReport(taskId, {
        version: selectedVersion,
      });
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => {
        window.URL.revokeObjectURL(url);
      }, 0);
      message.success('HTML 报告已开始导出');
    } catch (error) {
      console.error(error);
      message.error('导出 HTML 报告失败');
    } finally {
      setExportLoading(false);
    }
  };

  const refreshTaskContext = async () => {
    await Promise.all([
      pollTaskRuntimeState(),
      loadTree(),
      loadAssets(),
      loadSearchContent(),
      loadProtocolAnalysis(),
    ]);
  };

  const handleTaskExecution = async () => {
    if (!task) {
      return;
    }

    const targets = task.targets || [];
    if (!targets.length) {
      message.error('任务缺少目标 URL，无法执行');
      return;
    }

    setActionLoading(true);
    try {
      if (executionStatus === 'running') {
        await stopTaskScan(task.id);
        message.success('任务已停止');
      } else if (
        versions.length > 0 ||
        ['completed', 'failed', 'stopped'].includes(executionStatus)
      ) {
        await restartTaskScan(task);
        message.success('任务已重新启动扫描');
        if (!isViewingLatest) {
          history.push(`/tasks/${taskId}`);
        }
      } else {
        await startTaskScan({
          taskId: task.id,
          urls: targets,
        });
        message.success('任务已启动扫描');
      }

      await refreshTaskContext();
    } catch (error) {
      console.error(error);
      message.error(`${executionActionLabel}任务失败`);
    } finally {
      if (isMounted.current) {
        setActionLoading(false);
      }
    }
  };

  if (!taskId) {
    return (
      <Card style={{ margin: 16 }}>
        <p>未找到任务 ID</p>
        <Button onClick={() => history.push('/tasks')}>返回任务列表</Button>
      </Card>
    );
  }

  if (
    !initialLoaded &&
    (taskLoading ||
      treeLoading ||
      riskLoading ||
      assetLoading ||
      protocolLoading)
  ) {
    return (
      <div
        style={{
          minHeight: 320,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Spin />
      </div>
    );
  }

  return (
    <Card
      style={{ margin: 16 }}
      title={headerTitle}
      extra={
        <Space wrap size={12}>
          {hasVersionHistory ? (
            <Space size={8}>
              <span>历史扫描</span>
              <Select
                value={selectedVersionValue}
                loading={versionsLoading}
                options={versionOptions}
                style={{ minWidth: 260 }}
                onChange={(value) => {
                  history.push(
                    value === 'latest'
                      ? `/tasks/${taskId}`
                      : `/tasks/${taskId}?version=${value}`,
                  );
                }}
              />
            </Space>
          ) : null}
          {hasVersionHistory && selectedVersionMeta ? (
            <Tag
              color={
                VERSION_STATUS_COLORS[selectedVersionMeta.status] || 'default'
              }
            >
              第 {selectedVersionMeta.version} 次扫描
            </Tag>
          ) : null}
          <Button
            type={executionStatus === 'running' ? 'default' : 'primary'}
            loading={actionLoading}
            disabled={!task?.targets?.length || !isViewingLatest}
            onClick={() => void handleTaskExecution()}
          >
            {isViewingLatest ? executionActionLabel : '切换到最新后操作'}
          </Button>
          <Button
            loading={exportLoading}
            disabled={!task}
            onClick={() => void handleExportReport()}
          >
            导出报告
          </Button>
          <Button onClick={() => history.push('/tasks')}>返回任务列表</Button>
        </Space>
      }
    >
      {hasVersionHistory ? (
        <Card
          size="small"
          title="扫描历史"
          style={{ marginBottom: 16 }}
          extra={
            <Typography.Text type="secondary">
              共 {versions.length} 次扫描
            </Typography.Text>
          }
        >
          <div
            style={{
              maxHeight: 420,
              overflowY: 'auto',
              paddingRight: 8,
            }}
          >
            <Timeline
              items={versions.map((item) => ({
                color:
                  item.version === selectedVersionMeta?.version
                    ? 'blue'
                    : undefined,
                children: (
                  <Space
                    direction="vertical"
                    size={4}
                    style={{ width: '100%', paddingBottom: 8 }}
                  >
                    <Space wrap size={8}>
                      <Button
                        type={
                          item.version === selectedVersionMeta?.version
                            ? 'primary'
                            : 'default'
                        }
                        size="small"
                        onClick={() =>
                          jumpToVersion(
                            item.isLatest ? undefined : item.version,
                          )
                        }
                      >
                        第 {item.version} 次扫描
                      </Button>
                      <Tag
                        color={VERSION_STATUS_COLORS[item.status] || 'default'}
                      >
                        {VERSION_STATUS_LABELS[item.status] || item.status}
                      </Tag>
                      {item.isLatest ? <Tag color="blue">最新</Tag> : null}
                      {item.triggerType ? <Tag>{item.triggerType}</Tag> : null}
                    </Space>
                    <Typography.Text type="secondary">
                      扫描时间：{formatDateTime(item.createdAt)}
                    </Typography.Text>
                    <Typography.Text type="secondary">
                      目标数：{item.targetsSnapshot.length}，进度：
                      {item.progress}%
                    </Typography.Text>
                  </Space>
                ),
              }))}
            />
          </div>
        </Card>
      ) : null}

      <Tabs
        items={[
          { key: 'overview', label: '概览', children: overview },
          {
            key: 'tree',
            label: '站点树',
            children: (
              <SiteTreePanel
                taskId={taskId}
                version={selectedVersion}
                treeData={treeData}
                jsResources={jsResources}
                apiResources={apiResources}
                loading={searchContentLoading}
              />
            ),
          },
          {
            key: 'risks',
            label: '风险',
            children: (
              <RiskWorkbench
                taskId={taskId}
                version={selectedVersion}
                risks={risks}
                protocolTraces={protocolTraces}
                loading={riskLoading}
                polling={Boolean(taskId)}
                onRefresh={() => void loadRisks(true)}
                onDeleted={() => void loadRisks(false)}
                onUpdated={() => void loadRisks(false)}
              />
            ),
          },
          {
            key: 'assets',
            label: '资产',
            children: <AssetsPanel assets={assets} />,
          },
          {
            key: 'protocol',
            label: '分析链路',
            children: (
              <ProtocolAnalysisPanel
                taskId={taskId}
                version={selectedVersion}
                loading={protocolLoading}
                traces={protocolTraces}
                staticAnalysis={staticAnalysis}
              />
            ),
          },
        ]}
      />
    </Card>
  );
}

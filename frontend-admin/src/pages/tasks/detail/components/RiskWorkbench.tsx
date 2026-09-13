import { useEffect, useMemo, useRef, useState } from 'react';

import { CaretRightOutlined, ClockCircleOutlined } from '@ant-design/icons';
import {
  Button,
  Card,
  Drawer,
  Empty,
  Input,
  List,
  Pagination,
  Popconfirm,
  Select,
  Space,
  Tag,
  Typography,
  message,
} from 'antd';

import {
  deleteTaskRisk,
  deleteTaskRiskCluster,
  updateTaskRiskStatus,
} from '@/services/tasks';
import type { Risk } from '@/types/task';
import { formatDateTime } from '@/utils/datetime';

interface Props {
  taskId: string;
  version?: number;
  risks: Risk[];
  loading?: boolean;
  polling?: boolean;
  initialSortMode?: RiskSortMode;
  onRefresh?: () => void;
  onDeleted?: (riskId: string) => void;
  onUpdated?: (riskId: string) => void;
}

type RiskListEntry =
  | {
      kind: 'risk';
      id: string;
      risk: Risk;
    }
  | {
      kind: 'cluster';
      id: string;
      clusterId: string;
      label: string;
      risks: Risk[];
      count: number;
      confidence: string;
      level: Risk['level'];
      kindLabel: string;
    };

type RiskSortMode =
  | 'default'
  | 'level_desc'
  | 'level_asc'
  | 'response_length_desc'
  | 'response_length_asc';

const levelColorMap: Record<Risk['level'], string> = {
  high: 'red',
  medium: 'orange',
  low: 'blue',
  info: 'default',
};

const levelLabelMap: Record<Risk['level'], string> = {
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

const confidenceColorMap: Record<string, string> = {
  high: 'success',
  medium: 'warning',
  low: 'default',
};

const confidenceLabelMap: Record<string, string> = {
  high: '高置信',
  medium: '中置信',
  low: '低置信',
};

const riskStatusColorMap: Record<string, string> = {
  open: 'gold',
  resolved: 'success',
  ignored: 'default',
};

const riskStatusLabelMap: Record<string, string> = {
  open: '待处理',
  resolved: '已修复',
  ignored: '已忽略',
};

const riskStatusOptions = [
  { label: '待处理', value: 'open' },
  { label: '已修复', value: 'resolved' },
  { label: '已忽略', value: 'ignored' },
];

const PAGE_SIZE_OPTIONS = ['10', '20', '50'];
const DEFAULT_PAGE_SIZE = 10;
const MIN_CLUSTER_SIZE = 3;
const CLUSTER_PAGE_SIZE = 20;
const SOURCE_MAP_PREFIX = 'sourceMap/';
const levelOrderMap: Record<Risk['level'], number> = {
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const sanitizeSummaryText = (value?: string) => {
  const text = (value || '').trim();
  if (!text) {
    return '';
  }

  return text
    .replace(/(?:^|[，,；;])\s*风险等级[:：][^，,；;]*/gi, '')
    .replace(/(?:^|[，,；;])\s*置信度[:：][^，,；;]*/gi, '')
    .replace(/(?:^|[，,；;])\s*响应长度[:：][^，,；;]*/gi, '')
    .replace(/(?:^|[，,；;])\s*发现[^，,；;]*漏洞/gi, '')
    .replace(/(?:^|[，,；;])\s+/g, ' ')
    .replace(/^[，,；;\s]+|[，,；;\s]+$/g, '')
    .trim();
};

const hasDisplayText = (value?: string) => Boolean((value || '').trim());

const hasCryptoKeyEvidence = (evidence?: Risk['cryptoKeyEvidence']) =>
  Boolean(
    evidence &&
    [
      evidence.algorithm,
      evidence.keyType,
      evidence.keyFormat,
      evidence.keyMaterial,
      evidence.fingerprint,
      evidence.sourceUrl,
      evidence.decoderPath,
      evidence.decryptFunction,
      evidence.verification,
    ].some(hasDisplayText),
  );

const buildRiskMetaLine = (
  risk: Pick<Risk, 'type' | 'category' | 'subcategory' | 'method'>,
) => {
  const classification = [risk.category?.trim(), risk.subcategory?.trim()]
    .filter(Boolean)
    .join(' / ');
  const parts = [classification || risk.type?.trim(), risk.method?.trim()].filter(
    Boolean,
  );
  return parts.length ? parts.join(' | ') : '-';
};

const normalizeRiskStatus = (status?: string) => {
  const normalized = (status || '').trim().toLowerCase();
  return normalized || 'open';
};

const renderRiskStatusTag = (status?: string) => {
  const normalized = normalizeRiskStatus(status);
  return (
    <Tag
      icon={normalized === 'open' ? <ClockCircleOutlined /> : undefined}
      color={riskStatusColorMap[normalized] || 'default'}
      style={{ marginInlineEnd: 0 }}
    >
      {riskStatusLabelMap[normalized] || normalized}
    </Tag>
  );
};

const buildRiskSummary = (risk: Risk) => {
  const parts: string[] = [];

  if (risk.confidenceReason) {
    parts.push(risk.confidenceReason.trim());
  } else {
    const sanitizedDescription = sanitizeSummaryText(risk.description);
    if (sanitizedDescription) {
      parts.push(sanitizedDescription);
    }
  }

  if (
    typeof risk.responseLength === 'number' &&
    Number.isFinite(risk.responseLength) &&
    risk.responseLength > 0
  ) {
    parts.push(`响应长度: ${risk.responseLength}`);
  }

  return parts.join('；') || '-';
};

const buildClusterSummary = (
  entry: Extract<RiskListEntry, { kind: 'cluster' }>,
) => {
  const parts = [
    `当前模板命中 ${entry.count} 个接口，默认折叠展示以降低重复噪音。`,
  ];
  const representativeReason = entry.risks[0]?.confidenceReason?.trim();
  if (representativeReason) {
    parts.push(`代表特征: ${representativeReason}`);
  }
  if (
    typeof entry.risks[0]?.responseLength === 'number' &&
    Number.isFinite(entry.risks[0]?.responseLength) &&
    (entry.risks[0]?.responseLength || 0) > 0
  ) {
    parts.push(`代表响应长度: ${entry.risks[0]?.responseLength}`);
  }
  return parts;
};

const buildRiskHitFeatures = (risk: Risk) => {
  const features: Array<{ key: string; label: string; color?: string }> = [];

  if (risk.staticContexts?.length) {
    features.push({
      key: 'static-context',
      label: `上下文命中 ${risk.staticContexts.length}`,
      color: 'purple',
    });
  }
  return features;
};

const buildClusterHitFeatures = (
  entry: Extract<RiskListEntry, { kind: 'cluster' }>,
) => {
  const featureMap = new Map<
    string,
    { label: string; color?: string; count: number }
  >();

  entry.risks.forEach((risk) => {
    buildRiskHitFeatures(risk).forEach((feature) => {
      const current = featureMap.get(feature.key);
      if (current) {
        current.count += 1;
        return;
      }
      featureMap.set(feature.key, {
        label: feature.label,
        color: feature.color,
        count: 1,
      });
    });
  });

  return Array.from(featureMap.entries()).map(([key, value]) => ({
    key,
    label: `${value.label} ${value.count}/${entry.count}`,
    color: value.color,
  }));
};

const shortenMiddle = (value: string, head = 40, tail = 24) => {
  if (value.length <= head + tail + 3) {
    return value;
  }
  return `${value.slice(0, head)}...${value.slice(-tail)}`;
};

const isSourceMapLocation = (value?: string) =>
  (value || '').trim().startsWith(SOURCE_MAP_PREFIX);

const parseSourceMapLocation = (value?: string) => {
  const normalized = (value || '').trim();
  if (!normalized.startsWith(SOURCE_MAP_PREFIX)) {
    return null;
  }

  const segments = normalized.split('/').filter(Boolean);
  const root = segments[1] || '';
  const relativePath = segments.slice(2).join('/');
  const fileName =
    relativePath.split('/').filter(Boolean).pop() || root || normalized;

  return {
    normalized,
    root,
    relativePath,
    fileName,
  };
};

const renderRiskLocation = (value?: string, compact = false) => {
  const normalized = (value || '').trim();
  if (!normalized) {
    return <Typography.Text type="secondary">-</Typography.Text>;
  }

  const sourceMapMeta = parseSourceMapLocation(normalized);
  if (!sourceMapMeta) {
    return (
      <Typography.Text
        title={normalized}
        style={{
          display: 'block',
          width: '100%',
          minWidth: 0,
          whiteSpace: compact ? 'nowrap' : 'normal',
          overflow: compact ? 'hidden' : 'visible',
          textOverflow: compact ? 'ellipsis' : 'clip',
          wordBreak: compact ? 'normal' : 'break-word',
          overflowWrap: compact ? 'normal' : 'anywhere',
        }}
      >
        {normalized}
      </Typography.Text>
    );
  }

  return (
    <Space
      direction="vertical"
      size={compact ? 2 : 6}
      style={{ width: '100%' }}
    >
      <Space wrap size={[8, 4]}>
        <Tag color="geekblue">SourceMap</Tag>
        <Typography.Text strong>{sourceMapMeta.fileName}</Typography.Text>
      </Space>
      {sourceMapMeta.relativePath ? (
        <Typography.Text
          code
          title={sourceMapMeta.relativePath}
          style={{
            display: 'block',
            width: '100%',
            minWidth: 0,
            whiteSpace: compact ? 'nowrap' : 'normal',
            overflow: compact ? 'hidden' : 'visible',
            textOverflow: compact ? 'ellipsis' : 'clip',
            wordBreak: compact ? 'normal' : 'break-word',
            overflowWrap: compact ? 'normal' : 'anywhere',
          }}
        >
          {compact
            ? shortenMiddle(sourceMapMeta.relativePath, 32, 18)
            : sourceMapMeta.relativePath}
        </Typography.Text>
      ) : null}
      <Typography.Text type="secondary">
        根目录:{' '}
        {compact
          ? shortenMiddle(sourceMapMeta.root || '-', 20, 10)
          : sourceMapMeta.root || '-'}
      </Typography.Text>
      {!compact ? (
        <Typography.Paragraph
          copyable={{ text: sourceMapMeta.normalized }}
          style={{
            margin: 0,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            overflowWrap: 'anywhere',
          }}
        >
          完整路径: {sourceMapMeta.normalized}
        </Typography.Paragraph>
      ) : null}
    </Space>
  );
};

export const filterRisks = ({
  risks,
  keyword,
  level,
  status,
  clusterFilter,
}: {
  risks: Risk[];
  keyword: string;
  level?: Risk['level'];
  status?: string;
  clusterFilter?: string;
}) => {
  const term = keyword.trim().toLowerCase();

  return risks.filter((risk) => {
    const matchesKeyword =
      !term ||
      risk.title.toLowerCase().includes(term) ||
      risk.url.toLowerCase().includes(term) ||
      risk.type.toLowerCase().includes(term);
    const matchesLevel = !level || risk.level === level;
    const matchesStatus =
      !status ||
      normalizeRiskStatus(risk.status) === normalizeRiskStatus(status);
    const clusterLabel = (risk.denyTemplateLabel || '').trim();
    const matchesCluster =
      !clusterFilter ||
      (clusterFilter === '__none__'
        ? !clusterLabel
        : clusterLabel === clusterFilter);
    return matchesKeyword && matchesLevel && matchesStatus && matchesCluster;
  });
};

export default function RiskWorkbench({
  taskId,
  version,
  risks,
  loading,
  polling,
  initialSortMode = 'level_desc',
  onRefresh,
  onDeleted,
  onUpdated,
}: Props) {
  const [keyword, setKeyword] = useState('');
  const [level, setLevel] = useState<Risk['level'] | undefined>();
  const [status, setStatus] = useState<string | undefined>();
  const [clusterFilter, setClusterFilter] = useState<string | undefined>();
  const [selected, setSelected] = useState<Risk | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [updatingRiskId, setUpdatingRiskId] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [sortMode, setSortMode] = useState<RiskSortMode>(initialSortMode);
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>(
    {},
  );
  const [clusterPages, setClusterPages] = useState<Record<string, number>>({});
  const [statusOverrides, setStatusOverrides] = useState<
    Record<string, string>
  >({});
  const activeTaskIdRef = useRef(taskId);
  const deleteTaskIdRef = useRef('');
  const deleteInFlightRef = useRef(false);

  useEffect(() => {
    activeTaskIdRef.current = taskId;
    deleteTaskIdRef.current = '';
    deleteInFlightRef.current = false;
    setKeyword('');
    setLevel(undefined);
    setStatus(undefined);
    setClusterFilter(undefined);
    setSelected(null);
    setDeleting(false);
    setUpdatingRiskId('');
    setPage(1);
    setPageSize(DEFAULT_PAGE_SIZE);
    setSortMode(initialSortMode);
    setExpandedGroups({});
    setClusterPages({});
    setStatusOverrides({});
  }, [initialSortMode, taskId]);

  const clusterOptions = useMemo(() => {
    const labels = Array.from(
      new Set(
        risks
          .map((risk) => (risk.denyTemplateLabel || '').trim())
          .filter(Boolean),
      ),
    ).sort((left, right) => left.localeCompare(right, 'zh-CN'));

    return [
      { label: '未归类', value: '__none__' },
      ...labels.map((label) => ({
        label,
        value: label,
      })),
    ];
  }, [risks]);

  const effectiveRisks = useMemo(
    () =>
      risks.map((risk) => {
        const nextStatus = statusOverrides[risk.id];
        if (!nextStatus) {
          return risk;
        }
        return {
          ...risk,
          status: nextStatus,
        };
      }),
    [risks, statusOverrides],
  );

  const filteredRisks = useMemo(() => {
    return filterRisks({
      risks: effectiveRisks,
      keyword,
      level,
      status,
      clusterFilter,
    });
  }, [clusterFilter, effectiveRisks, keyword, level, status]);

  const sortedRisks = useMemo(() => {
    const next = [...filteredRisks];
    if (sortMode === 'default') {
      return next;
    }

    next.sort((left, right) => {
      if (sortMode === 'level_desc' || sortMode === 'level_asc') {
        const delta = levelOrderMap[right.level] - levelOrderMap[left.level];
        if (delta !== 0) {
          return sortMode === 'level_desc' ? delta : -delta;
        }
      }

      if (
        sortMode === 'response_length_desc' ||
        sortMode === 'response_length_asc'
      ) {
        const leftLength = left.responseLength || 0;
        const rightLength = right.responseLength || 0;
        const delta = rightLength - leftLength;
        if (delta !== 0) {
          return sortMode === 'response_length_desc' ? delta : -delta;
        }
      }

      return (left.createdAt || '').localeCompare(right.createdAt || '');
    });

    return next;
  }, [filteredRisks, sortMode]);

  const pagedEntries = useMemo(() => {
    const entries: RiskListEntry[] = [];
    const grouped = new Set<string>();

    sortedRisks.forEach((risk) => {
      const clusterId = (risk.denyTemplateId || '').trim();
      const clusterLabel = (risk.denyTemplateLabel || '').trim();
      if (
        clusterId &&
        clusterLabel &&
        (risk.denyTemplateCount || 0) >= MIN_CLUSTER_SIZE
      ) {
        if (grouped.has(clusterId)) {
          return;
        }
        grouped.add(clusterId);
        const clusterRisks = sortedRisks.filter(
          (item) => item.denyTemplateId === clusterId,
        );
        entries.push({
          kind: 'cluster',
          id: `cluster-${clusterId}`,
          clusterId,
          label: clusterLabel,
          risks: clusterRisks,
          count: clusterRisks.length,
          confidence: risk.confidence || 'low',
          level: risk.level,
          kindLabel:
            risk.denyTemplateKind === 'auth_required'
              ? '认证拒绝簇'
              : '拒绝模板簇',
        });
        return;
      }

      entries.push({
        kind: 'risk',
        id: risk.id,
        risk,
      });
    });

    const start = (page - 1) * pageSize;
    return {
      total: entries.length,
      entries: entries.slice(start, start + pageSize),
    };
  }, [page, pageSize, sortedRisks]);

  useEffect(() => {
    setPage(1);
  }, [clusterFilter, keyword, level, sortMode, status]);

  useEffect(() => {
    const maxPage = Math.max(1, Math.ceil(pagedEntries.total / pageSize));
    if (page > maxPage) {
      setPage(maxPage);
    }
  }, [pagedEntries.total, page, pageSize]);
  const toggleGroup = (clusterId: string) => {
    setExpandedGroups((current) => ({
      ...current,
      [clusterId]: !current[clusterId],
    }));
    setClusterPages((current) => ({
      ...current,
      [clusterId]: current[clusterId] || 1,
    }));
  };

  const handleClusterPageChange = (clusterId: string, nextPage: number) => {
    setClusterPages((current) => ({
      ...current,
      [clusterId]: nextPage,
    }));
  };

  const handleDelete = async (risk: Risk) => {
    if (deleteInFlightRef.current) {
      return;
    }

    const requestTaskId = taskId;
    deleteInFlightRef.current = true;
    deleteTaskIdRef.current = requestTaskId;
    setDeleting(true);
    try {
      await deleteTaskRisk(risk.id);
      if (
        activeTaskIdRef.current !== requestTaskId ||
        deleteTaskIdRef.current !== requestTaskId
      ) {
        return;
      }
      message.success('漏洞删除成功');
      if (selected?.id === risk.id) {
        setSelected(null);
      }
      onDeleted?.(risk.id);
    } catch (error) {
      console.error(error);
      if (
        activeTaskIdRef.current !== requestTaskId ||
        deleteTaskIdRef.current !== requestTaskId
      ) {
        return;
      }
      message.error('删除漏洞失败');
    } finally {
      if (
        activeTaskIdRef.current === requestTaskId &&
        deleteTaskIdRef.current === requestTaskId
      ) {
        deleteTaskIdRef.current = '';
        deleteInFlightRef.current = false;
        setDeleting(false);
      }
    }
  };

  const handleUpdateStatus = async (risk: Risk, nextStatus: string) => {
    const normalizedNext = normalizeRiskStatus(nextStatus);
    const currentStatus = normalizeRiskStatus(risk.status);
    if (!risk.id || normalizedNext === currentStatus) {
      return;
    }

    setUpdatingRiskId(risk.id);
    try {
      await updateTaskRiskStatus(risk.id, { status: normalizedNext });
      setStatusOverrides((current) => ({
        ...current,
        [risk.id]: normalizedNext,
      }));
      if (selected?.id === risk.id) {
        setSelected((current) =>
          current ? { ...current, status: normalizedNext } : current,
        );
      }
      message.success('漏洞状态已更新');
      onUpdated?.(risk.id);
    } catch (error) {
      console.error(error);
      message.error('更新漏洞状态失败');
    } finally {
      setUpdatingRiskId('');
    }
  };

  const handleDeleteCluster = async (
    entry: Extract<RiskListEntry, { kind: 'cluster' }>,
  ) => {
    if (deleteInFlightRef.current) {
      return;
    }

    const requestTaskId = taskId;
    deleteInFlightRef.current = true;
    deleteTaskIdRef.current = requestTaskId;
    setDeleting(true);
    try {
      await deleteTaskRiskCluster(taskId, entry.clusterId, { version });
      if (
        activeTaskIdRef.current !== requestTaskId ||
        deleteTaskIdRef.current !== requestTaskId
      ) {
        return;
      }
      message.success(`已删除 ${entry.count} 条模板簇风险`);
      setExpandedGroups((current) => {
        const next = { ...current };
        delete next[entry.clusterId];
        return next;
      });
      if (selected?.denyTemplateId === entry.clusterId) {
        setSelected(null);
      }
      onDeleted?.(entry.clusterId);
    } catch (error) {
      console.error(error);
      if (
        activeTaskIdRef.current !== requestTaskId ||
        deleteTaskIdRef.current !== requestTaskId
      ) {
        return;
      }
      message.error('删除模板簇失败');
    } finally {
      if (
        activeTaskIdRef.current === requestTaskId &&
        deleteTaskIdRef.current === requestTaskId
      ) {
        deleteTaskIdRef.current = '';
        deleteInFlightRef.current = false;
        setDeleting(false);
      }
    }
  };

  return (
    <>
      <Card
        title="风险发现"
        extra={
          <Space>
            {polling ? <Tag color="processing">自动刷新中</Tag> : null}
            <Button onClick={onRefresh}>刷新</Button>
          </Space>
        }
        styles={{ body: { paddingTop: 16 } }}
      >
        <Space
          wrap
          style={{
            marginBottom: 16,
            width: '100%',
            justifyContent: 'space-between',
          }}
        >
          <Space wrap>
            <Input
              allowClear
              value={keyword}
              onChange={(event) => setKeyword(event.target.value)}
              placeholder="搜索风险标题、类型或 URL"
              style={{ width: 320 }}
            />
            <Select
              allowClear
              placeholder="风险等级"
              value={level}
              onChange={(value) => setLevel(value)}
              options={(
                ['high', 'medium', 'low', 'info'] as Risk['level'][]
              ).map((item) => ({
                label: levelLabelMap[item],
                value: item,
              }))}
              style={{ width: 160 }}
            />
            <Select
              allowClear
              placeholder="处置状态"
              value={status}
              onChange={(value) => setStatus(value)}
              options={riskStatusOptions}
              style={{ width: 160 }}
            />
            <Select
              allowClear
              data-testid="risk-cluster-select"
              placeholder="模板簇"
              value={clusterFilter}
              onChange={(value) => setClusterFilter(value)}
              options={clusterOptions}
              style={{ width: 220 }}
            />
            <Select
              data-testid="risk-sort-select"
              value={sortMode}
              onChange={(value) => setSortMode(value)}
              options={[
                { label: '默认排序', value: 'default' },
                { label: '风险等级: 高到低', value: 'level_desc' },
                { label: '风险等级: 低到高', value: 'level_asc' },
                { label: '响应长度: 长到短', value: 'response_length_desc' },
                { label: '响应长度: 短到长', value: 'response_length_asc' },
              ]}
              style={{ width: 200 }}
            />
          </Space>
          <Typography.Text type="secondary">
            共 {filteredRisks.length} 条风险
          </Typography.Text>
        </Space>

        <List
          loading={loading}
          locale={{ emptyText: <Empty description="暂无风险数据" /> }}
          dataSource={pagedEntries.entries}
          renderItem={(entry) => {
            if (entry.kind === 'cluster') {
              const expanded = Boolean(expandedGroups[entry.clusterId]);
              const clusterPage = clusterPages[entry.clusterId] || 1;
              const clusterPageStart = (clusterPage - 1) * CLUSTER_PAGE_SIZE;
              const visibleClusterRisks = entry.risks.slice(
                clusterPageStart,
                clusterPageStart + CLUSTER_PAGE_SIZE,
              );
              return (
                <List.Item key={entry.id} actions={[]}>
                  <List.Item.Meta
                    title={
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'flex-start',
                          justifyContent: 'space-between',
                          gap: 16,
                          width: '100%',
                        }}
                      >
                        <Space wrap size={8} style={{ flex: 1 }}>
                          <Button
                            key="toggle"
                            type="text"
                            size="small"
                            aria-label={expanded ? '收起接口' : '展开接口'}
                            onClick={() => toggleGroup(entry.clusterId)}
                            style={{
                              paddingInline: 4,
                              minWidth: 24,
                            }}
                            icon={
                              <CaretRightOutlined
                                style={{
                                  transition: 'transform 0.2s ease',
                                  transform: expanded
                                    ? 'rotate(90deg)'
                                    : 'rotate(0deg)',
                                }}
                              />
                            }
                          />
                          <Tag color={levelColorMap[entry.level]}>
                            {levelLabelMap[entry.level]}
                          </Tag>
                          <Tag
                            color={
                              confidenceColorMap[entry.confidence] || 'default'
                            }
                          >
                            {confidenceLabelMap[entry.confidence] ||
                              `${entry.confidence} 置信`}
                          </Tag>
                          <Tag>{entry.kindLabel}</Tag>
                          <Typography.Text strong>
                            {entry.label}
                          </Typography.Text>
                        </Space>
                        <Popconfirm
                          key="delete-cluster"
                          title="确认删除该模板簇吗？"
                          description={`将批量删除 ${entry.count} 条风险记录，删除后无法恢复。`}
                          disabled={deleting}
                          onConfirm={() => void handleDeleteCluster(entry)}
                          okButtonProps={{
                            danger: true,
                            loading: deleting,
                          }}
                        >
                          <Button
                            key="delete"
                            danger
                            type="link"
                            disabled={deleting}
                            style={{ paddingInline: 0, flexShrink: 0 }}
                          >
                            删除模板簇
                          </Button>
                        </Popconfirm>
                      </div>
                    }
                    description={
                      <Space
                        direction="vertical"
                        size={8}
                        style={{ width: '100%' }}
                      >
                        {buildClusterSummary(entry).map((line) => (
                          <Typography.Text key={line} type="secondary">
                            {line}
                          </Typography.Text>
                        ))}
                        {buildClusterHitFeatures(entry).length ? (
                          <Space wrap size={[4, 4]}>
                            {buildClusterHitFeatures(entry).map((feature) => (
                              <Tag key={feature.key} color={feature.color}>
                                {feature.label}
                              </Tag>
                            ))}
                          </Space>
                        ) : null}
                        {expanded ? (
                          <div
                            style={{
                              display: 'grid',
                              gap: 8,
                              padding: '8px 0 0',
                            }}
                          >
                            <Typography.Text type="secondary">
                              当前显示第 {clusterPage} 页，每页{' '}
                              {CLUSTER_PAGE_SIZE} 条。
                            </Typography.Text>
                            {visibleClusterRisks.map((risk) => (
                              <div
                                key={risk.id}
                                style={{
                                  display: 'flex',
                                  justifyContent: 'space-between',
                                  gap: 12,
                                  alignItems: 'flex-start',
                                  flexWrap: 'wrap',
                                  minWidth: 0,
                                }}
                              >
                                <Space
                                  direction="vertical"
                                  size={2}
                                  style={{ flex: 1, minWidth: 0 }}
                                >
                                  <Space wrap size={[4, 4]}>
                                    <Tag color={levelColorMap[risk.level]}>
                                      {levelLabelMap[risk.level]}
                                    </Tag>
                                    {risk.confidence ? (
                                      <Tag
                                        color={
                                          confidenceColorMap[risk.confidence] ||
                                          'default'
                                        }
                                      >
                                        {confidenceLabelMap[risk.confidence] ||
                                          `${risk.confidence} 置信`}
                                      </Tag>
                                    ) : null}
                                    {renderRiskStatusTag(risk.status)}
                                  </Space>
                                  <Typography.Text strong>
                                    {risk.title}
                                  </Typography.Text>
                                  <Typography.Text type="secondary">
                                    {buildRiskMetaLine(risk)}
                                  </Typography.Text>
                                  {renderRiskLocation(risk.url, true)}
                                  <Typography.Paragraph
                                    type="secondary"
                                    style={{
                                      margin: 0,
                                      display: '-webkit-box',
                                      WebkitBoxOrient: 'vertical',
                                      WebkitLineClamp: 2,
                                      overflow: 'hidden',
                                      whiteSpace: 'normal',
                                      wordBreak: 'break-word',
                                      overflowWrap: 'anywhere',
                                    }}
                                  >
                                    {buildRiskSummary(risk)}
                                  </Typography.Paragraph>
                                  {buildRiskHitFeatures(risk).length ? (
                                    <Space wrap size={[4, 4]}>
                                      {buildRiskHitFeatures(risk).map(
                                        (feature) => (
                                          <Tag
                                            key={feature.key}
                                            color={feature.color}
                                          >
                                            {feature.label}
                                          </Tag>
                                        ),
                                      )}
                                    </Space>
                                  ) : null}
                                </Space>
                                <Space
                                  wrap
                                  size={[8, 8]}
                                  style={{
                                    flexShrink: 0,
                                    width: 'auto',
                                    marginLeft: 'auto',
                                  }}
                                >
                                  <Select
                                    data-testid={`risk-status-select-${risk.id}`}
                                    size="small"
                                    value={normalizeRiskStatus(risk.status)}
                                    options={riskStatusOptions}
                                    style={{ width: 110 }}
                                    loading={updatingRiskId === risk.id}
                                    onChange={(value) =>
                                      void handleUpdateStatus(risk, value)
                                    }
                                  />
                                  <Button
                                    type="link"
                                    onClick={() => setSelected(risk)}
                                  >
                                    查看详情
                                  </Button>
                                  <Popconfirm
                                    title="确认删除该漏洞记录吗？"
                                    description="删除后将无法恢复。"
                                    disabled={deleting}
                                    onConfirm={() => void handleDelete(risk)}
                                    okButtonProps={{
                                      danger: true,
                                      loading: deleting,
                                    }}
                                  >
                                    <Button
                                      danger
                                      type="link"
                                      disabled={deleting}
                                    >
                                      删除
                                    </Button>
                                  </Popconfirm>
                                </Space>
                              </div>
                            ))}
                            {entry.count > CLUSTER_PAGE_SIZE ? (
                              <div
                                style={{
                                  display: 'flex',
                                  justifyContent: 'flex-end',
                                  paddingTop: 8,
                                }}
                              >
                                <Pagination
                                  simple
                                  current={clusterPage}
                                  pageSize={CLUSTER_PAGE_SIZE}
                                  total={entry.count}
                                  onChange={(nextPage) =>
                                    handleClusterPageChange(
                                      entry.clusterId,
                                      nextPage,
                                    )
                                  }
                                />
                              </div>
                            ) : null}
                          </div>
                        ) : null}
                      </Space>
                    }
                  />
                </List.Item>
              );
            }

            const risk = entry.risk;
            return (
              <List.Item
                key={risk.id}
                onClick={() => setSelected(risk)}
                style={{ cursor: 'pointer', minWidth: 0 }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    justifyContent: 'space-between',
                    gap: 12,
                    flexWrap: 'wrap',
                    width: '100%',
                    minWidth: 0,
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <List.Item.Meta
                      style={{ minWidth: 0 }}
                      title={
                        <Space wrap style={{ minWidth: 0 }}>
                          <Typography.Text strong>{risk.title}</Typography.Text>
                          <Tag color={levelColorMap[risk.level]}>
                            {levelLabelMap[risk.level]}
                          </Tag>
                          {risk.confidence ? (
                            <Tag
                              color={
                                confidenceColorMap[risk.confidence] || 'default'
                              }
                            >
                              {confidenceLabelMap[risk.confidence] ||
                                `${risk.confidence} 置信`}
                            </Tag>
                          ) : null}
                          {renderRiskStatusTag(risk.status)}
                          {risk.aiVerified ? (
                            <Tag color="processing">AI</Tag>
                          ) : null}
                        </Space>
                      }
                      description={
                        <Space
                          direction="vertical"
                          size={4}
                          style={{ width: '100%', minWidth: 0 }}
                        >
                          <Typography.Text type="secondary">
                            {buildRiskMetaLine(risk)}
                          </Typography.Text>
                          <div style={{ width: '100%', minWidth: 0 }}>
                            {renderRiskLocation(risk.url, true)}
                          </div>
                          <Typography.Paragraph
                            type="secondary"
                            style={{
                              margin: 0,
                              display: '-webkit-box',
                              WebkitBoxOrient: 'vertical',
                              WebkitLineClamp: 3,
                              overflow: 'hidden',
                              whiteSpace: 'normal',
                              wordBreak: 'break-word',
                              overflowWrap: 'anywhere',
                            }}
                          >
                            {buildRiskSummary(risk)}
                          </Typography.Paragraph>
                          {buildRiskHitFeatures(risk).length ? (
                            <Space wrap size={[4, 4]}>
                              {buildRiskHitFeatures(risk).map((feature) => (
                                <Tag key={feature.key} color={feature.color}>
                                  {feature.label}
                                </Tag>
                              ))}
                            </Space>
                          ) : null}
                        </Space>
                      }
                    />
                  </div>
                  <Space
                    wrap
                    size={[8, 8]}
                    onClick={(event) => event.stopPropagation()}
                    style={{
                      flexShrink: 0,
                      width: 'auto',
                      marginLeft: 'auto',
                    }}
                  >
                    <Select
                      key="status"
                      data-testid={`risk-status-select-${risk.id}`}
                      size="small"
                      value={normalizeRiskStatus(risk.status)}
                      options={riskStatusOptions}
                      style={{ width: 110 }}
                      loading={updatingRiskId === risk.id}
                      onClick={(event) => event.stopPropagation()}
                      onChange={(value) => void handleUpdateStatus(risk, value)}
                    />
                    <Button
                      key="detail"
                      type="link"
                      onClick={(event) => {
                        event.stopPropagation();
                        setSelected(risk);
                      }}
                    >
                      查看详情
                    </Button>
                    <Popconfirm
                      key="delete"
                      title="确认删除该漏洞记录吗？"
                      description="删除后将无法恢复。"
                      disabled={deleting}
                      onConfirm={(event) => {
                        event?.stopPropagation?.();
                        void handleDelete(risk);
                      }}
                      okButtonProps={{ danger: true, loading: deleting }}
                      onCancel={(event) => event?.stopPropagation?.()}
                    >
                      <Button
                        danger
                        type="link"
                        disabled={deleting}
                        onClick={(event) => event.stopPropagation()}
                      >
                        删除
                      </Button>
                    </Popconfirm>
                  </Space>
                </div>
              </List.Item>
            );
          }}
        />

        {pagedEntries.total ? (
          <div
            style={{
              display: 'flex',
              justifyContent: 'flex-end',
              marginTop: 16,
            }}
          >
            <Pagination
              current={page}
              pageSize={pageSize}
              total={pagedEntries.total}
              showSizeChanger
              pageSizeOptions={PAGE_SIZE_OPTIONS}
              onChange={(nextPage, nextPageSize) => {
                setPage(nextPage);
                if (nextPageSize !== pageSize) {
                  setPageSize(nextPageSize);
                }
              }}
            />
          </div>
        ) : null}
      </Card>

      <Drawer
        width={720}
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected?.title || '风险详情'}
        destroyOnClose
      >
        {selected ? (
          <div style={{ display: 'grid', gap: 16 }}>
            <Space wrap>
              <Tag color={levelColorMap[selected.level]}>
                {levelLabelMap[selected.level]}
              </Tag>
              {renderRiskStatusTag(selected.status)}
              {selected.confidence ? (
                <Tag
                  color={confidenceColorMap[selected.confidence] || 'default'}
                >
                  {confidenceLabelMap[selected.confidence] ||
                    `${selected.confidence} 置信`}
                </Tag>
              ) : null}
              {selected.aiVerified ? <Tag color="processing">AI</Tag> : null}
            </Space>

            <Card size="small">
              <Space direction="vertical" size={8}>
                {hasDisplayText(selected.type) ? (
                  <Typography.Text>类型: {selected.type}</Typography.Text>
                ) : null}
                {hasDisplayText(selected.category) ? (
                  <Typography.Text>
                    漏洞大类: {selected.category}
                  </Typography.Text>
                ) : null}
                {hasDisplayText(selected.subcategory) ? (
                  <Typography.Text>
                    漏洞小类: {selected.subcategory}
                  </Typography.Text>
                ) : null}
                {hasDisplayText(selected.businessObject) ? (
                  <Typography.Text>
                    业务对象: {selected.businessObject}
                  </Typography.Text>
                ) : null}
                {hasDisplayText(selected.method) ? (
                  <Typography.Text>方法: {selected.method}</Typography.Text>
                ) : null}
                {hasDisplayText(selected.url) ? (
                  <div>
                    <Typography.Text
                      style={{ display: 'block', marginBottom: 4 }}
                    >
                      {isSourceMapLocation(selected.url) ? '来源定位:' : 'URL:'}
                    </Typography.Text>
                    {renderRiskLocation(selected.url)}
                  </div>
                ) : null}
                {selected.confidence ? (
                  <Typography.Text>
                    置信度:{' '}
                    {confidenceLabelMap[selected.confidence] ||
                      selected.confidence}
                  </Typography.Text>
                ) : null}
                {selected.status ? (
                  <Typography.Text>
                    漏洞状态:{' '}
                    {riskStatusLabelMap[normalizeRiskStatus(selected.status)] ||
                      normalizeRiskStatus(selected.status)}
                  </Typography.Text>
                ) : null}
                {hasDisplayText(selected.confidenceReason) ? (
                  <Typography.Text>
                    置信度说明: {selected.confidenceReason}
                  </Typography.Text>
                ) : null}
                {hasDisplayText(selected.denyTemplateLabel) ? (
                  <Typography.Text>
                    拒绝模板簇: {selected.denyTemplateLabel}
                    {selected.denyTemplateCount
                      ? `（命中 ${selected.denyTemplateCount} 个接口）`
                      : ''}
                  </Typography.Text>
                ) : null}
                {hasDisplayText(selected.createdAt) ? (
                  <Typography.Text>
                    创建时间: {formatDateTime(selected.createdAt)}
                  </Typography.Text>
                ) : null}
                {hasDisplayText(selected.description) ? (
                  <Typography.Text>
                    描述: {selected.description}
                  </Typography.Text>
                ) : null}
              </Space>
            </Card>

            {hasDisplayText(selected.request) ? (
              <Card size="small" title="请求报文">
                <pre
                  style={{
                    margin: 0,
                    maxHeight: 240,
                    overflow: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}
                >
                  {selected.request}
                </pre>
              </Card>
            ) : null}

            {hasDisplayText(selected.responsePlaintext) ? (
              <Card size="small" title="响应解密明文">
                <pre
                  style={{
                    margin: 0,
                    maxHeight: 320,
                    overflow: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}
                >
                  {selected.responsePlaintext}
                </pre>
              </Card>
            ) : null}

            {hasDisplayText(selected.response) ? (
              <Card size="small" title="响应报文">
                <pre
                  style={{
                    margin: 0,
                    maxHeight: 320,
                    overflow: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}
                >
                  {selected.response}
                </pre>
              </Card>
            ) : null}

            {hasCryptoKeyEvidence(selected.cryptoKeyEvidence) ? (
              <Card size="small" title="泄露密钥证据">
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  {hasDisplayText(selected.cryptoKeyEvidence?.algorithm) ||
                  hasDisplayText(selected.cryptoKeyEvidence?.keyType) ? (
                    <Typography.Text>
                      算法/类型: {selected.cryptoKeyEvidence?.algorithm}
                      {selected.cryptoKeyEvidence?.keyType
                        ? ` / ${selected.cryptoKeyEvidence.keyType}`
                        : ''}
                    </Typography.Text>
                  ) : null}
                  {hasDisplayText(selected.cryptoKeyEvidence?.keyFormat) ||
                  selected.cryptoKeyEvidence?.keyBits ? (
                    <Typography.Text>
                      格式: {selected.cryptoKeyEvidence?.keyFormat}
                      {selected.cryptoKeyEvidence?.keyBits
                        ? `（${selected.cryptoKeyEvidence.keyBits} 位）`
                        : ''}
                    </Typography.Text>
                  ) : null}
                  {hasDisplayText(selected.cryptoKeyEvidence?.sourceUrl) ? (
                    <Typography.Text>
                      来源: {selected.cryptoKeyEvidence?.sourceUrl}
                    </Typography.Text>
                  ) : null}
                  {hasDisplayText(selected.cryptoKeyEvidence?.decoderPath) ? (
                    <Typography.Text>
                      提取链路: {selected.cryptoKeyEvidence?.decoderPath}
                    </Typography.Text>
                  ) : null}
                  {selected.cryptoKeyEvidence?.decryptFunction ? (
                    <Typography.Text>
                      解密函数: {selected.cryptoKeyEvidence?.decryptFunction}
                    </Typography.Text>
                  ) : null}
                  {selected.cryptoKeyEvidence?.verification ? (
                    <Typography.Text>
                      验证: {selected.cryptoKeyEvidence?.verification}
                    </Typography.Text>
                  ) : null}
                  {hasDisplayText(selected.cryptoKeyEvidence?.keyMaterial) ? (
                    <pre
                      style={{
                        margin: 0,
                        maxHeight: 320,
                        overflow: 'auto',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {selected.cryptoKeyEvidence?.keyMaterial}
                    </pre>
                  ) : null}
                </Space>
              </Card>
            ) : null}

            {selected.staticContexts?.length ? (
              <Card
                size="small"
                title="静态命中上下文"
                extra={
                  <Typography.Text type="secondary">
                    {selected.staticContexts.length} 条
                  </Typography.Text>
                }
              >
                <List
                  dataSource={selected.staticContexts}
                  renderItem={(item) => (
                    <List.Item>
                      <div style={{ display: 'grid', gap: 8, width: '100%' }}>
                        <Typography.Text strong>
                          {item.sourceUrl || '-'}
                        </Typography.Text>
                        <pre
                          style={{
                            margin: 0,
                            maxHeight: 220,
                            overflow: 'auto',
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-word',
                          }}
                        >
                          {item.snippet || '暂无上下文片段'}
                        </pre>
                      </div>
                    </List.Item>
                  )}
                />
              </Card>
            ) : null}

            <Space>
              <Popconfirm
                title="确认删除该漏洞记录吗？"
                description="删除后将无法恢复。"
                disabled={deleting}
                onConfirm={() => void handleDelete(selected)}
                okButtonProps={{ danger: true, loading: deleting }}
              >
                <Button danger loading={deleting} disabled={deleting}>
                  删除漏洞
                </Button>
              </Popconfirm>
            </Space>
          </div>
        ) : null}
      </Drawer>
    </>
  );
}

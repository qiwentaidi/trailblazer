import {
  Button,
  Card,
  Col,
  Descriptions,
  message,
  Progress,
  Row,
  Space,
  Statistic,
  Tag,
  Typography,
} from 'antd';
import { useMemo, useState } from 'react';

import type {
  AssetData,
  Risk,
  TaskSummary,
  TaskVersionSummary,
  TreeNode,
} from '@/types/task';
import {
  countTreeNodes,
  normalizeAssetBuckets,
  normalizeRiskLevel,
} from './taskDetailUtils';

interface Props {
  task: TaskSummary | null;
  treeData: TreeNode[];
  risks: Risk[];
  assets: AssetData | null;
  executionStatus: string;
  executionProgress: number;
  selectedVersion?: number;
  selectedVersionMeta?: TaskVersionSummary;
  versionCount?: number;
}

const countAssetGroups = (assets: AssetData | null) => {
  if (!assets) {
    return 0;
  }

  const normalizedAssets = normalizeAssetBuckets(assets);

  return [
    normalizedAssets.email,
    normalizedAssets.idCard,
    normalizedAssets.phone,
    normalizedAssets.ipUrl,
    normalizedAssets.apiRoot,
    normalizedAssets.apiRouter,
  ].filter((group) => group.length > 0).length;
};

const taskStatusColorMap: Record<string, string> = {
  pending: 'default',
  running: 'processing',
  completed: 'success',
  failed: 'error',
  stopped: 'warning',
};

const DEFAULT_TARGET_TAG_LIMIT = 12;

export default function TaskOverview({
  task,
  treeData,
  risks,
  assets,
  executionStatus,
  executionProgress,
  selectedVersion,
  selectedVersionMeta,
  versionCount = 0,
}: Props) {
  const riskCountMap = risks.reduce(
    (acc, risk) => {
      acc[normalizeRiskLevel(risk.level)] += 1;
      return acc;
    },
    { high: 0, medium: 0, low: 0, info: 0 },
  );

  const targets = useMemo(() => task?.targets || [], [task?.targets]);
  const assetGroups = countAssetGroups(assets);
  const [expandedTargets, setExpandedTargets] = useState(false);
  const hasVersionHistory = versionCount > 1;
  const currentScanLabel = hasVersionHistory
    ? selectedVersionMeta
      ? `第 ${selectedVersionMeta.version} 次扫描`
      : selectedVersion
        ? `第 ${selectedVersion} 次扫描`
        : '最新扫描结果'
    : '当前扫描';
  const visibleTargets = useMemo(
    () =>
      expandedTargets ? targets : targets.slice(0, DEFAULT_TARGET_TAG_LIMIT),
    [expandedTargets, targets],
  );
  const hiddenTargetCount = Math.max(0, targets.length - visibleTargets.length);
  const handleCopyTargets = async () => {
    if (!targets.length) {
      message.error('当前任务没有可复制的目标');
      return;
    }

    try {
      await navigator.clipboard.writeText(targets.join('\n'));
      message.success(`已复制 ${targets.length} 个目标`);
    } catch {
      message.error('复制目标失败');
    }
  };

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <Row gutter={16}>
        <Col xs={24} sm={12} xl={6}>
          <Card styles={{ body: { padding: 16 } }}>
            <Statistic title="任务状态" value={executionStatus || '-'} />
          </Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card styles={{ body: { padding: 16 } }}>
            <Statistic title="风险总数" value={risks.length} />
          </Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card styles={{ body: { padding: 16 } }}>
            <Statistic title="高风险" value={riskCountMap.high} />
          </Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card styles={{ body: { padding: 16 } }}>
            <Statistic title="站点节点" value={countTreeNodes(treeData)} />
          </Card>
        </Col>
      </Row>

      <Card title="任务概况" styles={{ body: { paddingTop: 16 } }}>
        <Descriptions column={2} bordered>
          <Descriptions.Item label="任务名称">
            {task?.name || '-'}
          </Descriptions.Item>
          <Descriptions.Item label="任务状态">
            {executionStatus ? (
              <Tag color={taskStatusColorMap[executionStatus] || 'default'}>
                {executionStatus}
              </Tag>
            ) : (
              '-'
            )}
          </Descriptions.Item>
          <Descriptions.Item label="执行进度">
            <div style={{ minWidth: 180 }}>
              <Progress percent={executionProgress} size="small" />
            </div>
          </Descriptions.Item>
          <Descriptions.Item label="目标数量">
            {targets.length}
          </Descriptions.Item>
          <Descriptions.Item label="资产分类">{assetGroups}</Descriptions.Item>
          <Descriptions.Item label="扫描次数">
            {versionCount || '-'}
          </Descriptions.Item>
          <Descriptions.Item label="当前视图">
            <Tag color="blue">{currentScanLabel}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="任务 ID" span={2}>
            <Typography.Text copyable>{task?.id || '-'}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="目标列表" span={2}>
            <div style={{ display: 'grid', gap: 12 }}>
              {targets.length ? (
                <>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {visibleTargets.map((target) => (
                      <Tag key={target} color="blue">
                        {target}
                      </Tag>
                    ))}
                    {hiddenTargetCount > 0 && !expandedTargets ? (
                      <Tag>{`+${hiddenTargetCount} 个目标`}</Tag>
                    ) : null}
                  </div>
                  {targets.length > DEFAULT_TARGET_TAG_LIMIT ? (
                    <Space size={8} wrap>
                      <Button
                        type="link"
                        style={{ padding: 0 }}
                        onClick={() => setExpandedTargets((value) => !value)}
                      >
                        {expandedTargets ? '收起目标列表' : '展开全部目标'}
                      </Button>
                      <Typography.Text type="secondary">
                        当前显示 {visibleTargets.length}/{targets.length}
                      </Typography.Text>
                    </Space>
                  ) : null}
                  <Button
                    type="link"
                    style={{ padding: 0, width: 'fit-content' }}
                    onClick={handleCopyTargets}
                  >
                    复制全部目标
                  </Button>
                </>
              ) : (
                <span>-</span>
              )}
            </div>
          </Descriptions.Item>
          <Descriptions.Item label="风险分布" span={2}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              <Tag color="red">高危 {riskCountMap.high}</Tag>
              <Tag color="orange">中危 {riskCountMap.medium}</Tag>
              <Tag color="blue">低危 {riskCountMap.low}</Tag>
              <Tag>{`信息 ${riskCountMap.info}`}</Tag>
            </div>
          </Descriptions.Item>
        </Descriptions>
      </Card>
    </div>
  );
}

import { PaperClipOutlined, RobotOutlined } from '@ant-design/icons';
import { Attachments, Bubble, Sender, Think } from '@ant-design/x';
import type { UploadFile } from 'antd';
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Drawer,
  Empty,
  Flex,
  Form,
  Input,
  List,
  Modal,
  Space,
  Tag,
  Typography,
  message,
} from 'antd';
import { useEffect, useMemo, useRef, useState } from 'react';

import {
  createCollaborativeSession,
  decideCollaborativeAction,
  executeCollaborativeAction,
  fetchCollaborativeSession,
  stageLabel,
  streamCollaborativeSession,
  validateCollaborativeTarget,
} from '@/services/collaborativeTesting';
import type {
  ApprovalDecision,
  CollaborationSession,
  EndpointClue,
  PendingRiskAction,
  RequestBlueprint,
  TestResult,
} from '@/types/collaborativeTesting';

import styles from './index.module.less';

const decisionTag: Record<string, { label: string; color: string }> = {
  pending: { label: '待决定', color: 'gold' },
  skipped: { label: '已跳过', color: 'default' },
  'dry-run': { label: 'Dry-run', color: 'blue' },
  'authorized-replay': { label: '已授权', color: 'purple' },
  'false-positive': { label: '误报', color: 'default' },
  'more-analysis': { label: '继续分析', color: 'cyan' },
};

const initialTarget = '';
const attachmentAccept = '.har,.json,.yaml,.yml,.js,.txt,.md,.zip';
const collaborationSessionStorageKey = 'collaborative-testing:last-session-id';
const evidencePreviewLimit = 10;

const testResultTag: Record<
  TestResult['status'],
  { label: string; color: string }
> = {
  recorded: { label: '真实请求', color: 'blue' },
  finding: { label: '发现风险', color: 'red' },
  completed: { label: '已执行', color: 'green' },
};

const riskLevelTag: Record<string, { label: string; color: string }> = {
  high: { label: '高风险', color: 'red' },
  medium: { label: '中风险', color: 'orange' },
  low: { label: '低风险', color: 'blue' },
  info: { label: '信息', color: 'default' },
};

const getRiskLevelTag = (riskLevel?: string) =>
  riskLevelTag[riskLevel?.trim().toLowerCase() ?? ''] ?? {
    label: riskLevel || '未知',
    color: 'default',
  };

export default function CollaborativeTestingPage() {
  const [target, setTarget] = useState(initialTarget);
  const [session, setSession] = useState<CollaborationSession>();
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState('');
  const [selectedBlueprint, setSelectedBlueprint] =
    useState<RequestBlueprint>();
  const [selectedEndpointClue, setSelectedEndpointClue] =
    useState<EndpointClue>();
  const [approvalAction, setApprovalAction] = useState<PendingRiskAction>();
  const [executionAction, setExecutionAction] = useState<PendingRiskAction>();
  const [attachments, setAttachments] = useState<UploadFile[]>([]);
  const [expandedEvidence, setExpandedEvidence] = useState({
    endpointClues: false,
    testRecords: false,
  });
  const attachmentRef = useRef<{
    select: (options?: { accept?: string; multiple?: boolean }) => void;
    upload: (file: File) => void;
  }>(null);
  const senderShellRef = useRef<HTMLDivElement>(null);
  const [approvalForm] = Form.useForm<{
    testEnvironment: string;
    testIdentity: string;
    authorizationScope: string;
    acknowledgement: boolean;
  }>();
  const [executionForm] = Form.useForm<{
    body?: string;
    headers?: string;
  }>();

  const pendingActions = useMemo(
    () =>
      session?.pendingRiskActions.filter(
        (item) => item.decision === 'pending',
      ) || [],
    [session],
  );
  const testResults = useMemo(() => session?.testResults ?? [], [session]);
  const timeline = useMemo(() => session?.timeline ?? [], [session]);
  const endpointClues = useMemo(() => session?.endpointClues ?? [], [session]);

  const attachmentFiles = useMemo(
    () =>
      attachments.reduce<File[]>((files, item) => {
        if (item.originFileObj) files.push(item.originFileObj);
        return files;
      }, []),
    [attachments],
  );

  const addPastedFiles = (files: FileList) => {
    Array.from(files).forEach((file) => attachmentRef.current?.upload(file));
  };

  useEffect(() => {
    if (!session?.id || session.status !== 'running') return;
    return streamCollaborativeSession(session.id, {
      onSession: setSession,
      onError: () => {
        // The stream reconnects itself. Avoid showing a transient network
        // warning for a connection that is already recovering.
      },
    });
  }, [session?.id, session?.status]);

  useEffect(() => {
    const savedSessionID = window.localStorage.getItem(
      collaborationSessionStorageKey,
    );
    if (!savedSessionID) return;
    void fetchCollaborativeSession(savedSessionID)
      .then(setSession)
      .catch(() =>
        window.localStorage.removeItem(collaborationSessionStorageKey),
      );
  }, []);

  useEffect(() => {
    setExpandedEvidence({ endpointClues: false, testRecords: false });
  }, [session?.id]);

  const start = async (value = target) => {
    const nextTarget = value.trim();
    if (!validateCollaborativeTarget(nextTarget)) {
      message.error('请输入有效的 HTTP(S) 目标 URL');
      return;
    }
    setStarting(true);
    setError('');
    try {
      const nextSession = await createCollaborativeSession(
        nextTarget,
        attachmentFiles,
      );
      setSession(nextSession);
      window.localStorage.setItem(
        collaborationSessionStorageKey,
        nextSession.id,
      );
      setTarget('');
      setAttachments([]);
    } catch (nextError) {
      setError(
        nextError instanceof Error ? nextError.message : '启动真实协同扫描失败',
      );
    } finally {
      setStarting(false);
    }
  };

  const beginNewSession = () => {
    window.localStorage.removeItem(collaborationSessionStorageKey);
    setSession(undefined);
    setTarget('');
    setAttachments([]);
  };

  const decide = async (
    action: PendingRiskAction,
    decision: Exclude<ApprovalDecision, 'pending'>,
    payload: Record<string, string> = {},
  ) => {
    if (!session) return;
    try {
      setSession(
        await decideCollaborativeAction(session.id, action.id, {
          decision,
          ...payload,
        }),
      );
    } catch (nextError) {
      message.error(
        nextError instanceof Error ? nextError.message : '保存审批决策失败',
      );
    }
  };

  const submitApproval = async () => {
    if (!approvalAction) return;
    const values = await approvalForm.validateFields();
    const { acknowledgement: _acknowledgement, ...approvalPayload } = values;
    await decide(approvalAction, 'authorized-replay', approvalPayload);
    setApprovalAction(undefined);
    approvalForm.resetFields();
  };

  const submitExecution = async () => {
    if (!session || !executionAction) return;
    try {
      const values = await executionForm.validateFields();
      let headers: Record<string, string> | undefined;
      if (values.headers?.trim()) {
        headers = JSON.parse(values.headers) as Record<string, string>;
      }
      setSession(
        await executeCollaborativeAction(session.id, executionAction.id, {
          body: values.body,
          headers,
        }),
      );
      setExecutionAction(undefined);
      executionForm.resetFields();
    } catch (nextError) {
      message.error(
        nextError instanceof Error ? nextError.message : '执行授权请求失败',
      );
    }
  };

  const isEndpointClueStage = (title: string) =>
    /接口线索|接口发现|接口识别/.test(title);
  const isTestRecordStage = (title: string) =>
    /自动测试|测试计划|测试执行/.test(title);

  const renderTestRecords = () => {
    const hasMore = testResults.length > evidencePreviewLimit;
    const visibleResults = expandedEvidence.testRecords
      ? testResults
      : testResults.slice(0, evidencePreviewLimit);
    return (
      <div className={styles.analysisEvidence}>
        <List
          className={styles.analysisList}
          size="small"
          dataSource={visibleResults}
          locale={{
            emptyText:
              '未记录到实际请求或安全发现；请求蓝图不等同于已执行测试。',
          }}
          renderItem={(result) => {
            const config = testResultTag[result.status];
            return (
              <List.Item>
                <div className={styles.resultItem}>
                  <Space size={6} wrap>
                    <Tag color={config.color}>{config.label}</Tag>
                    <Tag>{result.method || 'UNKNOWN'}</Tag>
                    {result.riskLevel ? (
                      <Tag color={getRiskLevelTag(result.riskLevel).color}>
                        {result.riskLevel}
                      </Tag>
                    ) : null}
                    {result.statusCode ? (
                      <Tag color="green">HTTP {result.statusCode}</Tag>
                    ) : null}
                    <Typography.Text strong>{result.route}</Typography.Text>
                  </Space>
                  <div className={styles.resultSummary}>
                    <Typography.Text type="secondary">
                      {result.summary}
                    </Typography.Text>
                  </div>
                </div>
              </List.Item>
            );
          }}
        />
        {hasMore ? (
          <Button
            type="link"
            size="small"
            className={styles.evidenceToggle}
            onClick={() =>
              setExpandedEvidence((current) => ({
                ...current,
                testRecords: !current.testRecords,
              }))
            }
          >
            {expandedEvidence.testRecords
              ? `收起至前 ${evidencePreviewLimit} 条`
              : `展开其余 ${testResults.length - evidencePreviewLimit} 条`}
          </Button>
        ) : null}
      </div>
    );
  };

  const renderEndpointClues = () => {
    const hasMore = endpointClues.length > evidencePreviewLimit;
    const visibleClues = expandedEvidence.endpointClues
      ? endpointClues
      : endpointClues.slice(0, evidencePreviewLimit);
    return (
      <div className={styles.analysisEvidence}>
        <Typography.Text className={styles.evidenceSummary} type="secondary">
          共 {session?.coverage.requestBlueprintsExtracted ?? 0}{' '}
          {'条提取证据；同一接口的不同'}
          {' JS 调用会合并显示。'}
        </Typography.Text>
        <List
          className={styles.analysisList}
          size="small"
          dataSource={visibleClues}
          locale={{ emptyText: '扫描尚未提取到接口线索。' }}
          renderItem={(clue) => (
            <List.Item
              actions={[
                <Button
                  key="view"
                  type="link"
                  size="small"
                  onClick={() => {
                    setSelectedBlueprint(clue.representative);
                    setSelectedEndpointClue(clue);
                  }}
                >
                  查看
                </Button>,
              ]}
            >
              <Space size={8} wrap>
                <Tag color={clue.method === 'GET' ? 'green' : 'blue'}>
                  {clue.method}
                </Tag>
                <Typography.Text>{clue.path}</Typography.Text>
                {clue.unresolvedSymbols?.length ? <Tag>待补全</Tag> : null}
                <Tag>{clue.evidence.length} 处来源</Tag>
              </Space>
            </List.Item>
          )}
        />
        {hasMore ? (
          <Button
            type="link"
            size="small"
            className={styles.evidenceToggle}
            onClick={() =>
              setExpandedEvidence((current) => ({
                ...current,
                endpointClues: !current.endpointClues,
              }))
            }
          >
            {expandedEvidence.endpointClues
              ? `收起至前 ${evidencePreviewLimit} 条`
              : `展开其余 ${endpointClues.length - evidencePreviewLimit} 条`}
          </Button>
        ) : null}
      </div>
    );
  };

  const conversation = session
    ? [
        {
          key: 'target',
          role: 'user',
          content: `协同测试 ${session.target}`,
        },
        ...timeline.map((event) => ({
          key: event.id,
          role: 'ai',
          content: (
            <Think
              className={styles.analysisThink}
              loading={event.state === 'running'}
              blink={event.state === 'running'}
              defaultExpanded={event.state !== 'completed'}
              title={
                <Space size={6} wrap>
                  <Tag
                    color={
                      event.state === 'failed'
                        ? 'red'
                        : event.state === 'running'
                          ? 'processing'
                          : event.state === 'waiting'
                            ? 'gold'
                            : 'green'
                    }
                  >
                    {event.state === 'running'
                      ? '分析中'
                      : event.state === 'waiting'
                        ? '等待决定'
                        : event.state === 'failed'
                          ? '分析失败'
                          : '分析完成'}
                  </Tag>
                  <Typography.Text strong>{event.title}</Typography.Text>
                </Space>
              }
            >
              <div className={styles.analysisContent}>
                <Typography.Text type="secondary">
                  {event.detail || '该步骤没有额外的分析摘要。'}
                </Typography.Text>
                <Typography.Text
                  type="secondary"
                  className={styles.analysisHint}
                >
                  此处展示可审计的执行与证据摘要，不展示模型隐藏推理。
                </Typography.Text>
                {isEndpointClueStage(event.title)
                  ? renderEndpointClues()
                  : null}
                {isTestRecordStage(event.title) ? renderTestRecords() : null}
              </div>
            </Think>
          ),
        })),
      ]
    : [];

  return (
    <div className={styles.page}>
      <div className={styles.topbar}>
        <Typography.Text strong>人机协同测试</Typography.Text>
        {session ? (
          <Space size={8}>
            <Tag
              color={
                session.status === 'failed'
                  ? 'error'
                  : session.status === 'running'
                    ? 'processing'
                    : 'success'
              }
            >
              {stageLabel[session.stage]}
            </Tag>
            <Typography.Text type="secondary">
              {session.coverage.apiRoutesDiscovered} 接口 ·{' '}
              {pendingActions.length} 待决定
            </Typography.Text>
            <Button size="small" type="text" onClick={beginNewSession}>
              新建测试
            </Button>
          </Space>
        ) : null}
      </div>

      {error ? (
        <Alert
          type="error"
          showIcon
          message={error}
          closable
          onClose={() => setError('')}
        />
      ) : null}

      <div className={styles.workspace}>
        <main className={styles.mainPane}>
          {!session ? (
            <div className={styles.emptyStart}>
              <RobotOutlined />
              <Typography.Title level={4}>协同测试</Typography.Title>
              <Typography.Text type="secondary">
                输入已授权目标开始
              </Typography.Text>
            </div>
          ) : (
            <Bubble.List
              className={styles.conversation}
              autoScroll
              items={conversation}
              role={{
                ai: {
                  placement: 'start',
                  variant: 'borderless',
                },
                user: { placement: 'end' },
              }}
            />
          )}

          <div className={styles.senderShell} ref={senderShellRef}>
            <Attachments
              ref={attachmentRef}
              items={attachments}
              accept={attachmentAccept}
              maxCount={8}
              beforeUpload={() => false}
              onChange={({ fileList }) => setAttachments(fileList)}
              getDropContainer={() => senderShellRef.current}
            >
              <span className={styles.hiddenUploader} aria-hidden />
            </Attachments>
            <Sender
              className={styles.sender}
              value={target}
              loading={starting || session?.status === 'running'}
              placeholder="输入目标 URL；可附加 HAR、OpenAPI 或 JS 文件"
              autoSize={{ minRows: 1, maxRows: 4 }}
              onChange={setTarget}
              onSubmit={start}
              onPasteFile={addPastedFiles}
              suffix={false}
              header={
                attachments.length ? (
                  <Attachments
                    items={attachments}
                    overflow="wrap"
                    onRemove={(file) => {
                      setAttachments((current) =>
                        current.filter((item) => item.uid !== file.uid),
                      );
                      return true;
                    }}
                  />
                ) : null
              }
              footer={(actionNode) => (
                <Flex
                  className={styles.senderFooter}
                  align="center"
                  justify="space-between"
                >
                  <Button
                    type="text"
                    size="small"
                    icon={<PaperClipOutlined />}
                    aria-label="添加附件"
                    onClick={() =>
                      attachmentRef.current?.select({
                        accept: attachmentAccept,
                        multiple: true,
                      })
                    }
                  />
                  <Flex align="center">{actionNode}</Flex>
                </Flex>
              )}
            />
          </div>
        </main>

        <aside className={styles.actionPane}>
          <div className={styles.actionHead}>
            <Typography.Text strong>需要你决定</Typography.Text>
            <Badge count={pendingActions.length} showZero color="#1677ff" />
          </div>
          {session ? (
            <List
              className={styles.actionList}
              dataSource={session.pendingRiskActions}
              locale={{ emptyText: '没有等待审批的风险动作。' }}
              renderItem={(action) => {
                const config = decisionTag[action.decision];
                const riskTag = getRiskLevelTag(action.riskLevel);
                return (
                  <List.Item>
                    <div className={styles.actionItem}>
                      <Space size={6}>
                        <Tag color={riskTag.color}>{riskTag.label}</Tag>
                        <Tag>{action.method}</Tag>
                        <Tag color={config.color}>{config.label}</Tag>
                      </Space>
                      <Typography.Text strong>{action.route}</Typography.Text>
                      <div className={styles.actionButtons}>
                        <Button
                          size="small"
                          onClick={() => {
                            setSelectedBlueprint(action.requestPreview);
                            setSelectedEndpointClue(undefined);
                          }}
                        >
                          查看
                        </Button>
                        {action.decision === 'pending' ? (
                          <>
                            <Button
                              size="small"
                              onClick={() => void decide(action, 'skipped')}
                            >
                              跳过
                            </Button>
                            <Button
                              size="small"
                              type="primary"
                              onClick={() => void decide(action, 'dry-run')}
                            >
                              Dry-run
                            </Button>
                            <Button
                              size="small"
                              onClick={() => setApprovalAction(action)}
                            >
                              授权
                            </Button>
                          </>
                        ) : null}
                        {action.decision === 'authorized-replay' &&
                        !action.execution ? (
                          <Button
                            size="small"
                            type="primary"
                            onClick={() => setExecutionAction(action)}
                          >
                            执行
                          </Button>
                        ) : null}
                        {action.execution ? (
                          <Tag color="success">
                            HTTP {action.execution.statusCode}
                          </Tag>
                        ) : null}
                      </div>
                    </div>
                  </List.Item>
                );
              }}
            />
          ) : (
            <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description="风险动作将在真实扫描完成后出现。"
            />
          )}
        </aside>
      </div>

      <Drawer
        title={
          selectedBlueprint
            ? `${selectedBlueprint.method} ${selectedBlueprint.path}`
            : '请求蓝图'
        }
        width={560}
        open={Boolean(selectedBlueprint)}
        onClose={() => {
          setSelectedBlueprint(undefined);
          setSelectedEndpointClue(undefined);
        }}
      >
        {selectedBlueprint ? (
          <div className={styles.drawerBody}>
            <Alert
              type="info"
              showIcon
              message="此预览来自已保存 JS 的真实静态分析；Dry-run 不发送请求。"
            />
            <Typography.Text type="secondary">
              证据来源
              {selectedEndpointClue
                ? `（${selectedEndpointClue.evidence.length} 处）`
                : ''}
            </Typography.Text>
            {selectedEndpointClue ? (
              <List
                size="small"
                dataSource={selectedEndpointClue.evidence}
                renderItem={(evidence) => (
                  <List.Item>
                    <div className={styles.evidenceItem}>
                      <Typography.Text>
                        {evidence.file || '未记录'}
                      </Typography.Text>
                      <Typography.Text type="secondary">
                        {evidence.snippet || '未提取到代码片段'}
                      </Typography.Text>
                    </div>
                  </List.Item>
                )}
              />
            ) : (
              <>
                <Typography.Paragraph className={styles.mono}>
                  {selectedBlueprint.source?.file || '未记录'}
                </Typography.Paragraph>
                <Typography.Text type="secondary">代码片段</Typography.Text>
                <Typography.Paragraph className={styles.mono}>
                  {selectedBlueprint.source?.snippet || '未提取到代码片段'}
                </Typography.Paragraph>
              </>
            )}
            <Typography.Text type="secondary">Payload</Typography.Text>
            <Typography.Paragraph className={styles.mono}>
              {selectedBlueprint.payloadPreview || '无请求体'}
            </Typography.Paragraph>
            <Typography.Text type="secondary">参数</Typography.Text>
            <List
              size="small"
              dataSource={selectedBlueprint.params}
              locale={{ emptyText: '未解析到参数。' }}
              renderItem={(param) => (
                <List.Item>
                  <Typography.Text code>{param.name}</Typography.Text>
                  <Typography.Text type="secondary">
                    {param.location || 'unknown'} ·{' '}
                    {param.valueExpr || param.value || '-'}
                  </Typography.Text>
                </List.Item>
              )}
            />
          </div>
        ) : null}
      </Drawer>

      <Modal
        title="授权高风险动作"
        open={Boolean(approvalAction)}
        okText="记录授权"
        cancelText="取消"
        onCancel={() => {
          setApprovalAction(undefined);
          approvalForm.resetFields();
        }}
        onOk={() => void submitApproval()}
      >
        <Alert type="warning" showIcon message="仅限授权测试环境" />
        <Form
          form={approvalForm}
          layout="vertical"
          initialValues={{ acknowledgement: false }}
        >
          <Form.Item
            name="testEnvironment"
            label="测试环境"
            rules={[{ required: true, message: '请填写测试环境' }]}
          >
            <Input placeholder="例如 staging" />
          </Form.Item>
          <Form.Item
            name="testIdentity"
            label="测试身份"
            rules={[{ required: true, message: '请填写测试身份' }]}
          >
            <Input placeholder="例如 qa-user-001" />
          </Form.Item>
          <Form.Item
            name="authorizationScope"
            label="授权范围"
            rules={[{ required: true, message: '请填写授权范围' }]}
          >
            <Input placeholder="例如仅 /api/apply/save" />
          </Form.Item>
          <Form.Item
            name="acknowledgement"
            valuePropName="checked"
            rules={[
              {
                validator: (_, value) =>
                  value
                    ? Promise.resolve()
                    : Promise.reject(new Error('请确认使用授权测试数据')),
              },
            ]}
          >
            <Checkbox>我确认使用的是授权测试环境和测试数据。</Checkbox>
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="执行已授权请求"
        open={Boolean(executionAction)}
        okText="发送一次请求"
        cancelText="取消"
        onCancel={() => {
          setExecutionAction(undefined);
          executionForm.resetFields();
        }}
        onOk={() => void submitExecution()}
      >
        <Alert
          type="warning"
          showIcon
          message="服务端只会向配置白名单中的测试主机发送一次请求。"
        />
        <Form form={executionForm} layout="vertical">
          <Form.Item name="body" label="请求体（可选）">
            <Input.TextArea rows={4} placeholder='例如 {"name":"test"}' />
          </Form.Item>
          <Form.Item
            name="headers"
            label="请求头 JSON（可选）"
            rules={[
              {
                validator: (_, value) => {
                  if (!value?.trim()) return Promise.resolve();
                  try {
                    const parsed = JSON.parse(value);
                    return parsed && typeof parsed === 'object'
                      ? Promise.resolve()
                      : Promise.reject(new Error('请求头必须是 JSON 对象'));
                  } catch {
                    return Promise.reject(new Error('请求头不是合法 JSON'));
                  }
                },
              },
            ]}
          >
            <Input.TextArea
              rows={3}
              placeholder='例如 {"X-Test-User":"qa-001"}'
            />
          </Form.Item>
        </Form>
      </Modal>

    </div>
  );
}

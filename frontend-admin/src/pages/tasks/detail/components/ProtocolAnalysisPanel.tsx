import {
  Alert,
  Button,
  Card,
  Collapse,
  Descriptions,
  Drawer,
  Empty,
  Select,
  Space,
  Spin,
  Table,
  Tag,
  Timeline,
  Typography,
  message,
} from 'antd';
import { useEffect, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { explainProtocolTraceStream } from '@/services/tasks';
import type {
  ProtocolTrace,
  StaticProtocolAnalysis,
  StaticProtocolEndpoint,
  StaticProtocolProfile,
} from '@/types/task';
import type { ProtocolFlowStep } from './taskDetailUtils';
import {
  buildProtocolTraceFlow,
  groupProtocolTracesByAlgorithms,
  groupProtocolTracesByStackFingerprint,
} from './taskDetailUtils';

interface Props {
  taskId: string;
  version?: number;
  traces: ProtocolTrace[];
  staticAnalysis: StaticProtocolAnalysis | null;
  loading?: boolean;
  initialTraceFilterMode?: ProtocolTraceFilterMode;
}

type ProtocolTraceFilterMode = 'crypto_focused' | 'all';

const renderTagList = (items?: string[]) =>
  items?.length ? (
    <Space wrap>
      {items.map((item) => (
        <Tag key={item}>{item}</Tag>
      ))}
    </Space>
  ) : (
    '-'
  );

const renderKeyValueTags = (
  items?: Record<string, string>,
  options?: {
    maxHeight?: number;
    dataTestId?: string;
  },
) => {
  const entries = Object.entries(items || {});
  if (!entries.length) {
    return '-';
  }

  return (
    <div
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: 8,
        minWidth: 0,
        maxHeight: options?.maxHeight,
        overflowY: options?.maxHeight ? 'auto' : undefined,
        overflowX: 'hidden',
        alignContent: 'flex-start',
        paddingRight: options?.maxHeight ? 4 : undefined,
      }}
      data-testid={options?.dataTestId}
    >
      {entries.map(([key, value]) => (
        <div
          key={key}
          style={{
            maxWidth: '100%',
            minWidth: 0,
            padding: '2px 8px',
            borderRadius: 6,
            border: '1px solid #d9d9d9',
            background: '#fafafa',
            wordBreak: 'break-word',
            overflowWrap: 'anywhere',
            whiteSpace: 'normal',
          }}
        >
          <Typography.Text
            style={{
              maxWidth: '100%',
              minWidth: 0,
              wordBreak: 'break-word',
              overflowWrap: 'anywhere',
              whiteSpace: 'normal',
            }}
          >
            <strong>{key}:</strong> {value}
          </Typography.Text>
        </div>
      ))}
    </div>
  );
};

const renderSnippet = (value?: string) =>
  value ? (
    <pre
      style={{
        margin: 0,
        maxHeight: 240,
        overflow: 'auto',
        width: '100%',
        maxWidth: '100%',
        minWidth: 0,
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        overflowWrap: 'anywhere',
      }}
    >
      {value}
    </pre>
  ) : (
    '暂无内容'
  );

const renderWrappingText = (value?: string, fallback = '-') => (
  <span
    style={{
      display: 'block',
      width: '100%',
      maxWidth: '100%',
      minWidth: 0,
      whiteSpace: 'normal',
      wordBreak: 'break-word',
      overflowWrap: 'anywhere',
    }}
  >
    {value || fallback}
  </span>
);

const renderFlowStepContent = (step: {
  title: string;
  source?: string;
  algorithm?: string;
  input?: string;
  output?: string;
  callId?: string;
  parentCallId?: string;
  functionPath?: string;
  moduleId?: string;
  materialKeys?: string[];
}) => (
  <div style={{ display: 'grid', gap: 12, minWidth: 0 }}>
    <Space wrap>
      {step.source ? <Tag>{step.source}</Tag> : null}
      {step.algorithm ? <Tag color="blue">{step.algorithm}</Tag> : null}
      {step.functionPath ? <Tag color="purple">{step.functionPath}</Tag> : null}
      {step.moduleId ? (
        <Tag color="geekblue">module:{step.moduleId}</Tag>
      ) : null}
      {step.callId ? <Tag color="cyan">call:{step.callId}</Tag> : null}
      {(step.materialKeys || []).map((key) => (
        <Tag color="gold" key={key}>
          {key}
        </Tag>
      ))}
    </Space>
    <Descriptions bordered size="small" column={1}>
      <Descriptions.Item label="函数路径">
        {step.functionPath || '-'}
      </Descriptions.Item>
      {step.moduleId ? (
        <Descriptions.Item label="模块 ID">{step.moduleId}</Descriptions.Item>
      ) : null}
      {step.callId ? (
        <Descriptions.Item label="调用 ID">{step.callId}</Descriptions.Item>
      ) : null}
      {step.parentCallId ? (
        <Descriptions.Item label="父调用 ID">
          {step.parentCallId}
        </Descriptions.Item>
      ) : null}
      <Descriptions.Item label="输入预览">
        {renderSnippet(step.input)}
      </Descriptions.Item>
      <Descriptions.Item label="输出预览">
        {renderSnippet(step.output)}
      </Descriptions.Item>
    </Descriptions>
  </div>
);

const truncateFlowValue = (value?: string, maxLength = 96) => {
  const normalized = value?.replace(/\s+/g, ' ').trim();
  if (!normalized) {
    return '';
  }

  return normalized.length > maxLength
    ? `${normalized.slice(0, maxLength)}...`
    : normalized;
};

const renderFlowPreviewText = (label: string, value?: string) => {
  const preview = truncateFlowValue(value);
  if (!preview) {
    return null;
  }

  return (
    <Typography.Text
      type="secondary"
      style={{
        display: 'block',
        wordBreak: 'break-word',
        overflowWrap: 'anywhere',
      }}
    >
      <strong>{label}：</strong>
      {preview}
    </Typography.Text>
  );
};

const renderFlowLaneTimeline = (
  steps: ProtocolFlowStep[],
  emptyDescription: string,
) =>
  steps.length ? (
    <Timeline
      items={steps.map((step, index) => ({
        color: step.kind === 'request' ? 'blue' : 'green',
        content: (
          <Collapse
            size="small"
            items={[
              {
                key: step.id,
                label: (
                  <div style={{ display: 'grid', gap: 8 }}>
                    <Space wrap>
                      <Tag color={step.kind === 'request' ? 'blue' : 'green'}>
                        {`步骤 ${index + 1}`}
                      </Tag>
                      <Typography.Text strong>{step.title}</Typography.Text>
                      {step.algorithm ? (
                        <Tag color="blue">{step.algorithm}</Tag>
                      ) : null}
                      {step.functionPath ? (
                        <Tag color="purple">{step.functionPath}</Tag>
                      ) : null}
                    </Space>
                    {renderFlowPreviewText('输入', step.input)}
                    {renderFlowPreviewText('输出', step.output)}
                  </div>
                ),
                children: renderFlowStepContent(step),
              },
            ]}
          />
        ),
      }))}
    />
  ) : (
    <Empty description={emptyDescription} />
  );

const renderMarkdown = (content: string) => (
  <div
    style={{
      wordBreak: 'break-word',
      overflowWrap: 'anywhere',
    }}
  >
    <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
  </div>
);

const parseAIExplanationCards = (content?: string) => {
  const normalized = content?.replace(/\r\n/g, '\n').trim() || '';
  if (!normalized) {
    return [];
  }

  const items: Array<{ id: string; title: string; body: string }> = [];
  let currentNumber = '';
  let currentBody = '';
  const normalizeCardTitle = (value: string) =>
    value
      .trim()
      .replace(/^\*\*(.+)\*\*$/u, '$1')
      .replace(/^__(.+)__$/u, '$1')
      .replace(/^`(.+)`$/u, '$1')
      .trim();

  const pushCurrent = () => {
    const rawBody = currentBody.trim();
    if (!rawBody) {
      return;
    }

    const firstLineBreakIndex = rawBody.indexOf('\n');
    const firstLine =
      firstLineBreakIndex >= 0
        ? rawBody.slice(0, firstLineBreakIndex)
        : rawBody;
    const remaining =
      firstLineBreakIndex >= 0
        ? rawBody.slice(firstLineBreakIndex + 1).trim()
        : '';
    const titleMatch = firstLine.match(/^(.*?)(：|:)\s*(.*)$/);

    if (titleMatch) {
      const [, titlePrefix, , firstLineRemainder] = titleMatch;
      const body = [firstLineRemainder.trim(), remaining]
        .filter(Boolean)
        .join('\n\n');
      items.push({
        id: `${currentNumber}-${items.length}`,
        title: `${currentNumber}. ${normalizeCardTitle(titlePrefix)}`,
        body: body || firstLineRemainder.trim(),
      });
      return;
    }

    const standaloneTitle = normalizeCardTitle(firstLine);
    if (
      remaining &&
      standaloneTitle &&
      standaloneTitle !== firstLine &&
      !/[。；，,:：]/u.test(standaloneTitle)
    ) {
      items.push({
        id: `${currentNumber}-${items.length}`,
        title: `${currentNumber}. ${standaloneTitle}`,
        body: remaining,
      });
      return;
    }

    items.push({
      id: `${currentNumber}-${items.length}`,
      title: `${currentNumber}. 说明`,
      body: rawBody,
    });
  };

  normalized.split('\n').forEach((line) => {
    const itemMatch = line.match(/^\s*(\d+)\.\s+(.*)$/);
    if (itemMatch) {
      pushCurrent();
      currentNumber = itemMatch[1];
      currentBody = itemMatch[2].trim();
      return;
    }

    currentBody = currentBody ? `${currentBody}\n${line}` : line;
  });

  pushCurrent();
  return items;
};

const renderAIExplanationCards = (
  content: string,
  emptyDescription: string,
) => {
  const cards = parseAIExplanationCards(content);
  if (!cards.length) {
    return <Empty description={emptyDescription} />;
  }

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      {cards.map((card) => (
        <Card key={card.id} size="small" title={card.title}>
          {renderMarkdown(card.body)}
        </Card>
      ))}
    </div>
  );
};

const parseAIExplanationLanes = (content?: string) => {
  const normalized = content?.replace(/\r\n/g, '\n').trim() || '';
  if (!normalized) {
    return {
      request: '',
      response: '',
    };
  }

  let currentLane: 'request' | 'response' | null = null;
  let hasExplicitLane = false;
  const requestLines: string[] = [];
  const responseLines: string[] = [];

  normalized.split('\n').forEach((line) => {
    const trimmed = line.trim();
    if (/^#{1,6}\s*请求(?:甬道|链路)/.test(trimmed)) {
      currentLane = 'request';
      hasExplicitLane = true;
      return;
    }
    if (/^#{1,6}\s*响应(?:甬道|链路)/.test(trimmed)) {
      currentLane = 'response';
      hasExplicitLane = true;
      return;
    }

    if (currentLane === 'request') {
      requestLines.push(line);
      return;
    }
    if (currentLane === 'response') {
      responseLines.push(line);
    }
  });

  if (!hasExplicitLane) {
    return {
      request: normalized,
      response: '',
    };
  }

  return {
    request: requestLines.join('\n').trim(),
    response: responseLines.join('\n').trim(),
  };
};

const getFlowStepByTitle = (
  steps: Array<{
    title: string;
    output?: string;
  }>,
  title: string,
) => steps.find((step) => step.title === title)?.output;

const endpointToProtocolTrace = (
  endpoint: StaticProtocolEndpoint,
): ProtocolTrace => ({
  trace_id: endpoint.trace_id || '',
  page_url: endpoint.page_url,
  request_url: endpoint.request_url,
  method: endpoint.method,
  request_before_transform: endpoint.request_before_transform,
  final_request_body: endpoint.final_request_body,
  request_steps: endpoint.request_steps,
  response_steps: endpoint.response_steps,
  session_materials: endpoint.session_materials,
  algorithms: endpoint.algorithms,
});

const renderEndpointTraceDetail = (
  endpoint: StaticProtocolEndpoint,
  titlePrefix?: string,
) => {
  const endpointTrace = endpoint.trace_id
    ? endpointToProtocolTrace(endpoint)
    : null;
  const endpointFlow = endpointTrace
    ? buildProtocolTraceFlow(endpointTrace)
    : null;

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <Descriptions bordered size="small" column={1}>
        <Descriptions.Item label="请求地址">
          {renderWrappingText(
            endpoint.request_url || endpoint.path,
            endpoint.path,
          )}
        </Descriptions.Item>
        {endpoint.trace_id ? (
          <Descriptions.Item label="轨迹 ID">
            {endpoint.trace_id}
          </Descriptions.Item>
        ) : null}
        {endpoint.algorithms?.length ? (
          <Descriptions.Item label="算法">
            {renderTagList(endpoint.algorithms)}
          </Descriptions.Item>
        ) : null}
        {endpoint.context?.length ? (
          <Descriptions.Item label="上下文">
            {renderTagList(endpoint.context)}
          </Descriptions.Item>
        ) : null}
      </Descriptions>

      {endpointTrace ? (
        <>
          <div
            style={{
              display: 'grid',
              gap: 16,
              gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
              alignItems: 'start',
            }}
          >
            <Card size="small" title={`${titlePrefix || ''}请求甬道`}>
              <div style={{ display: 'grid', gap: 12 }}>
                <Card size="small" title="加密前请求数据">
                  {renderSnippet(
                    getFlowStepByTitle(
                      endpointFlow?.requestLane || [],
                      '原始请求明文',
                    ) || endpoint.request_before_transform,
                  )}
                </Card>
                <Card size="small" title="最终请求包">
                  {renderSnippet(
                    getFlowStepByTitle(
                      endpointFlow?.requestLane || [],
                      '最终发包请求体',
                    ) || endpoint.final_request_body,
                  )}
                </Card>
              </div>
            </Card>
            <Card size="small" title={`${titlePrefix || ''}响应甬道`}>
              <div style={{ display: 'grid', gap: 12 }}>
                <Card size="small" title="原始响应包">
                  {renderSnippet(
                    getFlowStepByTitle(
                      endpointFlow?.responseLane || [],
                      '原始响应密文',
                    ) || endpoint.session_materials?.latest_response_ciphertext,
                  )}
                </Card>
                <Card size="small" title="响应解密结果">
                  {renderSnippet(
                    getFlowStepByTitle(
                      endpointFlow?.responseLane || [],
                      '响应明文',
                    ) || endpoint.session_materials?.latest_response_plaintext,
                  )}
                </Card>
              </div>
            </Card>
          </div>

          <Card title="链路总结" size="small">
            <Descriptions bordered size="small" column={1}>
              <Descriptions.Item label="请求链路">
                {endpointFlow?.summary.hasRequestLane ? '已捕获' : '未捕获'}
              </Descriptions.Item>
              <Descriptions.Item label="响应链路">
                {endpointFlow?.summary.hasResponseLane ? '已捕获' : '未捕获'}
              </Descriptions.Item>
              <Descriptions.Item label="响应密文">
                {endpointFlow?.summary.hasResponseCiphertext
                  ? '已捕获'
                  : '未捕获'}
              </Descriptions.Item>
              <Descriptions.Item label="响应明文">
                {endpointFlow?.summary.hasResponsePlaintext
                  ? '已捕获'
                  : '未捕获'}
              </Descriptions.Item>
              <Descriptions.Item label="最终明文来源">
                {endpointFlow?.summary.finalResponseSource || '-'}
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <div
            style={{
              display: 'grid',
              gap: 16,
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              alignItems: 'start',
            }}
          >
            <Card title={`${titlePrefix || ''}请求链路流程`} size="small">
              {renderFlowLaneTimeline(
                endpointFlow?.requestLane || [],
                '暂无请求链路流程',
              )}
            </Card>
            <Card title={`${titlePrefix || ''}响应链路流程`} size="small">
              {renderFlowLaneTimeline(
                endpointFlow?.responseLane || [],
                '暂无响应链路流程',
              )}
            </Card>
          </div>
        </>
      ) : null}
    </div>
  );
};

const renderStaticProfile = (profile: StaticProtocolProfile) => (
  <div style={{ display: 'grid', gap: 16 }}>
    <Descriptions bordered size="small" column={1}>
      <Descriptions.Item label="协议画像">
        {profile.name || '-'}
      </Descriptions.Item>
      <Descriptions.Item label="请求封装">
        {profile.request_wrapper || '-'}
      </Descriptions.Item>
      <Descriptions.Item label="请求加密">
        {profile.request_cipher || '-'}
      </Descriptions.Item>
      <Descriptions.Item label="响应解密">
        {profile.response_cipher || '-'}
      </Descriptions.Item>
      <Descriptions.Item label="密钥交换">
        {profile.key_exchange || '-'}
      </Descriptions.Item>
      <Descriptions.Item label="签名算法">
        {profile.signature_algorithm || '-'}
      </Descriptions.Item>
      <Descriptions.Item label="API Base">
        {renderTagList(profile.api_base_urls)}
      </Descriptions.Item>
      <Descriptions.Item label="控制字段">
        {renderTagList(profile.control_fields)}
      </Descriptions.Item>
      <Descriptions.Item label="静态请求流水线">
        {renderTagList(profile.request_pipeline)}
      </Descriptions.Item>
      <Descriptions.Item label="静态响应流水线">
        {renderTagList(profile.response_pipeline)}
      </Descriptions.Item>
      <Descriptions.Item label="请求头字段">
        {renderKeyValueTags(profile.header_fields)}
      </Descriptions.Item>
    </Descriptions>

    {profile.primary_endpoint?.trace_id ? (
      <Card size="small" title="主命中轨迹">
        {renderEndpointTraceDetail(profile.primary_endpoint, '主链')}
      </Card>
    ) : null}

    <Card size="small" title={`命中端点 (${profile.endpoints?.length || 0})`}>
      {profile.endpoints?.length ? (
        <Collapse
          items={profile.endpoints.map((endpoint, index) => {
            return {
              key: `${endpoint.method}-${endpoint.path}-${index}`,
              label: (
                <Space wrap>
                  <Tag color="blue">{endpoint.method || 'GET'}</Tag>
                  <Typography.Text strong>{endpoint.path}</Typography.Text>
                  {endpoint.trace_id ? (
                    <Tag color="gold">已关联轨迹</Tag>
                  ) : null}
                </Space>
              ),
              children: (
                <div style={{ display: 'grid', gap: 16 }}>
                  <Descriptions bordered size="small" column={1}>
                    <Descriptions.Item label="来源文件">
                      {endpoint.source_file || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="客户端">
                      {endpoint.client || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="载荷位置">
                      {endpoint.request_payload_carrier || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="载荷类型">
                      {endpoint.request_payload_format || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="参数">
                      {(endpoint.params || [])
                        .map((item) => item.name)
                        .join(', ') || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="请求地址">
                      {renderWrappingText(
                        endpoint.request_url || endpoint.path,
                        endpoint.path,
                      )}
                    </Descriptions.Item>
                    {endpoint.trace_id ? (
                      <Descriptions.Item label="轨迹 ID">
                        {endpoint.trace_id}
                      </Descriptions.Item>
                    ) : null}
                    {endpoint.algorithms?.length ? (
                      <Descriptions.Item label="算法">
                        {renderTagList(endpoint.algorithms)}
                      </Descriptions.Item>
                    ) : null}
                    {endpoint.context?.length ? (
                      <Descriptions.Item label="上下文">
                        {renderTagList(endpoint.context)}
                      </Descriptions.Item>
                    ) : null}
                    {endpoint.request_payload_preview ? (
                      <Descriptions.Item label="请求包候选">
                        {renderSnippet(endpoint.request_payload_preview)}
                      </Descriptions.Item>
                    ) : null}
                    <Descriptions.Item label="代码片段">
                      {renderSnippet(endpoint.snippet)}
                    </Descriptions.Item>
                  </Descriptions>

                  {endpoint.trace_id
                    ? renderEndpointTraceDetail(endpoint)
                    : null}
                </div>
              ),
            };
          })}
        />
      ) : (
        <Empty description="暂无静态端点命中" />
      )}
    </Card>
  </div>
);

export default function ProtocolAnalysisPanel({
  taskId,
  version,
  traces,
  staticAnalysis,
  loading,
  initialTraceFilterMode = 'crypto_focused',
}: Props) {
  const [selectedTraceId, setSelectedTraceId] = useState<string>('');
  const [traceFilterMode, setTraceFilterMode] = useState<ProtocolTraceFilterMode>(
    initialTraceFilterMode,
  );
  const [aiExplaining, setAIExplaining] = useState(false);
  const [aiExplanationByTraceId, setAIExplanationByTraceId] = useState<
    Record<string, { explanation: string; model?: string }>
  >({});
  const [aiExplanationError, setAIExplanationError] = useState('');
  const explainAbortControllerRef = useRef<AbortController | null>(null);
  const hasCryptoFocusedSignal = (trace: ProtocolTrace) => {
    const responseCiphertext = Boolean(
      trace.session_materials?.latest_response_ciphertext?.trim(),
    );
    if (responseCiphertext) {
      return true;
    }

    const responseSteps = trace.response_steps || [];
    return responseSteps.some((step) => {
      const source = (step.source || '').toLowerCase();
      const algorithm = (step.algorithm || '').toLowerCase();
      const signal = `${source} ${algorithm}`;
      return /(decrypt|decode|sm4|aes|des|rsa|cipher|base64|hex|atob|btoa)/.test(
        signal,
      );
    });
  };

  const filteredTraces =
    traceFilterMode === 'all'
      ? traces
      : traces.filter((trace) => hasCryptoFocusedSignal(trace));

  useEffect(() => {
    setTraceFilterMode(initialTraceFilterMode);
  }, [initialTraceFilterMode]);

  useEffect(() => {
    setSelectedTraceId((current) =>
      current && filteredTraces.some((trace) => trace.trace_id === current)
        ? current
        : '',
    );
  }, [filteredTraces]);

  useEffect(
    () => () => {
      explainAbortControllerRef.current?.abort();
    },
    [],
  );

  if (loading) {
    return (
      <div
        style={{
          minHeight: 280,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Spin />
      </div>
    );
  }

  const staticProfiles = staticAnalysis?.profiles || [];
  const hiddenPlaintextOnlyCount = Math.max(0, traces.length - filteredTraces.length);
  const traceGroups = groupProtocolTracesByAlgorithms(filteredTraces);
  const selectedTrace =
    filteredTraces.find((trace) => trace.trace_id === selectedTraceId) || null;
  const selectedTraceFlow = selectedTrace
    ? buildProtocolTraceFlow(selectedTrace)
    : null;
  const selectedAIExplanation = selectedTrace
    ? aiExplanationByTraceId[selectedTrace.trace_id]
    : undefined;
  const selectedAIExplanationLanes = parseAIExplanationLanes(
    selectedAIExplanation?.explanation,
  );

  const handleExplainTrace = async () => {
    if (!taskId || !selectedTrace?.trace_id) {
      return;
    }

    const currentTraceId = selectedTrace.trace_id;
    explainAbortControllerRef.current?.abort();
    const controller = new AbortController();
    explainAbortControllerRef.current = controller;

    setAIExplaining(true);
    setAIExplanationError('');
    setAIExplanationByTraceId((current) => ({
      ...current,
      [currentTraceId]: {
        explanation: '',
        model: current[currentTraceId]?.model || '',
      },
    }));

    try {
      const result = await explainProtocolTraceStream(
        taskId,
        { traceId: currentTraceId },
        {
          version,
          signal: controller.signal,
          onEvent: (event) => {
            if (event.type === 'delta') {
              setAIExplanationByTraceId((current) => ({
                ...current,
                [currentTraceId]: {
                  explanation: `${current[currentTraceId]?.explanation || ''}${event.delta || ''}`,
                  model: current[currentTraceId]?.model || '',
                },
              }));
              return;
            }

            if (event.type === 'done') {
              setAIExplanationByTraceId((current) => ({
                ...current,
                [currentTraceId]: {
                  explanation:
                    event.explanation ||
                    current[currentTraceId]?.explanation ||
                    '',
                  model: event.model || current[currentTraceId]?.model || '',
                },
              }));
            }
          },
        },
      );
      if (!result?.explanation) {
        setAIExplanationError('AI 未返回可用解释');
        message.warning('AI 未返回可用解释');
        return;
      }
      setAIExplanationByTraceId((current) => ({
        ...current,
        [currentTraceId]: {
          explanation: result.explanation || '',
          model: result.model || '',
        },
      }));
      message.success('AI 解释生成成功');
    } catch (error) {
      if ((error as Error)?.name === 'AbortError') {
        return;
      }
      console.error(error);
      setAIExplanationError(
        error instanceof Error && error.message
          ? error.message
          : 'AI 解释生成失败，请检查模型配置或稍后重试',
      );
      message.error('AI 解释生成失败');
    } finally {
      if (explainAbortControllerRef.current === controller) {
        explainAbortControllerRef.current = null;
      }
      setAIExplaining(false);
    }
  };

  if (!traces.length && !staticProfiles.length) {
    return (
      <Card>
        <Empty description="当前任务暂无协议链路或静态分析结果" />
      </Card>
    );
  }

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <Card
        title="协议轨迹"
        extra={
          <Space wrap>
            <Tag>{`展示 ${filteredTraces.length}/${traces.length}`}</Tag>
            <Select
              value={traceFilterMode}
              onChange={(value) => setTraceFilterMode(value)}
              style={{ width: 220 }}
              options={[
                { label: '仅看加解密相关轨迹', value: 'crypto_focused' },
                { label: '显示全部轨迹', value: 'all' },
              ]}
            />
          </Space>
        }
      >
        {hiddenPlaintextOnlyCount > 0 && traceFilterMode === 'crypto_focused' ? (
          <Alert
            showIcon
            type="info"
            style={{ marginBottom: 16 }}
            title={`已默认隐藏 ${hiddenPlaintextOnlyCount} 条“明文直出/缺少密文证据”的轨迹，避免干扰加解密分析。`}
          />
        ) : null}
        {traceGroups.length ? (
          <Collapse
            items={traceGroups.map((group) => ({
              key: group.id,
              label: (
                <Space wrap>
                  <Typography.Text strong>{group.label}</Typography.Text>
                  <Typography.Text type="secondary">
                    {`${group.traces.length} 个接口轨迹`}
                  </Typography.Text>
                </Space>
              ),
              children: (
                <div style={{ display: 'grid', gap: 16, minWidth: 0 }}>
                  {(() => {
                    const stackGroups = groupProtocolTracesByStackFingerprint(
                      group.traces,
                    );

                    return (
                      <>
                        <Descriptions bordered size="small" column={1}>
                          <Descriptions.Item label="轨迹数量">
                            {group.traces.length}
                          </Descriptions.Item>
                          <Descriptions.Item label="调用来源">
                            {stackGroups.length}
                          </Descriptions.Item>
                          <Descriptions.Item label="传输层">
                            {renderTagList(
                              Array.from(
                                new Set(
                                  group.traces.map(
                                    (trace) => trace.transport || 'http',
                                  ),
                                ),
                              ),
                            )}
                          </Descriptions.Item>
                        </Descriptions>

                        <div style={{ display: 'grid', gap: 16 }}>
                          {stackGroups.map((stackGroup) => (
                            <Card
                              key={stackGroup.id}
                              size="small"
                              title={
                                <Space wrap>
                                  <Typography.Text strong>
                                    接口列表
                                  </Typography.Text>
                                  <Tag>{`${stackGroup.traces.length} 条接口`}</Tag>
                                </Space>
                              }
                            >
                              <Table
                                rowKey="trace_id"
                                size="small"
                                tableLayout="fixed"
                                pagination={{
                                  pageSize: 5,
                                  showSizeChanger: false,
                                }}
                                dataSource={stackGroup.traces}
                                columns={[
                                  {
                                    title: '方法',
                                    dataIndex: 'method',
                                    render: (value: string | undefined) =>
                                      value || 'GET',
                                    width: 96,
                                  },
                                  {
                                    title: '请求地址',
                                    dataIndex: 'request_url',
                                    width: '40%',
                                    render: (
                                      value: string | undefined,
                                      trace: ProtocolTrace,
                                    ) =>
                                      renderWrappingText(value, trace.trace_id),
                                  },
                                  {
                                    title: '页面 URL',
                                    dataIndex: 'page_url',
                                    width: '32%',
                                    render: (value: string | undefined) =>
                                      renderWrappingText(value),
                                  },
                                  {
                                    title: '操作',
                                    key: 'action',
                                    width: 120,
                                    render: (
                                      _: unknown,
                                      trace: ProtocolTrace,
                                    ) => (
                                      <Typography.Link
                                        onClick={() =>
                                          setSelectedTraceId(trace.trace_id)
                                        }
                                      >
                                        查看详情
                                      </Typography.Link>
                                    ),
                                  },
                                ]}
                              />
                            </Card>
                          ))}
                        </div>
                      </>
                    );
                  })()}
                </div>
              ),
            }))}
          />
        ) : (
          <Empty description="暂无协议轨迹" />
        )}
      </Card>

      <Card
        title="静态协议分析"
        extra={
          <Space>
            <Tag>{`JS 文件 ${staticAnalysis?.js_count || 0}`}</Tag>
            <Tag>{`协议画像 ${staticProfiles.length}`}</Tag>
          </Space>
        }
      >
        {staticProfiles.length ? (
          <Collapse
            items={staticProfiles.map((profile) => ({
              key: profile.id,
              label: (
                <Space wrap>
                  <Typography.Text strong>{profile.name}</Typography.Text>
                  {profile.encryption_enabled ? (
                    <Tag color="warning">加密链路</Tag>
                  ) : null}
                </Space>
              ),
              children: renderStaticProfile(profile),
            }))}
          />
        ) : (
          <Empty description="暂无静态协议画像" />
        )}
      </Card>

      <Drawer
        title="协议轨迹详情"
        size="50%"
        open={Boolean(selectedTrace)}
        onClose={() => setSelectedTraceId('')}
        destroyOnClose
      >
        {selectedTrace ? (
          <div style={{ display: 'grid', gap: 16, minWidth: 0 }}>
            <Descriptions bordered size="small" column={1}>
              <Descriptions.Item label="轨迹 ID">
                {selectedTrace.trace_id}
              </Descriptions.Item>
              <Descriptions.Item label="请求方法">
                {selectedTrace.method || 'GET'}
              </Descriptions.Item>
              <Descriptions.Item label="页面 URL">
                {selectedTrace.page_url || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="算法">
                {renderTagList(selectedTrace.algorithms)}
              </Descriptions.Item>
              <Descriptions.Item label="签名字段">
                {renderTagList(selectedTrace.signature_fields)}
              </Descriptions.Item>
              <Descriptions.Item label="动态参数">
                {renderKeyValueTags(selectedTrace.dynamic_params)}
              </Descriptions.Item>
              <Descriptions.Item label="会话材料">
                {renderKeyValueTags(selectedTrace.session_materials, {
                  maxHeight: 320,
                  dataTestId: 'protocol-session-materials',
                })}
              </Descriptions.Item>
            </Descriptions>

            <div
              style={{
                display: 'grid',
                gap: 16,
                gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                alignItems: 'start',
              }}
            >
              <Card size="small" title="请求甬道">
                <div style={{ display: 'grid', gap: 12 }}>
                  <Card size="small" title="加密前请求数据">
                    {renderSnippet(
                      getFlowStepByTitle(
                        selectedTraceFlow?.requestLane || [],
                        '原始请求明文',
                      ) || selectedTrace.request_before_transform,
                    )}
                  </Card>
                  <Card size="small" title="最终请求包">
                    {renderSnippet(
                      getFlowStepByTitle(
                        selectedTraceFlow?.requestLane || [],
                        '最终发包请求体',
                      ) || selectedTrace.final_request_body,
                    )}
                  </Card>
                </div>
              </Card>
              <Card size="small" title="响应甬道">
                <div style={{ display: 'grid', gap: 12 }}>
                  <Card size="small" title="原始响应包">
                    {renderSnippet(
                      getFlowStepByTitle(
                        selectedTraceFlow?.responseLane || [],
                        '原始响应密文',
                      ) ||
                        selectedTrace.session_materials
                          ?.latest_response_ciphertext,
                    )}
                  </Card>
                  <Card size="small" title="响应解密结果">
                    {renderSnippet(
                      getFlowStepByTitle(
                        selectedTraceFlow?.responseLane || [],
                        '响应明文',
                      ) ||
                        selectedTrace.session_materials
                          ?.latest_response_plaintext,
                    )}
                  </Card>
                </div>
              </Card>
            </div>

            <Card title="链路总结" size="small">
              <Descriptions bordered size="small" column={1}>
                <Descriptions.Item label="请求链路">
                  {selectedTraceFlow?.summary.hasRequestLane
                    ? '已捕获'
                    : '未捕获'}
                </Descriptions.Item>
                <Descriptions.Item label="响应链路">
                  {selectedTraceFlow?.summary.hasResponseLane
                    ? '已捕获'
                    : '未捕获'}
                </Descriptions.Item>
                <Descriptions.Item label="响应密文">
                  {selectedTraceFlow?.summary.hasResponseCiphertext
                    ? '已捕获'
                    : '未捕获'}
                </Descriptions.Item>
                <Descriptions.Item label="响应明文">
                  {selectedTraceFlow?.summary.hasResponsePlaintext
                    ? '已捕获'
                    : '未捕获'}
                </Descriptions.Item>
                <Descriptions.Item label="最终明文来源">
                  {selectedTraceFlow?.summary.finalResponseSource || '-'}
                </Descriptions.Item>
              </Descriptions>
            </Card>

            <Card
              title="AI 解释"
              size="small"
              extra={
                <Button
                  size="small"
                  onClick={() => void handleExplainTrace()}
                  loading={aiExplaining}
                >
                  生成 AI 解释
                </Button>
              }
            >
              <div style={{ display: 'grid', gap: 12 }}>
                {selectedAIExplanation?.model ? (
                  <Typography.Text type="secondary">
                    当前模型：{selectedAIExplanation.model}
                  </Typography.Text>
                ) : null}
                {aiExplanationError ? (
                  <Alert type="warning" showIcon message={aiExplanationError} />
                ) : null}
                {selectedAIExplanation?.explanation ? (
                  <div
                    style={{
                      display: 'grid',
                      gap: 16,
                      gridTemplateColumns:
                        'repeat(auto-fit, minmax(280px, 1fr))',
                      alignItems: 'start',
                    }}
                  >
                    <Card title="请求甬道 AI 解释" size="small">
                      {selectedAIExplanationLanes.request ? (
                        renderAIExplanationCards(
                          selectedAIExplanationLanes.request,
                          '请求甬道解释生成中或暂无内容',
                        )
                      ) : (
                        <Empty description="请求甬道解释生成中或暂无内容" />
                      )}
                    </Card>
                    <Card title="响应甬道 AI 解释" size="small">
                      {selectedAIExplanationLanes.response ? (
                        renderAIExplanationCards(
                          selectedAIExplanationLanes.response,
                          '响应甬道解释生成中或暂无内容',
                        )
                      ) : (
                        <Empty description="响应甬道解释生成中或暂无内容" />
                      )}
                    </Card>
                  </div>
                ) : (
                  <Empty description="暂未生成 AI 白话解释，可手动点击生成。" />
                )}
              </div>
            </Card>

            <div
              style={{
                display: 'grid',
                gap: 16,
                gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                alignItems: 'start',
              }}
            >
              <Card title="请求链路流程" size="small">
                {renderFlowLaneTimeline(
                  selectedTraceFlow?.requestLane || [],
                  '暂无请求链路流程',
                )}
              </Card>
              <Card title="响应链路流程" size="small">
                {renderFlowLaneTimeline(
                  selectedTraceFlow?.responseLane || [],
                  '暂无响应链路流程',
                )}
              </Card>
            </div>
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}

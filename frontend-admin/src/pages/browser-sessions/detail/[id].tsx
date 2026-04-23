import { ArrowLeftOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import {
  Button,
  Card,
  Empty,
  Space,
  Spin,
  Table,
  Tag,
  Typography,
  message,
  type TableColumnsType,
} from 'antd';
import { useEffect, useMemo, useState } from 'react';
import { history, useParams } from 'umi';

import { fetchBrowserSessionDetail } from '@/services/browserSessions';
import type {
  BrowserSessionDetail,
  BrowserSessionRequestSummary,
  BrowserSessionTraceSummary,
  ProtocolTraceStep,
} from '@/types/task';
import { formatDateTime } from '@/utils/datetime';

const SESSION_MATERIAL_HIGHLIGHTS = [
  'rsa_public_key',
  'rsa_public_key_source',
  'key_exchange_public_key',
  'key_exchange_header',
  'latest_plaintext',
  'latest_ciphertext',
  'latest_response_plaintext',
  'latest_response_ciphertext',
];

function renderCopyableParagraph(label: string, value?: string, rows = 4) {
  return (
    <Typography.Paragraph
      copyable={!!value}
      ellipsis={{ rows, expandable: true, symbol: '展开' }}
      style={{ marginBottom: 0 }}
    >
      {label}：{value || '-'}
    </Typography.Paragraph>
  );
}

function renderTraceSteps(title: string, steps?: ProtocolTraceStep[]) {
  if (!steps?.length) {
    return <Typography.Text type="secondary">{title}：-</Typography.Text>;
  }

  return (
    <Space direction="vertical" size={8} style={{ width: '100%' }}>
      <Typography.Text strong>{title}</Typography.Text>
      {steps.map((step, index) => (
        <Card
          key={`${title}-${index}-${step.call_id || step.function_path || step.source || 'step'}`}
          size="small"
          style={{ background: '#fff' }}
        >
          <Space direction="vertical" size={4} style={{ width: '100%' }}>
            <Typography.Text>
              步骤 {index + 1}：{step.algorithm || step.source || '未命名步骤'}
            </Typography.Text>
            <Typography.Text type="secondary">
              来源：{step.function_path || step.source || '-'}
              {step.module_id ? ` / 模块 ${step.module_id}` : ''}
            </Typography.Text>
            {renderCopyableParagraph('输入', step.input_preview, 3)}
            {renderCopyableParagraph('输出', step.output_preview, 3)}
          </Space>
        </Card>
      ))}
    </Space>
  );
}

function renderSessionMaterials(trace?: BrowserSessionTraceSummary | null) {
  const materials = trace?.session_materials || {};
  const entries = Object.entries(materials).filter(([, value]) => !!value);
  if (!entries.length) {
    return <Typography.Text type="secondary">会话材料：-</Typography.Text>;
  }

  const orderedEntries = [
    ...SESSION_MATERIAL_HIGHLIGHTS.filter((key) => materials[key]).map((key) => [
      key,
      materials[key],
    ]),
    ...entries.filter(([key]) => !SESSION_MATERIAL_HIGHLIGHTS.includes(key)),
  ] as Array<[string, string]>;

  return (
    <Space direction="vertical" size={8} style={{ width: '100%' }}>
      <Typography.Text strong>会话材料</Typography.Text>
      {orderedEntries.map(([key, value]) => (
        <Card key={key} size="small" style={{ background: '#fff' }}>
          {renderCopyableParagraph(key, value, key.includes('key') ? 6 : 4)}
        </Card>
      ))}
    </Space>
  );
}

function findTraceForRequest(
  request: BrowserSessionRequestSummary | null,
  traces?: BrowserSessionTraceSummary[],
) {
  if (!request || !traces?.length) {
    return null;
  }

  if (request.trace_id) {
    const exactTrace = traces.find((trace) => trace.trace_id === request.trace_id);
    if (exactTrace) {
      return exactTrace;
    }
  }

  return (
    traces.find(
      (trace) =>
        trace.request_url === request.url &&
        (trace.method || 'GET').toUpperCase() === (request.method || 'GET').toUpperCase(),
    ) || null
  );
}

function collectTraceMaterials(
  selectedTrace: BrowserSessionTraceSummary | null,
  traces?: BrowserSessionTraceSummary[],
) {
  if (selectedTrace?.session_materials && Object.keys(selectedTrace.session_materials).length) {
    return selectedTrace;
  }
  return (
    traces?.find((trace) => trace.session_materials && Object.keys(trace.session_materials).length) ||
    null
  );
}

function buildRawRequest(request: BrowserSessionRequestSummary | null) {
  if (!request) {
    return '-';
  }

  const lines: string[] = [];
  const method = request.method || 'GET';
  let requestTarget = request.url || '/';

  try {
    const parsed = new URL(request.url);
    requestTarget = `${parsed.pathname || '/'}${parsed.search || ''}`;
    lines.push(`${method} ${requestTarget} HTTP/1.1`);
    lines.push(`Host: ${parsed.host}`);
  } catch {
    lines.push(`${method} ${requestTarget} HTTP/1.1`);
  }

  Object.entries(request.request_headers || {}).forEach(([key, value]) => {
    lines.push(`${key}: ${value}`);
  });

  if (request.request_body) {
    lines.push('');
    lines.push(request.request_body);
  }

  return lines.join('\n');
}

function buildRawResponse(request: BrowserSessionRequestSummary | null) {
  if (!request) {
    return '-';
  }

  const lines: string[] = [];
  lines.push(`HTTP/1.1 ${request.response_code || 0}`);
  Object.entries(request.response_headers || {}).forEach(([key, value]) => {
    lines.push(`${key}: ${value}`);
  });

  if (request.response_body) {
    lines.push('');
    lines.push(request.response_body);
  }

  return lines.join('\n');
}

function renderRawBlock(value: string) {
  return (
    <pre
      style={{
        margin: 0,
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        fontFamily:
          'ui-monospace, SFMono-Regular, SF Mono, Menlo, Monaco, Consolas, Liberation Mono, monospace',
        fontSize: 12,
        lineHeight: 1.7,
      }}
    >
      {value}
    </pre>
  );
}

export default function BrowserSessionDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<BrowserSessionDetail>();
  const [selectedRequestId, setSelectedRequestId] = useState<number | null>(null);

  useEffect(() => {
    if (!id) {
      return;
    }
    let alive = true;
    setLoading(true);
    fetchBrowserSessionDetail(id)
      .then((resp) => {
        if (!alive) return;
        setDetail(resp.data);
        setSelectedRequestId(resp.data.requests?.[0]?.id ?? null);
      })
      .catch((error: any) => {
        const detailMessage =
          error?.data?.detail ||
          error?.data?.error ||
          error?.message ||
          '加载会话详情失败';
        message.error(String(detailMessage));
      })
      .finally(() => {
        if (alive) {
          setLoading(false);
        }
      });

    return () => {
      alive = false;
    };
  }, [id]);

  const selectedRequest = useMemo(
    () =>
      detail?.requests?.find((item) => item.id === selectedRequestId) ||
      detail?.requests?.[0] ||
      null,
    [detail?.requests, selectedRequestId],
  );
  const selectedTrace = useMemo(
    () => findTraceForRequest(selectedRequest, detail?.suspiciousTraces),
    [detail?.suspiciousTraces, selectedRequest],
  );
  const materialTrace = useMemo(
    () => collectTraceMaterials(selectedTrace, detail?.suspiciousTraces),
    [detail?.suspiciousTraces, selectedTrace],
  );
  const rawRequest = useMemo(() => buildRawRequest(selectedRequest), [selectedRequest]);
  const rawResponse = useMemo(() => buildRawResponse(selectedRequest), [selectedRequest]);

  const columns: TableColumnsType<BrowserSessionRequestSummary> = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 88,
      defaultSortOrder: 'descend',
      sorter: (a, b) => a.id - b.id,
    },
    {
      title: 'Method',
      dataIndex: 'method',
      key: 'method',
      width: 90,
      render: (value: string) => <Tag color="blue">{value || 'GET'}</Tag>,
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      ellipsis: true,
      render: (value: string) => <Typography.Text ellipsis={{ tooltip: value }}>{value}</Typography.Text>,
    },
    {
      title: 'Status',
      dataIndex: 'response_code',
      key: 'response_code',
      width: 90,
      render: (value?: number) =>
        value ? <Tag color={value >= 400 ? 'error' : 'success'}>{value}</Tag> : '-',
    },
    {
      title: 'Signal',
      key: 'signal',
      width: 140,
      render: (_value, request) =>
        request.is_suspicious ? (
          <Tag color="warning">可疑加密</Tag>
        ) : request.has_protocol_trace ? (
          <Tag color="processing">协议链路</Tag>
        ) : (
          '-'
        ),
    },
    {
      title: 'Time',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (value: string) => formatDateTime(value),
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card
        title="受控会话详情"
        extra={
          <Space>
            <Button icon={<ArrowLeftOutlined />} onClick={() => history.push('/browser-sessions')}>
              返回列表
            </Button>
            {detail ? (
              <Tag color={detail.session.suspicious_crypto_count ? 'warning' : 'default'}>
                <SafetyCertificateOutlined /> 可疑加密 {detail.session.suspicious_crypto_count || 0}
              </Tag>
            ) : null}
          </Space>
        }
      >
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '48px 0' }}>
            <Spin />
          </div>
        ) : !detail ? (
          <Empty description="暂无会话详情" />
        ) : (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Card size="small">
              <Space direction="vertical" size={4}>
                <Typography.Text strong>{detail.session.site_host}</Typography.Text>
                <Typography.Text type="secondary">{detail.session.entry_url}</Typography.Text>
                <Typography.Text type="secondary">
                  状态 {detail.session.status} / 页面 {detail.session.page_count} / 请求{' '}
                  {detail.session.request_count}
                </Typography.Text>
              </Space>
            </Card>

            <Card
              size="small"
              title={`流量历史 ${detail.requests.length}`}
              styles={{ body: { padding: 0 } }}
            >
              <Table<BrowserSessionRequestSummary>
                rowKey="id"
                virtual
                size="small"
                pagination={false}
                scroll={{ y: 260, x: 1400 }}
                dataSource={detail.requests}
                columns={columns}
                onRow={(record) => ({
                  onClick: () => setSelectedRequestId(record.id),
                  style: {
                    cursor: 'pointer',
                    background: record.id === selectedRequest?.id ? '#eaf3ff' : undefined,
                  },
                })}
              />
            </Card>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr) 340px',
                gap: 12,
                alignItems: 'stretch',
              }}
            >
              <Card
                size="small"
                title="Request"
                style={{ height: 560 }}
                styles={{ body: { height: 511, overflow: 'auto' } }}
              >
                {!selectedRequest ? <Empty description="请选择一条流量" /> : renderRawBlock(rawRequest)}
              </Card>
              <Card
                size="small"
                title="Response"
                style={{ height: 560 }}
                styles={{ body: { height: 511, overflow: 'auto' } }}
              >
                {!selectedRequest ? <Empty description="请选择一条流量" /> : renderRawBlock(rawResponse)}
              </Card>
              <Card
                size="small"
                title="Inspector"
                style={{ height: 560 }}
                styles={{ body: { height: 511, overflow: 'auto' } }}
              >
                {!selectedRequest ? (
                  <Empty description="请选择一条流量" />
                ) : (
                  <Space direction="vertical" size={12} style={{ width: '100%' }}>
                    {selectedTrace ? (
                      <Card size="small" style={{ background: '#fafafa' }}>
                        <Space direction="vertical" size={6} style={{ width: '100%' }}>
                          <Typography.Text strong>链路</Typography.Text>
                          <Typography.Text type="secondary">
                            {selectedTrace.suspicious_reason || '命中可疑协议信号'}
                          </Typography.Text>
                          <Typography.Text>
                            算法：
                            {selectedTrace.algorithms?.length
                              ? selectedTrace.algorithms.join(', ')
                              : '未识别'}
                          </Typography.Text>
                          {renderTraceSteps('请求链路甬道', selectedTrace.request_steps)}
                          {renderTraceSteps('响应链路甬道', selectedTrace.response_steps)}
                        </Space>
                      </Card>
                    ) : (
                      <Empty description="当前流量暂无链路" />
                    )}
                    {materialTrace ? (
                      <Space direction="vertical" size={10} style={{ width: '100%' }}>
                        <Typography.Text type="secondary">
                          材料来源：{materialTrace.request_url || '当前会话'}
                        </Typography.Text>
                        {renderSessionMaterials(materialTrace)}
                      </Space>
                    ) : (
                      <Empty description="当前会话暂无材料" />
                    )}
                  </Space>
                )}
              </Card>
            </div>
          </Space>
        )}
      </Card>
    </Space>
  );
}

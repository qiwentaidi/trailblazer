import {
  DeleteOutlined,
  EyeInvisibleOutlined,
  EyeOutlined,
  LinkOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';
import {
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  type TableColumnsType,
  Tag,
  Typography,
  message,
} from 'antd';
import { useEffect, useRef, useState } from 'react';
import { history } from 'umi';

import {
  deleteBrowserSession,
  fetchBrowserSessions,
  launchBrowserSession,
  type FetchBrowserSessionsFilters,
  type LaunchBrowserSessionPayload,
} from '@/services/browserSessions';
import type { BrowserSessionSummary } from '@/types/task';
import { formatDateTime } from '@/utils/datetime';

const STATUS_OPTIONS = [
  { label: '全部状态', value: undefined },
  { label: '运行中', value: 'running' },
  { label: '已完成', value: 'completed' },
  { label: '失败', value: 'failed' },
];

const STATUS_COLORS: Record<string, string> = {
  running: 'processing',
  completed: 'success',
  failed: 'error',
  stopped: 'warning',
};

const MODE_LABELS: Record<string, string> = {
  manual: '人工操作',
  auto: '自动触发',
};

function resolveBrowserSessionDeletePageTarget(
  total: number,
  currentPage: number,
  currentPageSize: number,
  remainingRowsOnPage: number,
) {
  const nextTotal = Math.max(0, total - 1);
  const maxPage = Math.max(1, Math.ceil(nextTotal / Math.max(1, currentPageSize)));
  const shouldStepBack = remainingRowsOnPage <= 1 && currentPage > 1;
  const requestedPage = shouldStepBack ? currentPage - 1 : currentPage;
  return Math.min(Math.max(1, requestedPage), maxPage);
}

export default function BrowserSessionsPage() {
  const [launchForm] = Form.useForm<LaunchBrowserSessionPayload>();
  const [sessions, setSessions] = useState<BrowserSessionSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [launchOpen, setLaunchOpen] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [total, setTotal] = useState(0);
  const [keywordInput, setKeywordInput] = useState('');
  const [keyword, setKeyword] = useState('');
  const [statusFilter, setStatusFilter] = useState<string | undefined>();
  const requestSeq = useRef(0);
  const isMounted = useRef(false);
  const hasRunningSessions = sessions.some((session) => session.status === 'running');
  const captureDurationSeconds = Form.useWatch('captureDurationSeconds', launchForm);
  const keepOpen = captureDurationSeconds === 0;

  const currentFilters: FetchBrowserSessionsFilters = {
    keyword: keyword || undefined,
    status: statusFilter,
  };

  const loadSessions = async (
    nextPage = page,
    nextSize = pageSize,
    filters: FetchBrowserSessionsFilters = currentFilters,
    silent = false,
  ) => {
    const requestId = ++requestSeq.current;
    if (!silent) {
      setLoading(true);
    }
    try {
      const resp = await fetchBrowserSessions(nextPage, nextSize, filters);
      if (!isMounted.current || requestId !== requestSeq.current) {
        return;
      }
      setSessions(resp.data || []);
      setTotal(resp.pagination?.total || 0);
      setPage(resp.pagination?.page || nextPage);
      setPageSize(resp.pagination?.size || nextSize);
    } catch {
      if (isMounted.current && !silent) {
        message.error('加载受控会话失败');
      }
    } finally {
      if (!silent && isMounted.current && requestId === requestSeq.current) {
        setLoading(false);
      }
    }
  };

  const handleDeleteSession = async (record: BrowserSessionSummary) => {
    const targetPage = resolveBrowserSessionDeletePageTarget(
      total,
      page,
      pageSize,
      sessions.length,
    );

    setLoading(true);
    try {
      await deleteBrowserSession(record.session_id);
      message.success('受控会话已删除');
      await loadSessions(targetPage, pageSize, currentFilters);
    } catch (error: any) {
      const detail =
        error?.data?.detail ||
        error?.data?.error ||
        error?.message ||
        '删除受控会话失败';
      message.error(String(detail));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    isMounted.current = true;
    void loadSessions(1, pageSize);
    return () => {
      isMounted.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const intervalMs = hasRunningSessions ? 2000 : 5000;
    const timer = window.setInterval(() => {
      if (!document.hidden) {
        void loadSessions(page, pageSize, currentFilters, true);
      }
    }, intervalMs);

    const handleVisibilityChange = () => {
      if (!document.hidden) {
        void loadSessions(page, pageSize, currentFilters, true);
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasRunningSessions, page, pageSize, keyword, statusFilter]);

  const columns: TableColumnsType<BrowserSessionSummary> = [
    {
      title: '站点',
      dataIndex: 'site_host',
      key: 'site_host',
      render: (_value, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Text strong>{record.site_host}</Typography.Text>
          <Typography.Text type="secondary" style={{ maxWidth: 360 }} ellipsis>
            {record.entry_url}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '会话状态',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (value: string) => (
        <Tag color={STATUS_COLORS[value] || 'default'}>{value || 'unknown'}</Tag>
      ),
    },
    {
      title: '运行模式',
      dataIndex: 'mode',
      key: 'mode',
      width: 180,
      render: (_value, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Text>{MODE_LABELS[record.mode] || record.mode || '-'}</Typography.Text>
          <Typography.Text type="secondary">
            {record.browser_mode || '-'} / {record.browser_visible ? '可视' : '无头'}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '代理',
      dataIndex: 'proxy_type',
      key: 'proxy_type',
      width: 180,
      render: (_value, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Text>{record.proxy_type || 'none'}</Typography.Text>
          <Typography.Text type="secondary" ellipsis style={{ maxWidth: 140 }}>
            {record.proxy_address || '-'}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '观测计数',
      key: 'metrics',
      width: 280,
      render: (_value, record) => (
        <Space size={[8, 8]} wrap>
          <Tag icon={<LinkOutlined />}>页面 {record.page_count || 0}</Tag>
          <Tag>请求 {record.request_count || 0}</Tag>
          <Tag color={record.suspicious_crypto_count ? 'warning' : 'default'}>
            <SafetyCertificateOutlined /> 可疑加密 {record.suspicious_crypto_count || 0}
          </Tag>
        </Space>
      ),
    },
    {
      title: '时间',
      key: 'time',
      width: 200,
      render: (_value, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Text>{formatDateTime(record.started_at)}</Typography.Text>
          <Typography.Text type="secondary">
            最近活动 {formatDateTime(record.last_activity_at)}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 180,
      render: (_value, record) => (
        <Space>
          <Button size="small" onClick={() => history.push(`/browser-sessions/${record.session_id}`)}>
            详情
          </Button>
          <Popconfirm
            title="确认删除该受控会话吗？"
            description="删除后会同时清理页面记录和可疑加密轨迹。"
            okText="删除"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            onConfirm={() => void handleDeleteSession(record)}
          >
            <Button size="small" danger icon={<DeleteOutlined />}>
              删除
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <Card
      title="受控会话列表"
      extra={
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => void loadSessions(page, pageSize, currentFilters)}>
            刷新
          </Button>
          <Button
            type="primary"
            onClick={() => {
              launchForm.setFieldsValue({
                mode: 'manual',
                browserVisible: true,
                captureDurationSeconds: 0,
                timeoutSeconds: 0,
              });
              setLaunchOpen(true);
            }}
          >
            启动会话
          </Button>
          <Input.Search
            allowClear
            placeholder="按会话 ID、站点或入口 URL 筛选"
            style={{ width: 320 }}
            value={keywordInput}
            onChange={(event) => setKeywordInput(event.target.value)}
            onSearch={(value) => {
              const nextKeyword = value.trim();
              setKeywordInput(value);
              setKeyword(nextKeyword);
              void loadSessions(1, pageSize, {
                ...currentFilters,
                keyword: nextKeyword || undefined,
              });
            }}
          />
          <Select
            allowClear
            style={{ width: 160 }}
            placeholder="会话状态"
            options={STATUS_OPTIONS}
            value={statusFilter}
            onChange={(value) => {
              setStatusFilter(value);
              void loadSessions(1, pageSize, {
                ...currentFilters,
                status: value,
              });
            }}
          />
        </Space>
      }
    >
      <Table<BrowserSessionSummary>
        rowKey="session_id"
        loading={loading}
        dataSource={sessions}
        columns={columns}
        virtual
        scroll={{ y: 560, x: 1200 }}
        pagination={{
          current: page,
          pageSize,
          total,
          showSizeChanger: true,
          onChange: (nextPage, nextPageSize) => {
            void loadSessions(nextPage, nextPageSize, currentFilters);
          },
        }}
        locale={{
          emptyText: (
            <Space direction="vertical" size={8}>
              <Typography.Text type="secondary">还没有受控浏览器会话记录</Typography.Text>
              <Typography.Text type="secondary">
                先运行受控浏览器 demo，再回到这里查看单站点会话。
              </Typography.Text>
            </Space>
          ),
        }}
      />
      <Card size="small" style={{ marginTop: 16, background: '#fafafa' }} styles={{ body: { padding: 14 } }}>
        <Space size={18} wrap>
          <Typography.Text type="secondary">
            <EyeOutlined /> 可视浏览器适合人工调试
          </Typography.Text>
          <Typography.Text type="secondary">
            <EyeInvisibleOutlined /> 无头模式适合自动回归
          </Typography.Text>
          <Typography.Text type="secondary">
            建议约束一个受控窗口只记录一个站点
          </Typography.Text>
        </Space>
      </Card>
      <Modal
        title="启动受控浏览器会话"
        open={launchOpen}
        confirmLoading={launching}
        destroyOnClose
        okText="启动"
        cancelText="取消"
        onCancel={() => setLaunchOpen(false)}
        onOk={async () => {
          try {
            const values = await launchForm.validateFields();
            setLaunching(true);
            const payload: LaunchBrowserSessionPayload = {
              ...values,
              proxyType: values.proxyType || (values.proxyServer ? undefined : 'none'),
            };
            await launchBrowserSession(payload);
            message.success('受控会话已启动');
            setLaunchOpen(false);
            void loadSessions(1, pageSize, currentFilters);
          } catch (error: any) {
            if (error?.errorFields) {
              return;
            }
            const detail =
              error?.data?.detail ||
              error?.data?.error ||
              error?.message ||
              '启动受控会话失败';
            message.error(String(detail));
          } finally {
            setLaunching(false);
          }
        }}
      >
        <Form<LaunchBrowserSessionPayload>
          form={launchForm}
          layout="vertical"
          initialValues={{
            mode: 'manual',
            browserVisible: true,
            captureDurationSeconds: 0,
            timeoutSeconds: 0,
          }}
        >
          <Form.Item
            label="目标站点"
            name="targetUrl"
            rules={[
              { required: true, message: '请输入目标 URL' },
              { type: 'url', message: '请输入合法的 URL' },
            ]}
          >
            <Input placeholder="https://bittalk-user.shuiyou.com.cn/" />
          </Form.Item>
          <Form.Item label="运行模式" name="mode">
            <Select
              options={[
                { label: '人工操作', value: 'manual' },
                { label: '自动触发', value: 'auto' },
              ]}
            />
          </Form.Item>
          <Form.Item label="可视浏览器" name="browserVisible" valuePropName="checked">
            <Switch checkedChildren="可视" unCheckedChildren="无头" />
          </Form.Item>
          <Form.Item label="代理地址" name="proxyServer">
            <Input placeholder="http://127.0.0.1:8080" />
          </Form.Item>
          <Form.Item label="代理类型" name="proxyType">
            <Select
              allowClear
              placeholder="留空则自动推断"
              options={[
                { label: '自动推断', value: undefined },
                { label: 'HTTP', value: 'http' },
                { label: 'HTTPS', value: 'https' },
                { label: 'SOCKS5', value: 'socks5' },
                { label: '自定义', value: 'custom' },
              ]}
            />
          </Form.Item>
          <Form.Item label="代理绕过列表" name="proxyBypassList">
            <Input placeholder="<-loopback>" />
          </Form.Item>
          <Form.Item
            label="人工操作窗口时长（秒）"
            name="captureDurationSeconds"
            extra="填 0 表示永不关闭，只有你手动关闭浏览器窗口后才结束会话。"
          >
            <InputNumber min={0} max={600} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            label="总超时时间（秒）"
            name="timeoutSeconds"
            extra={keepOpen ? '当前已由人工操作窗口时长 0 接管，不会自动超时结束。' : undefined}
          >
            <InputNumber
              min={20}
              max={900}
              style={{ width: '100%' }}
              disabled={!!keepOpen}
              placeholder={keepOpen ? '人工操作窗口时长为 0 时此项不生效' : undefined}
            />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}

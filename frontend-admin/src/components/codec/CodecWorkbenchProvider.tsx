import {
  CopyOutlined,
  DeleteOutlined,
  RightOutlined,
  SwapOutlined,
} from '@ant-design/icons';
import {
  Button,
  Card,
  Collapse,
  Divider,
  Drawer,
  Empty,
  FloatButton,
  Input,
  Segmented,
  Select,
  Space,
  Tag,
  Typography,
  message,
} from 'antd';
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import {
  codecCategoryOptions,
  codecOperationsByCategory,
  getCodecAvailableModes,
  getCodecDefaultMode,
  getCodecDefaultOptions,
  getCodecOperation,
  runCodecOperation,
} from './operations';
import type {
  CodecMode,
  CodecWorkbenchState,
  OpenCodecWorkbenchOptions,
} from './types';

const STORAGE_KEY = 'trailblazer-codec-workbench';

type CodecWorkbenchContextValue = {
  openCodecWorkbench: (options?: OpenCodecWorkbenchOptions) => void;
  closeCodecWorkbench: () => void;
};

const CodecWorkbenchContext = createContext<CodecWorkbenchContextValue | null>(
  null,
);

const DEFAULT_OPERATION = getCodecOperation();
const DEFAULT_STATE: CodecWorkbenchState = {
  operationId: DEFAULT_OPERATION.id,
  mode: getCodecDefaultMode(DEFAULT_OPERATION),
  input: '',
  options: getCodecDefaultOptions(DEFAULT_OPERATION),
};

function CodecToolIcon() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      width="22"
      height="22"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{ display: 'block' }}
    >
      <path d="M5.75 10.75V8.9a2.6 2.6 0 1 1 5.2 0v1.85" />
      <rect x="4.5" y="10.75" width="7.7" height="6.65" rx="1.6" />
      <path d="M15.15 9.55V8.3a2.35 2.35 0 0 1 4.22-1.42" />
      <path d="M14 9.55h4.6a1.6 1.6 0 0 1 1.6 1.6v4.65a1.6 1.6 0 0 1-1.6 1.6H14" />
      <path d="M11.1 13.1h2.2" />
      <path d="M12.35 11.9l1.2 1.2-1.2 1.2" />
    </svg>
  );
}

const copyText = async (value: string) => {
  if (!value) {
    return;
  }
  await navigator.clipboard.writeText(value);
};

export function useCodecWorkbench() {
  const context = useContext(CodecWorkbenchContext);
  if (!context) {
    throw new Error(
      'useCodecWorkbench must be used within CodecWorkbenchProvider',
    );
  }
  return context;
}

export default function CodecWorkbenchProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [state, setState] = useState<CodecWorkbenchState>(DEFAULT_STATE);
  const [search, setSearch] = useState('');
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) {
        setLoaded(true);
        return;
      }
      const parsed = JSON.parse(raw) as Partial<CodecWorkbenchState>;
      const operation = getCodecOperation(parsed.operationId);
      const nextMode = getCodecAvailableModes(operation).includes(
        parsed.mode as CodecMode,
      )
        ? (parsed.mode as CodecMode)
        : getCodecDefaultMode(operation);
      setState({
        operationId: operation.id,
        mode: nextMode,
        input: parsed.input || '',
        options: {
          ...getCodecDefaultOptions(operation),
          ...(parsed.options || {}),
        },
      });
    } catch (error) {
      console.error(error);
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    if (!loaded) {
      return;
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  }, [loaded, state]);

  const operation = useMemo(
    () => getCodecOperation(state.operationId),
    [state],
  );
  const availableModes = useMemo(
    () => getCodecAvailableModes(operation),
    [operation],
  );
  const output = useMemo(
    () => runCodecOperation(operation, state.mode, state.input, state.options),
    [operation, state.input, state.mode, state.options],
  );

  const groupedOperations = useMemo(() => {
    const query = search.trim().toLowerCase();
    return codecOperationsByCategory
      .map((category) => ({
        ...category,
        operations: category.operations.filter(
          (item) =>
            !query ||
            item.name.toLowerCase().includes(query) ||
            item.description.toLowerCase().includes(query),
        ),
      }))
      .filter((category) => category.operations.length > 0);
  }, [search]);

  const setOperation = (operationId: string) => {
    const nextOperation = getCodecOperation(operationId);
    setState((current) => ({
      operationId: nextOperation.id,
      mode: getCodecDefaultMode(nextOperation),
      input: current.input,
      options: getCodecDefaultOptions(nextOperation),
    }));
  };

  const setMode = (mode: CodecMode) => {
    if (!availableModes.includes(mode)) {
      return;
    }
    setState((current) => ({ ...current, mode }));
  };

  const setInput = (input: string) => {
    setState((current) => ({ ...current, input }));
  };

  const setOption = (key: string, value: string) => {
    setState((current) => ({
      ...current,
      options: {
        ...current.options,
        [key]: value,
      },
    }));
  };

  const openCodecWorkbench = useCallback(
    (options?: OpenCodecWorkbenchOptions) => {
      setOpen(true);
      if (!options) {
        return;
      }
      const nextOperation = getCodecOperation(
        options.operationId || state.operationId,
      );
      const nextMode = getCodecAvailableModes(nextOperation).includes(
        (options.mode || state.mode) as CodecMode,
      )
        ? ((options.mode || state.mode) as CodecMode)
        : getCodecDefaultMode(nextOperation);
      setState((current) => ({
        operationId: nextOperation.id,
        mode: nextMode,
        input:
          options.input == null
            ? current.input
            : options.replaceInput === false
              ? `${current.input}${options.input}`
              : options.input,
        options: {
          ...getCodecDefaultOptions(nextOperation),
          ...(options.options || {}),
        },
      }));
    },
    [state.mode, state.operationId],
  );

  const closeCodecWorkbench = useCallback(() => setOpen(false), []);

  const contextValue = useMemo(
    () => ({
      openCodecWorkbench,
      closeCodecWorkbench,
    }),
    [closeCodecWorkbench, openCodecWorkbench],
  );

  return (
    <CodecWorkbenchContext.Provider value={contextValue}>
      {children}
      <FloatButton
        aria-label="加解密工具"
        icon={<CodecToolIcon />}
        tooltip="加解密工具"
        style={{
          position: 'fixed',
          right: 24,
          bottom: 144,
          width: 50,
          height: 50,
          zIndex: 300,
          boxShadow: '0 8px 24px rgba(0, 0, 0, 0.16)',
        }}
        onClick={() => setOpen(true)}
      />
      <Drawer
        title="前端加解密工具"
        placement="right"
        size="50vw"
        zIndex={1400}
        open={open}
        onClose={closeCodecWorkbench}
        destroyOnClose={false}
        styles={{ body: { padding: 16 } }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '260px minmax(0, 1fr)',
            gap: 16,
            height: '100%',
          }}
        >
          <Card
            size="small"
            title="能力列表"
            styles={{ body: { padding: 12, display: 'grid', gap: 12 } }}
          >
            <Input.Search
              allowClear
              placeholder="搜索操作"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            {groupedOperations.length ? (
              <Collapse
                defaultActiveKey={codecCategoryOptions.map((item) => item.id)}
                items={groupedOperations.map((category) => ({
                  key: category.id,
                  label: category.label,
                  children: (
                    <div style={{ display: 'grid', gap: 8 }}>
                      {category.operations.map((item) => (
                        <Button
                          key={item.id}
                          type={
                            item.id === operation.id ? 'primary' : 'default'
                          }
                          block
                          style={{
                            justifyContent: 'flex-start',
                            height: 'auto',
                            paddingBlock: 10,
                            paddingInline: 12,
                            borderRadius: 10,
                          }}
                          onClick={() => setOperation(item.id)}
                        >
                          <div
                            style={{
                              display: 'grid',
                              gap: 4,
                              textAlign: 'left',
                              width: '100%',
                            }}
                          >
                            <span>{item.name}</span>
                            <Typography.Text
                              type={
                                item.id === operation.id
                                  ? undefined
                                  : 'secondary'
                              }
                              style={{ whiteSpace: 'normal', fontSize: 12 }}
                            >
                              {item.description}
                            </Typography.Text>
                          </div>
                        </Button>
                      ))}
                    </div>
                  ),
                }))}
              />
            ) : (
              <Empty description="没有匹配的操作" />
            )}
          </Card>

          <div
            style={{
              display: 'grid',
              gap: 16,
              minWidth: 0,
              gridTemplateRows: 'auto auto minmax(0, 1fr)',
            }}
          >
            <div
              style={{
                border: '1px solid #f0f0f0',
                borderRadius: 16,
                background: 'linear-gradient(180deg, #ffffff 0%, #fafcff 100%)',
                padding: 18,
                display: 'grid',
                gap: 16,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  gap: 12,
                  flexWrap: 'wrap',
                }}
              >
                <div style={{ display: 'grid', gap: 8, minWidth: 0 }}>
                  <Space wrap>
                    <Typography.Title level={5} style={{ margin: 0 }}>
                      {operation.name}
                    </Typography.Title>
                    <Tag variant="filled" color="blue">
                      {
                        codecCategoryOptions.find(
                          (item) => item.id === operation.category,
                        )?.label
                      }
                    </Tag>
                  </Space>
                  <Typography.Paragraph
                    type="secondary"
                    style={{ marginBottom: 0, maxWidth: 720 }}
                  >
                    {operation.description}
                  </Typography.Paragraph>
                </div>
                <Space wrap>
                  <Button
                    icon={<DeleteOutlined />}
                    onClick={() =>
                      setState((current) => ({ ...current, input: '' }))
                    }
                  >
                    清空输入
                  </Button>
                  <Button
                    icon={<CopyOutlined />}
                    onClick={() =>
                      copyText(output)
                        .then(() => message.success('输出已复制'))
                        .catch((error) => {
                          console.error(error);
                          message.error('复制失败');
                        })
                    }
                    disabled={!output}
                  >
                    复制输出
                  </Button>
                  <Button
                    icon={<SwapOutlined />}
                    onClick={() => setInput(output)}
                    disabled={!output}
                  >
                    输出回填输入
                  </Button>
                </Space>
              </div>

              <div style={{ display: 'grid', gap: 10 }}>
                <Typography.Text strong>操作模式</Typography.Text>
                <Segmented<CodecMode>
                  options={availableModes.map((mode) => ({
                    label:
                      mode === 'encode'
                        ? '编码 / 加密'
                        : mode === 'decode'
                          ? '解码 / 解密'
                          : '转换',
                    value: mode,
                  }))}
                  value={state.mode}
                  onChange={(value) => setMode(value as CodecMode)}
                />
              </div>
            </div>

            {operation.options?.length ? (
              <div
                style={{
                  border: '1px solid #f0f0f0',
                  borderRadius: 16,
                  background: '#fff',
                  padding: 16,
                  display: 'grid',
                  gap: 14,
                }}
              >
                <div style={{ display: 'grid', gap: 4 }}>
                  <Typography.Text strong>参数配置</Typography.Text>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    参数会实时参与当前操作计算，适合快速试错和切换组合。
                  </Typography.Text>
                </div>
                <Divider style={{ margin: 0 }} />
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                    gap: 14,
                  }}
                >
                  {operation.options.map((option) => (
                    <div
                      key={option.key}
                      style={{
                        display: 'grid',
                        gap: 8,
                        padding: 12,
                        borderRadius: 12,
                        background: '#fafafa',
                        border: '1px solid #f0f0f0',
                      }}
                    >
                      <Typography.Text>{option.label}</Typography.Text>
                      {option.type === 'select' ? (
                        <Select
                          value={state.options[option.key]}
                          options={(option.options || []).map((value) => ({
                            label: value,
                            value,
                          }))}
                          onChange={(value) => setOption(option.key, value)}
                        />
                      ) : (
                        <Input
                          value={state.options[option.key]}
                          placeholder={option.placeholder}
                          onChange={(event) =>
                            setOption(option.key, event.target.value)
                          }
                        />
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            <div
              style={{
                display: 'grid',
                gridTemplateRows: 'minmax(0, 1fr) minmax(0, 1fr)',
                gap: 16,
                minHeight: 0,
              }}
            >
              <div
                style={{
                  border: '1px solid #f0f0f0',
                  borderRadius: 16,
                  background: '#fff',
                  overflow: 'hidden',
                  minWidth: 0,
                  display: 'grid',
                  gridTemplateRows: 'auto minmax(0, 1fr)',
                }}
              >
                <div
                  style={{
                    padding: '12px 14px',
                    borderBottom: '1px solid #f0f0f0',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 8,
                  }}
                >
                  <Typography.Text strong>输入</Typography.Text>
                  <Button
                    type="text"
                    icon={<DeleteOutlined />}
                    onClick={() => setInput('')}
                  />
                </div>
                <Input.TextArea
                  value={state.input}
                  onChange={(event) => setInput(event.target.value)}
                  placeholder="输入待处理内容"
                  autoSize={false}
                  style={{
                    height: '100%',
                    minHeight: 220,
                    border: 'none',
                    borderRadius: 0,
                    resize: 'none',
                    fontFamily:
                      'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                  }}
                />
              </div>

              <div
                style={{
                  border: '1px solid #f0f0f0',
                  borderRadius: 16,
                  background: '#fff',
                  overflow: 'hidden',
                  minWidth: 0,
                  display: 'grid',
                  gridTemplateRows: 'auto minmax(0, 1fr)',
                }}
              >
                <div
                  style={{
                    padding: '12px 14px',
                    borderBottom: '1px solid #f0f0f0',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 8,
                  }}
                >
                  <Typography.Text strong>输出</Typography.Text>
                  <Button
                    type="text"
                    icon={<RightOutlined />}
                    onClick={() => setInput(output)}
                    disabled={!output}
                  />
                </div>
                <Input.TextArea
                  value={output}
                  readOnly
                  placeholder="结果会实时显示在这里"
                  autoSize={false}
                  style={{
                    height: '100%',
                    minHeight: 220,
                    border: 'none',
                    borderRadius: 0,
                    resize: 'none',
                    background: '#fcfcfc',
                    fontFamily:
                      'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                  }}
                />
              </div>
            </div>
          </div>
        </div>
      </Drawer>
    </CodecWorkbenchContext.Provider>
  );
}

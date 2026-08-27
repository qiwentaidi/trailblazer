import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';

import ProtocolAnalysisPanel from './ProtocolAnalysisPanel';

jest.mock('@/services/tasks', () => ({
  __esModule: true,
  explainProtocolTraceStream: jest.fn(),
}));

const { explainProtocolTraceStream } = jest.requireMock('@/services/tasks') as {
  explainProtocolTraceStream: jest.Mock;
};

const buildTrace = () => ({
  trace_id: 'trace-1',
  transport: 'http',
  method: 'POST',
  request_url: 'https://example.com/api/protocol',
  algorithms: ['aes', 'rsa'],
  request_steps: [
    {
      source: 'JSON.stringify',
      algorithm: 'json.stringify',
      input_preview: '{"query":"demo"}',
      output_preview: '{"query":"demo"}',
      stack: 'at buildPayload (https://example.com/app.js:10:20)',
      captured_at_ms: 100,
    },
    {
      source: 'crypto.encrypt',
      algorithm: 'aes-cbc',
      input_preview: '{"query":"demo"}',
      output_preview: 'BBBBBBBBBBBBBBBBBBBBBBBB',
      stack: 'at encryptPayload (https://example.com/app.js:20:30)',
      captured_at_ms: 200,
    },
  ],
  response_steps: [
    {
      source: 'crypto.decrypt',
      algorithm: 'aes-cbc',
      input_preview: 'cipher-response',
      output_preview: '{"code":200}',
      stack: 'at decryptResponse (https://example.com/app.js:40:50)',
      captured_at_ms: 300,
    },
  ],
  session_materials: {
    token:
      'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
    latest_response_ciphertext: 'cipher-response',
    latest_response_plaintext: '{"code":200}',
  },
  stack: `at decryptPayload (https://example.com/app.js:12:34)
at handleResponse (https://example.com/app.js:56:78)`,
  request_before_transform: '{"query":"demo"}',
  final_request_body:
    'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
});

describe('ProtocolAnalysisPanel', () => {
  beforeAll(() => {
    class ResizeObserverMock {
      observe() {}

      unobserve() {}

      disconnect() {}
    }

    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: jest.fn().mockImplementation((query) => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      })),
    });

    Object.defineProperty(window, 'ResizeObserver', {
      writable: true,
      configurable: true,
      value: ResizeObserverMock,
    });

    Object.defineProperty(globalThis, 'ResizeObserver', {
      writable: true,
      configurable: true,
      value: ResizeObserverMock,
    });
  });

  test('renders highlighted payload cards with wrapping-safe styles', () => {
    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[
          buildTrace(),
          {
            ...buildTrace(),
            trace_id: 'trace-2',
            request_url: 'https://example.com/api/protocol/second',
            algorithms: ['aes', 'rsa'],
          },
        ]}
        staticAnalysis={null}
      />,
    );

    expect(screen.getByText('aes + rsa')).toBeInTheDocument();
    expect(screen.getAllByText('aes + rsa')).toHaveLength(1);
    expect(
      screen.getByText((content) => content.includes('2 个接口轨迹')),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /aes \+ rsa/i }));
    fireEvent.click(screen.getAllByText('查看详情')[0]);

    expect(screen.getByRole('dialog')).toBeInTheDocument();

    const beforeBody = screen
      .getByText('加密前请求数据')
      .closest('.ant-card')
      ?.querySelector('pre');
    const finalBody = screen
      .getByText('最终请求包')
      .closest('.ant-card')
      ?.querySelector('pre');

    expect(beforeBody).toHaveStyle({
      whiteSpace: 'pre-wrap',
      wordBreak: 'break-word',
      overflowWrap: 'anywhere',
      maxWidth: '100%',
      minWidth: '0',
    });
    expect(finalBody).toHaveStyle({
      whiteSpace: 'pre-wrap',
      wordBreak: 'break-word',
      overflowWrap: 'anywhere',
      maxWidth: '100%',
      minWidth: '0',
    });
  });

  test('shows all protocol traces without filter controls', () => {
    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[
          buildTrace(),
          {
            ...buildTrace(),
            trace_id: 'trace-plain',
            request_url: 'https://example.com/api/plain',
            algorithms: ['json.parse'],
            response_steps: [
              {
                source: 'JSON.stringify',
                algorithm: 'json.stringify',
                input_preview: '{"code":0}',
                output_preview: '{"code":0}',
                captured_at_ms: 100,
              },
            ],
            session_materials: {
              latest_response_plaintext: '{"code":0}',
            },
          },
        ]}
        staticAnalysis={null}
      />,
    );

    expect(screen.getByText('aes + rsa')).toBeInTheDocument();
    expect(screen.getByText('json.parse')).toBeInTheDocument();
    expect(screen.queryByText(/已默认隐藏 1 条/)).not.toBeInTheDocument();
    expect(
      screen.queryByRole('combobox', { name: /轨迹|筛选|加解密/i }),
    ).not.toBeInTheDocument();
    expect(screen.getByText('共 2 条')).toBeInTheDocument();
  });

  test('renders session materials with wrapping-safe styles', () => {
    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[buildTrace()]}
        staticAnalysis={null}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /aes \+ rsa/i }));
    fireEvent.click(screen.getByText('查看详情'));

    expect(screen.getByRole('dialog')).toBeInTheDocument();

    const sessionMaterial = screen.getByText(/token:/i).closest('div');

    expect(sessionMaterial).toHaveStyle({
      maxWidth: '100%',
      minWidth: '0',
      wordBreak: 'break-word',
      overflowWrap: 'anywhere',
      whiteSpace: 'normal',
    });

    const sessionMaterialsContainer = screen.getByTestId(
      'protocol-session-materials',
    );

    expect(sessionMaterialsContainer).toHaveStyle({
      maxHeight: '320px',
      overflowY: 'auto',
      overflowX: 'hidden',
    });
  });

  test('renders grouped traces in a paginated table without stack fingerprint column', () => {
    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={Array.from({ length: 6 }, (_, index) => ({
          ...buildTrace(),
          trace_id: `trace-${index + 1}`,
          request_url: `https://example.com/api/protocol/${index + 1}`,
        }))}
        staticAnalysis={null}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /aes \+ rsa/i }));

    const protocolTable = document.querySelector('.ant-table table');

    expect(screen.getAllByText('aes + rsa')).toHaveLength(1);
    expect(protocolTable).not.toBeNull();
    expect(
      within(protocolTable as HTMLElement).getByRole('columnheader', {
        name: '请求地址',
      }),
    ).toBeInTheDocument();
    expect(
      within(protocolTable as HTMLElement).queryByRole('columnheader', {
        name: '调用栈指纹',
      }),
    ).not.toBeInTheDocument();
    expect(screen.getAllByText('查看详情')).toHaveLength(5);
    expect(document.querySelector('.ant-pagination')).toHaveTextContent('2');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    fireEvent.click(screen.getAllByText('查看详情')[0]);

    const dialog = screen.getByRole('dialog');

    expect(dialog).toBeInTheDocument();
    expect(within(dialog).getByText('轨迹 ID')).toBeInTheDocument();
  });

  test('renders long request urls in wrapping-safe cells without expanding the table', () => {
    const longRequestUrl =
      'https://example.com/api/protocol/very/long/path/that/keeps/going?token=' +
      'A'.repeat(240) +
      '&payload=' +
      'B'.repeat(240);

    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[
          {
            ...buildTrace(),
            request_url: longRequestUrl,
            page_url: `${longRequestUrl}#/page`,
          },
        ]}
        staticAnalysis={null}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /aes \+ rsa/i }));

    const requestUrlCandidates = screen.getAllByText(longRequestUrl);
    const pageUrlCandidates = screen.getAllByText(`${longRequestUrl}#/page`);
    const requestUrl = requestUrlCandidates[0];
    const pageUrl = pageUrlCandidates[0];
    const table = document.querySelector('.ant-table table');

    expect(requestUrl).toHaveStyle({
      display: 'block',
      maxWidth: '100%',
      minWidth: '0',
      whiteSpace: 'normal',
      wordBreak: 'break-word',
      overflowWrap: 'anywhere',
    });
    expect(pageUrl).toHaveStyle({
      display: 'block',
      maxWidth: '100%',
      minWidth: '0',
      whiteSpace: 'normal',
      wordBreak: 'break-word',
      overflowWrap: 'anywhere',
    });
    expect(table).toHaveStyle({
      tableLayout: 'fixed',
    });
  });

  test('promotes primary trace-backed endpoint into the profile main view', async () => {
    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[]}
        staticAnalysis={{
          task_id: 'task-1',
          js_count: 1,
          profiles: [
            {
              id: 'sm4-sm2-md5-envelope',
              name: 'SM4/SM2/MD5 网络封装',
              request_pipeline: ['JSON.stringify(body)', 'SM4 加密'],
              response_pipeline: ['SM4 解密', 'JSON.parse'],
              primary_endpoint: {
                path: '/api/apiUser/getInfo',
                method: 'POST',
                trace_id: 'trace-1',
                request_url: 'https://example.com/api/apiUser/getInfo',
                request_before_transform: '{"query":"demo"}',
                final_request_body:
                  'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
                request_steps: buildTrace().request_steps,
                response_steps: buildTrace().response_steps,
                session_materials: buildTrace().session_materials,
                algorithms: ['aes-cbc'],
                source_file: 'protocol-trace',
                snippet: 'https://example.com/api/apiUser/getInfo',
              },
              endpoints: [],
            },
          ],
        }}
      />,
    );

    fireEvent.click(
      screen.getByRole('button', { name: /SM4\/SM2\/MD5 网络封装/i }),
    );

    expect(screen.getByText('主命中轨迹')).toBeInTheDocument();
    expect(screen.getByText('主链请求甬道')).toBeInTheDocument();
    expect(screen.getByText('主链响应甬道')).toBeInTheDocument();
    expect(screen.getByText('主链请求链路流程')).toBeInTheDocument();
    expect(screen.getByText('主链响应链路流程')).toBeInTheDocument();
    expect(screen.getByText('静态请求流水线')).toBeInTheDocument();
    expect(screen.getByText('静态响应流水线')).toBeInTheDocument();
  });

  test('renders aggregated endpoint client labels and payload metadata', () => {
    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[]}
        staticAnalysis={{
          task_id: 'task-1',
          js_count: 1,
          profiles: [
            {
              id: 'request-context-analysis',
              name: '请求上下文分析',
              endpoints: [
                {
                  path: '/stat/queryTop10ScriptsAuthorInfo',
                  method: 'GET',
                  client: 'wrapper:So -> rn | rn',
                  request_payload_carrier: 'body',
                  request_payload_format: 'json',
                  request_payload_preview: '{}',
                  source_file: 'https://example.com/main.js',
                  snippet: 'rn({type:"get",url:"/stat/queryTop10ScriptsAuthorInfo",body:{}})',
                },
              ],
            },
          ],
        }}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /请求上下文分析/i }));
    fireEvent.click(screen.getByText('/stat/queryTop10ScriptsAuthorInfo'));

    expect(screen.getByText('wrapper:So -> rn | rn')).toBeInTheDocument();
    expect(screen.getByText('body')).toBeInTheDocument();
    expect(screen.getByText('json')).toBeInTheDocument();
    expect(screen.getAllByText('{}').length).toBeGreaterThan(0);
  });

  test('renders complete request and response protocol lanes in the detail drawer', () => {
    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[buildTrace()]}
        staticAnalysis={null}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /aes \+ rsa/i }));
    fireEvent.click(screen.getByText('查看详情'));

    expect(screen.getByText('链路总结')).toBeInTheDocument();
    expect(screen.getByText('请求链路流程')).toBeInTheDocument();
    expect(screen.getByText('响应链路流程')).toBeInTheDocument();
    expect(screen.queryByText('请求链路说明')).not.toBeInTheDocument();
    expect(screen.queryByText('响应链路说明')).not.toBeInTheDocument();
    expect(screen.getByText('请求甬道')).toBeInTheDocument();
    expect(screen.getByText('响应甬道')).toBeInTheDocument();
    expect(screen.getByText('加密前请求数据')).toBeInTheDocument();
    expect(screen.getByText('最终请求包')).toBeInTheDocument();
    expect(screen.getByText('原始响应包')).toBeInTheDocument();
    expect(screen.getByText('响应解密结果')).toBeInTheDocument();

    const requestLaneCard = screen.getByText('请求甬道').closest('.ant-card');
    const responseLaneCard = screen.getByText('响应甬道').closest('.ant-card');

    expect(requestLaneCard).toHaveTextContent('加密前请求数据');
    expect(requestLaneCard).toHaveTextContent('最终请求包');
    expect(requestLaneCard).not.toHaveTextContent('原始响应包');
    expect(requestLaneCard).not.toHaveTextContent('响应解密结果');
    expect(responseLaneCard).toHaveTextContent('原始响应包');
    expect(responseLaneCard).toHaveTextContent('响应解密结果');
    expect(responseLaneCard).not.toHaveTextContent('加密前请求数据');
    expect(responseLaneCard).not.toHaveTextContent('最终请求包');
    expect(screen.getAllByText('{"query":"demo"}').length).toBeGreaterThan(0);
    expect(
      screen.getByText(
        'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      ),
    ).toBeInTheDocument();
    expect(screen.getAllByText('cipher-response').length).toBeGreaterThan(0);
    expect(screen.getAllByText('{"code":200}').length).toBeGreaterThan(0);
    expect(screen.getByText('捕获到的响应明文')).toBeInTheDocument();
    expect(screen.getAllByText('crypto.decrypt').length).toBeGreaterThan(0);
    expect(screen.queryByText('变换前请求体')).not.toBeInTheDocument();
    expect(screen.queryByText('最终请求体')).not.toBeInTheDocument();
    expect(screen.queryByText('输入预览')).not.toBeInTheDocument();
    expect(screen.queryByText('输出预览')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /crypto\.decrypt/i }));

    expect(screen.getAllByText('输入预览').length).toBeGreaterThan(0);
    expect(screen.getAllByText('输出预览').length).toBeGreaterThan(0);
    expect(screen.queryByText('模块 ID')).not.toBeInTheDocument();
    expect(screen.queryByText('调用 ID')).not.toBeInTheDocument();
    expect(screen.queryByText('父调用 ID')).not.toBeInTheDocument();
    expect(screen.queryByText('轨迹调用栈')).not.toBeInTheDocument();
    expect(screen.queryByText('步骤调用栈')).not.toBeInTheDocument();
    expect(screen.queryByText(/decryptPayload/)).not.toBeInTheDocument();
  });

  test('renders captured flow instead of fixed narrative templates', () => {
    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[
          {
            ...buildTrace(),
            algorithms: ['sm4.encrypt', 'sm4.decrypt'],
            request_before_transform: '{}',
            final_request_body: 'cfae1bdeaf9dc42005488a8ab41d3c4b',
            request_headers: {
              gv59jppeesnw: 'AHc5bsRm',
              kqn29pkxstkn: '1776137632717',
              bpzhepzrvcjy: 'ec834bbbb8520d1f1473bf17023d0e13',
              '6zzbinypyphq': '689a4dc4',
            },
            request_steps: [
              {
                source: 'module.se',
                algorithm: 'sm4.encrypt',
                input_preview: '{}',
                output_preview: 'cfae1bdeaf9dc42005488a8ab41d3c4b',
                captured_at_ms: 200,
              },
            ],
            response_steps: [
              {
                source: 'module.sd',
                algorithm: 'sm4.decrypt',
                input_preview: '"3e6f3315"',
                output_preview: '{"code":0}',
                captured_at_ms: 300,
              },
            ],
            session_materials: {
              session_seed_b: '0048183029130089',
              sm4_key_hex: '30303438313833303239313330303839',
              nonce: 'AHc5bsRm',
              timestamp: '1776137632717',
              signature: 'ec834bbbb8520d1f1473bf17023d0e13',
              key_exchange_header: '689a4dc4',
              key_exchange_public_key: '04CE9E4A',
              latest_response_ciphertext: '"3e6f3315"',
              latest_response_plaintext: '{"code":0}',
            },
          },
        ]}
        staticAnalysis={null}
      />,
    );

    fireEvent.click(
      screen.getByRole('button', {
        name: /sm4\.decrypt \+ sm4\.encrypt|sm4\.encrypt \+ sm4\.decrypt/i,
      }),
    );
    fireEvent.click(screen.getByText('查看详情'));

    expect(screen.getByText('原始请求明文')).toBeInTheDocument();
    expect(screen.getByText('SM4 密钥')).toBeInTheDocument();
    expect(screen.getByText('Nonce / IV')).toBeInTheDocument();
    expect(screen.getByText('请求头组装')).toBeInTheDocument();
    expect(screen.getByText('module.se')).toBeInTheDocument();
    expect(screen.getByText('最终发包请求体')).toBeInTheDocument();
    expect(screen.getByText('原始响应密文')).toBeInTheDocument();
    expect(screen.getByText('module.sd')).toBeInTheDocument();
    expect(screen.getAllByText('响应明文').length).toBeGreaterThan(0);
    expect(screen.queryByText(/生成会话种子/)).not.toBeInTheDocument();
    expect(
      screen.queryByText(/双层 Base64 包装会话 key/),
    ).not.toBeInTheDocument();
  });

  test('filters out unrelated preview steps that do not connect to the final payload chain', () => {
    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[
          {
            ...buildTrace(),
            algorithms: ['sm4'],
            request_steps: [
              {
                source: 'JSON.stringify',
                algorithm: 'json.stringify',
                input_preview: '{}',
                output_preview: '{}',
                captured_at_ms: 100,
              },
              {
                source: 'window.atob',
                algorithm: 'base64.decode',
                input_preview: 'Zm9v',
                output_preview: 'foo',
                captured_at_ms: 200,
              },
              {
                source: 'crypto.encrypt',
                algorithm: 'sm4',
                input_preview: '{}',
                output_preview: '29859a5debb3301935f5cd4a4604adcc',
                captured_at_ms: 300,
              },
            ],
            response_steps: [
              {
                source: 'window.btoa',
                algorithm: 'base64.encode',
                input_preview: 'bar',
                output_preview: 'YmFy',
                captured_at_ms: 100,
              },
              {
                source: 'crypto.decrypt',
                algorithm: 'sm4',
                input_preview:
                  'd230684a10c5b7f46b7fed6e674cbf3ab0b2a00b3e5b3d48dcc1929fa00cefbf7940144e010f33367',
                output_preview:
                  '{"code":"err.common.system.error","msg":"系统错误","success":false}',
                captured_at_ms: 200,
              },
            ],
            request_before_transform: '{}',
            final_request_body: '29859a5debb3301935f5cd4a4604adcc',
            session_materials: {
              latest_response_ciphertext:
                'd230684a10c5b7f46b7fed6e674cbf3ab0b2a00b3e5b3d48dcc1929fa00cefbf7940144e010f33367',
              latest_response_plaintext:
                '{"code":"err.common.system.error","msg":"系统错误","success":false}',
            },
          },
        ]}
        staticAnalysis={null}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /sm4/i }));
    fireEvent.click(screen.getByText('查看详情'));

    expect(screen.getAllByText('JSON.stringify').length).toBeGreaterThan(0);
    expect(screen.getAllByText('crypto.decrypt').length).toBeGreaterThan(0);
    expect(screen.queryByText('window.atob')).not.toBeInTheDocument();
    expect(screen.queryByText('window.btoa')).not.toBeInTheDocument();
  });

  test('does not present stringify-only response previews as a decrypt chain', () => {
    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[
          {
            ...buildTrace(),
            algorithms: ['hex-encoded-payload', 'json.parse'],
            response_steps: [
              {
                source: 'JSON.stringify',
                algorithm: 'json.stringify',
                input_preview:
                  '{"code":"err.common.system.error","msg":"系统错误","success":false}',
                output_preview:
                  '{"code":"err.common.system.error","msg":"系统错误","success":false}',
                captured_at_ms: 100,
              },
            ],
            session_materials: {
              latest_response_ciphertext:
                '"0bb4ec27512bb4975e55c9502ae3a599835fd4c3b6c0be5f43c6b7633096ac64110987dfc4744f3d230684a10c5b7f46b7fed6e674cbf3ab0b2a00b3e5b3d48dcc1929fa00cefbf7940144e010f33367"',
              latest_response_plaintext:
                '{"code":"err.common.system.error","msg":"系统错误","success":false}',
            },
          },
        ]}
        staticAnalysis={null}
      />,
    );

    fireEvent.click(
      screen.getByRole('button', { name: /hex-encoded-payload/i }),
    );
    fireEvent.click(screen.getByText('查看详情'));

    expect(
      screen.getByText('捕获到的响应明文（未关联到可验证解密步骤）'),
    ).toBeInTheDocument();
    expect(screen.queryByText('JSON.stringify')).not.toBeInTheDocument();
    expect(screen.getAllByText('原始响应密文').length).toBeGreaterThan(0);
    expect(screen.getAllByText('响应明文').length).toBeGreaterThan(0);
  });

  test('uses a stable drawer title instead of the request url', () => {
    const longRequestUrl =
      'https://example.com/api/protocol/very/long/path/that/keeps/going?token=' +
      'A'.repeat(240);

    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[
          {
            ...buildTrace(),
            request_url: longRequestUrl,
          },
        ]}
        staticAnalysis={null}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /aes \+ rsa/i }));
    fireEvent.click(screen.getByText('查看详情'));

    expect(screen.getByRole('dialog')).toBeInTheDocument();
    const drawerHeader = document.querySelector('.ant-drawer-header');

    expect(screen.getByText('协议轨迹详情')).toBeInTheDocument();
    expect(drawerHeader).toHaveTextContent('协议轨迹详情');
    expect(drawerHeader).not.toHaveTextContent(longRequestUrl);
  });

  test('does not render the manual decrypt workbench', () => {
    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[buildTrace()]}
        staticAnalysis={null}
      />,
    );

    expect(screen.queryByText('手动解密试验台')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: '尝试离线解密' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: '尝试 runtime 解密' }),
    ).not.toBeInTheDocument();
  });

  test('generates AI explanation for the selected protocol trace', async () => {
    explainProtocolTraceStream.mockImplementation(
      async (
        _taskId: string,
        _payload: { traceId: string },
        options?: {
          onEvent?: (event: {
            type: 'delta' | 'done';
            delta?: string;
            explanation?: string;
            model?: string;
          }) => void;
        },
      ) => {
        options?.onEvent?.({
          type: 'delta',
          delta:
            '## 请求甬道\n\n1. 明文准备：**已确认** 请求明文先进入 `module.se`。\n\n',
        });
        options?.onEvent?.({
          type: 'delta',
          delta:
            '## 响应甬道\n\n1. **密钥交换**\n**推断** `6zzbinypyphq` 用于种子交换。',
        });
        options?.onEvent?.({
          type: 'done',
          explanation:
            '## 请求甬道\n\n1. 明文准备：**已确认** 请求明文先进入 `module.se`。\n\n## 响应甬道\n\n1. **密钥交换**\n**推断** `6zzbinypyphq` 用于种子交换。',
          model: 'qwen-plus',
        });

        return {
          traceId: 'trace-1',
          explanation:
            '## 请求甬道\n\n1. 明文准备：**已确认** 请求明文先进入 `module.se`。\n\n## 响应甬道\n\n1. **密钥交换**\n**推断** `6zzbinypyphq` 用于种子交换。',
          model: 'qwen-plus',
        };
      },
    );

    render(
      <ProtocolAnalysisPanel
        taskId="task-1"
        traces={[buildTrace()]}
        staticAnalysis={null}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /aes \+ rsa/i }));
    fireEvent.click(screen.getByText('查看详情'));
    fireEvent.click(screen.getByRole('button', { name: '生成 AI 解释' }));

    await waitFor(() => {
      expect(explainProtocolTraceStream).toHaveBeenCalledWith(
        'task-1',
        { traceId: 'trace-1' },
        expect.objectContaining({
          version: undefined,
          signal: expect.any(Object),
          onEvent: expect.any(Function),
        }),
      );
    });

    expect(await screen.findByText(/当前模型：qwen-plus/)).toBeInTheDocument();
    expect(screen.getByText('请求甬道 AI 解释')).toBeInTheDocument();
    expect(screen.getByText('响应甬道 AI 解释')).toBeInTheDocument();
    expect(screen.getByText('1. 明文准备')).toBeInTheDocument();
    expect(screen.getByText('1. 密钥交换')).toBeInTheDocument();
    expect(screen.getByText('已确认')).toBeInTheDocument();
    expect(screen.getByText('module.se')).toBeInTheDocument();
    expect(screen.getByText('6zzbinypyphq')).toBeInTheDocument();
  });
});

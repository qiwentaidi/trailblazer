import { fireEvent, render, screen, waitFor } from '@testing-library/react';

import { CodecWorkbenchProvider, useCodecWorkbench } from '@/components/codec';
import RiskWorkbench, { filterRisks } from './RiskWorkbench';

jest.mock('@/services/tasks', () => ({
  __esModule: true,
  deleteTaskRisk: jest.fn(),
  deleteTaskRiskCluster: jest.fn(),
  decryptRiskResponse: jest.fn(),
  runtimeDecryptRiskResponse: jest.fn(),
}));

jest.mock('@/components/codec', () => {
  const actual = jest.requireActual('@/components/codec');
  return {
    ...actual,
    useCodecWorkbench: jest.fn(),
  };
});

const {
  decryptRiskResponse,
  runtimeDecryptRiskResponse,
} = jest.requireMock(
  '@/services/tasks',
) as {
  decryptRiskResponse: jest.Mock;
  runtimeDecryptRiskResponse: jest.Mock;
};
const mockedUseCodecWorkbench = useCodecWorkbench as jest.Mock;
const openCodecWorkbench = jest.fn();

const buildRisk = (index: number) => ({
  id: `risk-${index}`,
  title: `风险 ${index}`,
  level: index % 2 === 0 ? 'high' : 'medium',
  confidence: 'medium',
  type: 'sqli',
  url: `https://example.com/api/${index}`,
  description: `描述 ${index}`,
  confidenceReason: `置信说明 ${index}`,
  createdAt: '2026-04-13 12:00:00',
});

describe('RiskWorkbench', () => {
  beforeAll(() => {
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

    if (!global.MessageChannel) {
      class MockMessagePort {
        onmessage: ((event: { data: unknown }) => void) | null = null;

        postMessage = (data?: unknown) => {
          setTimeout(() => {
            this.onmessage?.({ data });
          }, 0);
        };

        start = jest.fn();
        close = jest.fn();
      }

      class MockMessageChannel {
        port1 = new MockMessagePort();
        port2 = new MockMessagePort();
      }

      Object.defineProperty(global, 'MessageChannel', {
        writable: true,
        value: MockMessageChannel,
      });
      Object.defineProperty(window, 'MessageChannel', {
        writable: true,
        value: MockMessageChannel,
      });
    }
  });

  beforeEach(() => {
    jest.clearAllMocks();
    mockedUseCodecWorkbench.mockReturnValue({
      openCodecWorkbench,
      closeCodecWorkbench: jest.fn(),
    });
  });

  test('shows only the first page of risks by default', () => {
    const risks = Array.from({ length: 11 }, (_, index) =>
      buildRisk(index + 1),
    );

    render(
      <CodecWorkbenchProvider>
        <RiskWorkbench taskId="task-1" risks={risks} />
      </CodecWorkbenchProvider>,
    );

    expect(screen.getByText('风险 1')).toBeInTheDocument();
    expect(screen.getByText('风险 10')).toBeInTheDocument();
    expect(screen.queryByText('风险 11')).not.toBeInTheDocument();
    expect(screen.getByText('共 11 条风险')).toBeInTheDocument();
    expect(screen.getAllByText('中置信').length).toBeGreaterThan(0);
  });

  test('sorts risks by level descending by default', async () => {
    const { container } = render(
      <CodecWorkbenchProvider>
        <RiskWorkbench
          taskId="task-1"
          risks={[
            {
              ...buildRisk(1),
              title: '信息风险',
              level: 'info',
            },
            {
              ...buildRisk(2),
              title: '高危风险',
              level: 'high',
            },
            {
              ...buildRisk(3),
              title: '低危风险',
              level: 'low',
            },
          ]}
        />
      </CodecWorkbenchProvider>,
    );

    await waitFor(() => {
      const titles = Array.from(
        container.querySelectorAll('.ant-list-item .ant-list-item-meta-title strong'),
      ).map((node) => node.textContent?.trim());
      expect(titles.slice(0, 3)).toEqual(['高危风险', '低危风险', '信息风险']);
    });
  });

  test('shows confidence in the risk drawer', async () => {
    const { container } = render(
      <CodecWorkbenchProvider>
        <RiskWorkbench
          taskId="task-1"
          initialSortMode="level_desc"
          risks={[
            {
              ...buildRisk(1),
              title: '未授权访问',
              confidence: 'low',
              confidenceReason: '相同响应特征已重复出现 8 次',
            },
          ]}
        />
      </CodecWorkbenchProvider>,
    );

    fireEvent.click(screen.getByRole('button', { name: '查看详情' }));

    expect(await screen.findByText(/置信度: 低置信/)).toBeInTheDocument();
    expect(
      screen.getByText(/置信度说明: 相同响应特征已重复出现 8 次/),
    ).toBeInTheDocument();
  });

  test('renders sourceMap locations with structured file metadata', async () => {
    render(
      <CodecWorkbenchProvider>
        <RiskWorkbench
          taskId="task-1"
          risks={[
            {
              ...buildRisk(1),
              title: '敏感关键词泄露',
              type: '敏感信息泄露',
              method: '',
              url: 'sourceMap/https_pcem.caocaoglobal.com/src/infrastructure/interceptor.js',
              confidenceReason:
                '发现敏感关键词泄露: very-long-token-value-that-should-not-dominate-the-row',
            },
          ]}
        />
      </CodecWorkbenchProvider>,
    );

    expect(screen.getByText('SourceMap')).toBeInTheDocument();
    expect(screen.getByText('interceptor.js')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '查看详情' }));

    expect(await screen.findByText('来源定位:')).toBeInTheDocument();
    expect(
      screen.getByText(
        /完整路径: sourceMap\/https_pcem\.caocaoglobal\.com\/src\/infrastructure\/interceptor\.js/,
      ),
    ).toBeInTheDocument();
  });

  test('collapses deny-template risks into a cluster row', async () => {
    const { container } = render(
      <CodecWorkbenchProvider>
        <RiskWorkbench
          taskId="task-1"
          risks={[
            {
              ...buildRisk(1),
              title: '未授权访问',
              type: '未授权访问',
              confidence: 'low',
              confidenceReason: '疑似统一认证拒绝模板，当前模板命中 3 个接口',
              denyTemplateId: 'cluster-auth-1',
              denyTemplateKind: 'auth_required',
              denyTemplateLabel: '疑似统一认证拒绝模板',
              denyTemplateCount: 3,
              url: 'https://example.com/api/a',
            },
            {
              ...buildRisk(2),
              title: '未授权访问',
              type: '未授权访问',
              confidence: 'low',
              denyTemplateId: 'cluster-auth-1',
              denyTemplateKind: 'auth_required',
              denyTemplateLabel: '疑似统一认证拒绝模板',
              denyTemplateCount: 3,
              url: 'https://example.com/api/b',
            },
            {
              ...buildRisk(3),
              title: '未授权访问',
              type: '未授权访问',
              confidence: 'low',
              denyTemplateId: 'cluster-auth-1',
              denyTemplateKind: 'auth_required',
              denyTemplateLabel: '疑似统一认证拒绝模板',
              denyTemplateCount: 3,
              url: 'https://example.com/api/c',
            },
          ]}
        />
      </CodecWorkbenchProvider>,
    );

    expect(screen.getByText('认证拒绝簇')).toBeInTheDocument();
    expect(
      screen.getAllByText(/当前模板命中 3 个接口/).length,
    ).toBeGreaterThan(0);
    expect(
      screen.queryByText('https://example.com/api/b'),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '展开接口' }));

    await waitFor(() => {
      expect(screen.getByText(/https:\/\/example\.com\/api\/b/)).toBeInTheDocument();
    });
    expect(screen.getAllByText('查看详情').length).toBeGreaterThan(0);
  });

  test('paginates expanded deny-template cluster items', async () => {
    const risks = Array.from({ length: 25 }, (_, index) => ({
      ...buildRisk(index + 1),
      title: '未授权访问',
      type: '未授权访问',
      confidence: 'low',
      denyTemplateId: 'cluster-auth-2',
      denyTemplateKind: 'auth_required',
      denyTemplateLabel: '疑似统一认证拒绝模板',
      denyTemplateCount: 25,
      url: `https://example.com/api/page-${index + 1}`,
    }));

    render(
      <CodecWorkbenchProvider>
        <RiskWorkbench taskId="task-1" risks={risks} />
      </CodecWorkbenchProvider>,
    );

    fireEvent.click(screen.getByRole('button', { name: '展开接口' }));

    expect(await screen.findByText(/当前显示第 1 页，每页 20 条/)).toBeInTheDocument();
    expect(screen.getByText(/https:\/\/example\.com\/api\/page-20/)).toBeInTheDocument();
    expect(
      screen.queryByText(/https:\/\/example\.com\/api\/page-21/),
    ).not.toBeInTheDocument();
  });

  test('filters risks by deny-template cluster label', () => {
    const risks = [
      {
        ...buildRisk(1),
        title: '模板簇 A 风险',
        denyTemplateId: 'cluster-a',
        denyTemplateLabel: '统一登录拒绝模板',
        denyTemplateCount: 1,
      },
      {
        ...buildRisk(2),
        title: '模板簇 B 风险',
        denyTemplateId: 'cluster-b',
        denyTemplateLabel: '网关拒绝模板',
        denyTemplateCount: 1,
      },
      {
        ...buildRisk(3),
        title: '普通风险',
      },
    ];

    expect(
      filterRisks({
        risks: risks as any,
        keyword: '',
        clusterFilter: '统一登录拒绝模板',
      }).map((risk) => risk.title),
    ).toEqual(['模板簇 A 风险']);
  });

  test('filters unclustered risks with the none cluster option', () => {
    const risks = [
      {
        ...buildRisk(1),
        title: '模板簇风险',
        denyTemplateId: 'cluster-a',
        denyTemplateLabel: '统一登录拒绝模板',
        denyTemplateCount: 1,
      },
      {
        ...buildRisk(2),
        title: '未归类风险',
      },
    ];

    expect(
      filterRisks({
        risks: risks as any,
        keyword: '',
        clusterFilter: '__none__',
      }).map((risk) => risk.title),
    ).toEqual(['未归类风险']);
  });

  test('sorts risks by level descending', async () => {
    const { container } = render(
      <CodecWorkbenchProvider>
        <RiskWorkbench
          taskId="task-1"
          initialSortMode="level_desc"
          risks={[
            {
              ...buildRisk(1),
              title: '信息风险',
              level: 'info',
            },
            {
              ...buildRisk(2),
              title: '高危风险',
              level: 'high',
            },
            {
              ...buildRisk(3),
              title: '低危风险',
              level: 'low',
            },
          ]}
        />
      </CodecWorkbenchProvider>,
    );

    await waitFor(() => {
      const titles = Array.from(
        container.querySelectorAll('.ant-list-item .ant-list-item-meta-title strong'),
      ).map((node) => node.textContent?.trim());
      expect(titles.slice(0, 3)).toEqual(['高危风险', '低危风险', '信息风险']);
    });
  });

  test('sorts risks by response length descending', async () => {
    const { container } = render(
      <CodecWorkbenchProvider>
        <RiskWorkbench
          taskId="task-1"
          initialSortMode="response_length_desc"
          risks={[
            {
              ...buildRisk(1),
              title: '短响应',
              responseLength: 10,
            },
            {
              ...buildRisk(2),
              title: '长响应',
              responseLength: 200,
            },
            {
              ...buildRisk(3),
              title: '中响应',
              responseLength: 80,
            },
          ]}
        />
      </CodecWorkbenchProvider>,
    );

    await waitFor(() => {
      const titles = Array.from(
        container.querySelectorAll('.ant-list-item .ant-list-item-meta-title strong'),
      ).map((node) => node.textContent?.trim());
      expect(titles.slice(0, 3)).toEqual(['长响应', '中响应', '短响应']);
    });
  });

  test('deduplicates repeated response-length text in list summaries', () => {
    render(
      <CodecWorkbenchProvider>
        <RiskWorkbench
          taskId="task-1"
          risks={[
            {
              ...buildRisk(1),
              title: '未授权访问',
              type: '未授权访问',
              confidence: 'high',
              confidenceReason: '响应体很短，可利用信息有限',
              responseLength: 69,
              description:
                '发现未授权访问漏洞，风险等级: medium，置信度: high，响应长度: 69；置信度说明: 响应体很短，可利用信息有限',
            },
          ]}
        />
      </CodecWorkbenchProvider>,
    );

    expect(screen.getByText('响应体很短，可利用信息有限；响应长度: 69')).toBeInTheDocument();
    expect(screen.getAllByText(/响应长度: 69/)).toHaveLength(1);
  });

  test('decrypts ciphertext from a linked protocol trace in the risk drawer', async () => {
    decryptRiskResponse.mockResolvedValue({
      keyHex: '00112233',
      ciphertext: 'abcd1234',
      plaintext: '{"code":200}',
      mode: 'offline',
      source: 'sm4',
      detail: '通过历史材料完成解密',
      functionHint: 'module.sd',
    });

    render(
      <CodecWorkbenchProvider>
        <RiskWorkbench
          taskId="task-1"
          version={2}
          risks={[
            {
              ...buildRisk(1),
              title: '未授权访问',
              type: '未授权访问',
              traceId: 'trace-1',
              hasProtocolTrace: true,
              responseCiphertext: 'abcd1234',
              decryptionStatus: 'not_tried',
            },
          ]}
        />
      </CodecWorkbenchProvider>,
    );

    fireEvent.click(screen.getByRole('button', { name: '查看详情' }));
    fireEvent.click(screen.getByRole('button', { name: '尝试离线二次解密' }));

    await waitFor(() => {
      expect(decryptRiskResponse).toHaveBeenCalledWith(
        'task-1',
        {
          traceId: 'trace-1',
          ciphertext: 'abcd1234',
        },
        {
          version: 2,
        },
      );
    });

    expect(await screen.findByText('{"code":200}')).toBeInTheDocument();
    expect(screen.getByText(/使用密钥: 00112233/)).toBeInTheDocument();
    expect(screen.getByText(/解密模式: offline/)).toBeInTheDocument();
    expect(screen.getByText(/结果来源: sm4/)).toBeInTheDocument();
    expect(screen.getByText(/函数线索: module.sd/)).toBeInTheDocument();
  });

  test('runtime decrypts ciphertext from a linked protocol trace in the risk drawer', async () => {
    runtimeDecryptRiskResponse.mockResolvedValue({
      ciphertext: 'abcd1234',
      plaintext: '{"code":201}',
      mode: 'runtime',
      source: 'browser-context',
      detail: '通过浏览器上下文在线执行页面解密逻辑完成还原',
      functionHint: 'module.sd',
    });

    render(
      <CodecWorkbenchProvider>
        <RiskWorkbench
          taskId="task-1"
          version={2}
          risks={[
            {
              ...buildRisk(1),
              title: '未授权访问',
              type: '未授权访问',
              traceId: 'trace-1',
              hasProtocolTrace: true,
              responseCiphertext: 'abcd1234',
              decryptionStatus: 'not_tried',
            },
          ]}
        />
      </CodecWorkbenchProvider>,
    );

    fireEvent.click(screen.getByRole('button', { name: '查看详情' }));
    fireEvent.click(
      screen.getByRole('button', { name: '尝试在线 runtime 解密' }),
    );

    await waitFor(() => {
      expect(runtimeDecryptRiskResponse).toHaveBeenCalledWith(
        'task-1',
        {
          traceId: 'trace-1',
          ciphertext: 'abcd1234',
          requestUrl: 'https://example.com/api/1',
        },
        {
          version: 2,
        },
      );
    });

    expect(await screen.findByText('{"code":201}')).toBeInTheDocument();
    expect(screen.getByText(/解密模式: runtime/)).toBeInTheDocument();
    expect(screen.getByText(/结果来源: browser-context/)).toBeInTheDocument();
  });

  test('opens codec workbench with inferred sm4 materials from the selected risk', () => {
    render(
      <CodecWorkbenchProvider>
        <RiskWorkbench
          taskId="task-1"
          version={2}
          risks={[
            {
              ...buildRisk(1),
              title: '未授权访问',
              type: '未授权访问',
              traceId: 'trace-1',
              hasProtocolTrace: true,
              request: `POST /api/demo HTTP/1.1
Host: example.com
gv59JPPEesNW: T4e3NhfC

abcd1234`,
              responseCiphertext: '"5cb35ee620256..."',
              decryptionStatus: 'not_tried',
            },
          ]}
          protocolTraces={[
            {
              trace_id: 'trace-1',
              session_materials: {
                sm4_key_hex: '31393435323038373838333136383734',
              },
            } as any,
          ]}
        />
      </CodecWorkbenchProvider>,
    );

    fireEvent.click(screen.getByRole('button', { name: '查看详情' }));
    fireEvent.click(screen.getByRole('button', { name: '用解密工具打开' }));

    expect(openCodecWorkbench).toHaveBeenCalledWith({
      operationId: 'sm4',
      mode: 'decode',
      input: '5cb35ee620256...',
      replaceInput: true,
      options: {
        key: '31393435323038373838333136383734',
        keyFormat: 'Hex',
        iv: 'T4e3NhfC',
        ivFormat: 'UTF8',
        mode: 'CBC',
        inputFormat: 'Base64',
        outputFormat: 'Hex',
      },
    });
  });
});

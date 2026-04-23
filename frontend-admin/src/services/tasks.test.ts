import request from '@/utils/request';
import {
  createTaskRecord,
  decryptProtocolPayload,
  decryptRiskResponse,
  deleteTaskRecord,
  deleteTaskRiskCluster,
  deriveAssetData,
  fetchTaskJS,
  fetchTasks,
  normalizeRisks,
  restartTaskScan,
  runtimeDecryptProtocolPayload,
  runtimeDecryptRiskResponse,
  startTaskScan,
  stopTaskScan,
  updateTaskRiskStatus,
} from './tasks';

jest.mock('@/utils/request', () => ({
  __esModule: true,
  default: {
    get: jest.fn(),
    post: jest.fn(),
    patch: jest.fn(),
    delete: jest.fn(),
  },
}));

describe('tasks service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('derives asset buckets from tree nodes and risk urls when the asset endpoint is unavailable', () => {
    const assets = deriveAssetData(
      'task-1',
      '示例任务',
      [
        {
          id: '1',
          label: 'root',
          url: 'https://demo.example.com',
          children: [
            {
              id: '2',
              label: 'api',
              url: 'https://demo.example.com/api/orders/list',
            },
          ],
        },
      ],
      [
        {
          id: 'risk-1',
          title: 'SQL 注入',
          level: 'high',
          type: 'sqli',
          url: 'https://demo.example.com/api/orders/detail?id=1',
          description: '',
          createdAt: '',
        },
      ],
    );

    expect(assets.taskId).toBe('task-1');
    expect(assets.taskName).toBe('示例任务');
    expect(assets.ipUrl).toEqual([
      { value: 'https://demo.example.com', source: ['站点树 · root'] },
      {
        value: 'https://demo.example.com/api/orders/detail?id=1',
        source: ['风险 · SQL 注入'],
      },
      {
        value: 'https://demo.example.com/api/orders/list',
        source: ['站点树 · api'],
      },
    ]);
    expect(assets.apiRoot).toEqual([
      {
        value: '/api',
        source: ['站点树 · api', '风险 · SQL 注入'],
      },
    ]);
    expect(assets.apiRouter).toEqual([
      {
        value: '/api/orders/detail',
        source: ['风险 · SQL 注入'],
      },
      {
        value: '/api/orders/list',
        source: ['站点树 · api'],
      },
    ]);
  });

  test('returns empty derived buckets when there is no tree or risk data to mine', () => {
    const assets = deriveAssetData('task-2', '', [], []);

    expect(assets.taskId).toBe('task-2');
    expect(assets.taskName).toBe('');
    expect(assets.ipUrl).toEqual([]);
    expect(assets.apiRoot).toEqual([]);
    expect(assets.apiRouter).toEqual([]);
  });

  test('creates a task record in pending state before scanning starts', async () => {
    await createTaskRecord({
      id: 'task-1',
      name: '新任务',
      targets: ['https://example.com'],
    });

    expect(request.post).toHaveBeenCalledWith('/api/task/save', {
      id: 'task-1',
      name: '新任务',
      targets: ['https://example.com'],
      status: 'pending',
      progress: 0,
    });
  });

  test('starts a scan with urls and task id', async () => {
    await startTaskScan({
      taskId: 'task-1',
      urls: ['https://example.com'],
    });

    expect(request.post).toHaveBeenCalledWith('/api/scan/start', {
      taskId: 'task-1',
      urls: ['https://example.com'],
    });
  });

  test('passes task filters through the list endpoint', async () => {
    await fetchTasks(2, 20, {
      keyword: 'gateway',
      status: 'running',
    });

    expect(request.get).toHaveBeenCalledWith('/api/task/records', {
      params: {
        page: 2,
        size: 20,
        keyword: 'gateway',
        status: 'running',
      },
    });
  });

  test('stops a running task through the existing backend endpoint', async () => {
    await stopTaskScan('task-1');

    expect(request.post).toHaveBeenCalledWith('/api/scan/stop', {
      taskId: 'task-1',
    });
  });

  test('clears tested urls before restarting an existing task', async () => {
    await restartTaskScan({
      id: 'task-1',
      targets: ['https://example.com'],
    });

    expect(request.delete).toHaveBeenCalledWith('/api/task/task-1/tested-urls');
    expect(request.post).toHaveBeenCalledWith('/api/scan/start', {
      taskId: 'task-1',
      urls: ['https://example.com'],
    });
  });

  test('requests task js resources through the task js endpoint', async () => {
    await fetchTaskJS('task-1', { version: 2 });

    expect(request.get).toHaveBeenCalledWith('/api/task/task-1/js', {
      params: { version: 2 },
    });
  });

  test('deletes a task record through the existing backend endpoint', async () => {
    await deleteTaskRecord('task-1');

    expect(request.post).toHaveBeenCalledWith('/api/task/delete', {
      id: 'task-1',
    });
  });

  test('normalizes risk protocol trace metadata from backend fields', () => {
    const risks = normalizeRisks([
      {
        vuln_id: 'risk-1',
        title: '未授权访问',
        level: 'high',
        confidence: 'low',
        type: '未授权访问',
        url: 'https://example.com/api/orders',
        trace_id: 'trace-1',
        has_protocol_trace: true,
        response_ciphertext: 'abcd1234',
        decryption_status: 'not_tried',
        decryption_detail: '已关联协议轨迹',
        confidence_reason: '相同响应大量重复',
        deny_template_id: 'cluster-a',
        deny_template_kind: 'auth_required',
        deny_template_label: '疑似统一认证拒绝模板',
        deny_template_count: 12,
        static_contexts: [
          {
            source_url: 'https://example.com/app.js',
            snippet: 'axios.get("/api/orders")',
          },
        ],
      },
    ]);

    expect(risks[0]).toMatchObject({
      status: 'open',
      confidence: 'low',
      traceId: 'trace-1',
      hasProtocolTrace: true,
      responseCiphertext: 'abcd1234',
      decryptionStatus: 'not_tried',
      decryptionDetail: '已关联协议轨迹',
      confidenceReason: '相同响应大量重复',
      denyTemplateId: 'cluster-a',
      denyTemplateKind: 'auth_required',
      denyTemplateLabel: '疑似统一认证拒绝模板',
      denyTemplateCount: 12,
      staticContexts: [
        {
          sourceUrl: 'https://example.com/app.js',
          snippet: 'axios.get("/api/orders")',
        },
      ],
    });
  });

  test('updates risk status through the vulnerability status endpoint', async () => {
    await updateTaskRiskStatus('risk-1', {
      status: 'resolved',
    });

    expect(request.patch).toHaveBeenCalledWith('/api/vuln/risk-1/status', {
      status: 'resolved',
    });
  });

  test('decrypts a risk response through the protocol tools endpoint', async () => {
    (request.post as jest.Mock).mockResolvedValue({
      data: {
        key_hex: '00112233',
        ciphertext: 'abcd1234',
        plaintext: '{"ok":true}',
        mode: 'offline',
        source: 'sm4',
        detail: '通过历史材料完成解密',
        function_hint: 'module.sd',
      },
    });

    const result = await decryptRiskResponse(
      'task-1',
      {
        traceId: 'trace-1',
        ciphertext: 'abcd1234',
      },
      {
        version: 3,
      },
    );

    expect(request.post).toHaveBeenCalledWith(
      '/api/task/task-1/protocol-tools/decrypt',
      {
        traceId: 'trace-1',
        ciphertext: 'abcd1234',
      },
      {
        params: { version: 3 },
      },
    );
    expect(result).toEqual({
      keyHex: '00112233',
      ciphertext: 'abcd1234',
      plaintext: '{"ok":true}',
      mode: 'offline',
      source: 'sm4',
      detail: '通过历史材料完成解密',
      functionHint: 'module.sd',
    });
  });

  test('deletes a deny-template cluster through the task cluster endpoint', async () => {
    await deleteTaskRiskCluster('task-1', 'cluster-auth-1', {
      version: 4,
    });

    expect(request.delete).toHaveBeenCalledWith(
      '/api/task/task-1/vuln-clusters/cluster-auth-1',
      {
        params: { version: 4 },
      },
    );
  });

  test('decrypts an arbitrary payload through a selected protocol trace', async () => {
    (request.post as jest.Mock).mockResolvedValue({
      data: {
        ciphertext: 'cipher-from-panel',
        plaintext: '{"from":"panel"}',
        mode: 'offline',
        source: 'captured-response-plaintext',
        detail: '通过所选链路复用历史明文证据',
        function_hint: 'module.sd',
      },
    });

    const result = await decryptProtocolPayload(
      'task-1',
      {
        traceId: 'trace-2',
        ciphertext: 'cipher-from-panel',
      },
      {
        version: 5,
      },
    );

    expect(request.post).toHaveBeenCalledWith(
      '/api/task/task-1/protocol-tools/decrypt',
      {
        traceId: 'trace-2',
        ciphertext: 'cipher-from-panel',
      },
      {
        params: { version: 5 },
      },
    );
    expect(result?.plaintext).toBe('{"from":"panel"}');
  });

  test('runtime decrypts a risk response through the runtime protocol endpoint', async () => {
    (request.post as jest.Mock).mockResolvedValue({
      data: {
        ciphertext: 'abcd1234',
        plaintext: '{"ok":true}',
        mode: 'runtime',
        source: 'browser-context',
        detail: '通过浏览器上下文在线执行页面解密逻辑完成还原',
        function_hint: 'module.sd',
      },
    });

    const result = await runtimeDecryptRiskResponse(
      'task-1',
      {
        traceId: 'trace-1',
        ciphertext: 'abcd1234',
        requestUrl: 'https://example.com/api/orders',
      },
      {
        version: 3,
      },
    );

    expect(request.post).toHaveBeenCalledWith(
      '/api/task/task-1/protocol-tools/runtime-decrypt',
      {
        traceId: 'trace-1',
        ciphertext: 'abcd1234',
        requestUrl: 'https://example.com/api/orders',
      },
      {
        params: { version: 3 },
      },
    );
    expect(result).toEqual({
      keyHex: '',
      ciphertext: 'abcd1234',
      plaintext: '{"ok":true}',
      mode: 'runtime',
      source: 'browser-context',
      detail: '通过浏览器上下文在线执行页面解密逻辑完成还原',
      functionHint: 'module.sd',
    });
  });

  test('runtime decrypts an arbitrary payload through a selected protocol trace', async () => {
    (request.post as jest.Mock).mockResolvedValue({
      data: {
        ciphertext: 'cipher-from-panel',
        plaintext: '{"from":"runtime-panel"}',
        mode: 'runtime',
        source: 'browser-context',
        detail: '通过浏览器上下文在线执行页面解密逻辑完成还原',
        function_hint: 'module.sd',
      },
    });

    const result = await runtimeDecryptProtocolPayload(
      'task-1',
      {
        traceId: 'trace-2',
        ciphertext: 'cipher-from-panel',
        requestUrl: 'https://example.com/api/panel',
        pageUrl: 'https://example.com/page',
      },
      {
        version: 5,
      },
    );

    expect(request.post).toHaveBeenCalledWith(
      '/api/task/task-1/protocol-tools/runtime-decrypt',
      {
        traceId: 'trace-2',
        ciphertext: 'cipher-from-panel',
        requestUrl: 'https://example.com/api/panel',
        pageUrl: 'https://example.com/page',
      },
      {
        params: { version: 5 },
      },
    );
    expect(result?.plaintext).toBe('{"from":"runtime-panel"}');
  });
});

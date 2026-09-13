import request from '@/utils/request';
import {
  createTaskRecord,
  deleteTaskRecord,
  deleteTaskRiskCluster,
  deriveAssetData,
  fetchTaskJS,
  fetchTasks,
  normalizeRisks,
  restartTaskScan,
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
        response_plaintext: '{"code":0,"data":{"id":1}}',
        decryption_status: 'not_tried',
        decryption_detail: '已关联协议轨迹',
        confidence_reason: '低置信：结果更像相似拒绝模板或通用错误响应',
        static_contexts: [
          {
            source_url: 'https://example.com/app.js',
            snippet: 'axios.get("/api/orders")',
          },
        ],
        crypto_key_evidence: {
          algorithm: 'RSA PKCS#1 v1.5',
          key_type: 'RSA 私钥',
          key_format: 'Base64 DER PKCS#8',
          key_material: 'MIIE...private-key-material',
          key_bits: 2048,
          fingerprint: 'abc123',
          source_url: 'https://example.com/app.js',
          decoder_path: 'str3 → s/d 异或解码',
          decrypt_function: 'rsaDecryptNew',
          verification: '已静态解密并验证 JSON 响应（1 个 RSA 块）',
        },
      },
    ]);

    expect(risks[0]).toMatchObject({
      status: 'open',
      confidence: 'low',
      traceId: 'trace-1',
      hasProtocolTrace: true,
      responseCiphertext: 'abcd1234',
      responsePlaintext: '{"code":0,"data":{"id":1}}',
      decryptionStatus: 'not_tried',
      decryptionDetail: '已关联协议轨迹',
      confidenceReason: '低置信：结果更像相似拒绝模板或通用错误响应',
      staticContexts: [
        {
          sourceUrl: 'https://example.com/app.js',
          snippet: 'axios.get("/api/orders")',
        },
      ],
      cryptoKeyEvidence: {
        algorithm: 'RSA PKCS#1 v1.5',
        keyType: 'RSA 私钥',
        keyFormat: 'Base64 DER PKCS#8',
        keyMaterial: 'MIIE...private-key-material',
        keyBits: 2048,
        fingerprint: 'abc123',
        sourceUrl: 'https://example.com/app.js',
        decoderPath: 'str3 → s/d 异或解码',
        decryptFunction: 'rsaDecryptNew',
        verification: '已静态解密并验证 JSON 响应（1 个 RSA 块）',
      },
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

});

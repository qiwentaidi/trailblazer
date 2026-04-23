import type {
  APIResource,
  AssetData,
  AssetValue,
  JSResource,
  PagedResponse,
  ProtocolAIExplanationResult,
  ProtocolDecryptResult,
  ProtocolTrace,
  Risk,
  StaticProtocolAnalysis,
  TaskSummary,
  TaskVersionSummary,
  TreeNode,
} from '@/types/task';
import { getApiBaseURL } from '@/utils/apiBase';
import request from '@/utils/request';
import { readStoredAuthToken } from '@/utils/session';

type TaskTreeResponse = { data: TreeNode[] };
type TaskRiskResponse = { data: unknown[] };
type BackendAssetItem =
  | AssetValue
  | { value?: string; source?: string | string[] };
type BackendAssetData = Omit<Partial<AssetData>, 'apiRoot' | 'apiRouter'> & {
  apiRoots?: BackendAssetItem[];
  apiRoutes?: BackendAssetItem[];
  apiRoot?: BackendAssetItem[];
  apiRouter?: BackendAssetItem[];
};
type TaskAssetResponse = { data: BackendAssetData };
type TaskProtocolTraceResponse = { data: ProtocolTrace[] };
type TaskStaticProtocolResponse = { data: StaticProtocolAnalysis };
type TaskJSResponse = { data: BackendJSResource[] };
type TaskAPIResponse = { data: BackendAPIResource[] };
type ProtocolDecryptResponse = {
  data?: {
    key_hex?: string;
    ciphertext?: string;
    plaintext?: string;
    mode?: string;
    source?: string;
    detail?: string;
    function_hint?: string;
  };
};
type ProtocolExplainResponse = {
  data?: {
    trace_id?: string;
    explanation?: string;
    model?: string;
  };
};
type ProtocolExplainStreamEvent =
  | {
      type: 'start';
      traceId?: string;
    }
  | {
      type: 'delta';
      traceId?: string;
      delta?: string;
    }
  | {
      type: 'done';
      traceId?: string;
      explanation?: string;
      model?: string;
    };
type TaskDetailResponse = {
  task_id?: string;
  task_name?: string;
  targets?: string[] | null;
  status?: string;
  created_at?: string;
  updated_at?: string;
  progress?: number;
};

type TaskVersionResponse = {
  task_id?: string;
  version?: number;
  targets_snapshot?: string[] | null;
  status?: string;
  progress?: number;
  highest_risk_level?: string;
  trigger_type?: string;
  is_latest?: boolean;
  started_at?: string;
  finished_at?: string;
  created_at?: string;
  updated_at?: string;
};

type BackendRisk = {
  vuln_id?: string;
  title?: string;
  level?: Risk['level'];
  status?: Risk['status'];
  confidence?: Risk['confidence'];
  type?: string;
  url?: string;
  method?: string;
  request?: string;
  response?: string;
  trace_id?: string;
  has_protocol_trace?: boolean;
  response_ciphertext?: string;
  decryption_status?: string;
  decryption_detail?: string;
  response_length?: number;
  static_contexts?: Array<{
    source_url?: string;
    snippet?: string;
  }>;
  confidence_reason?: string;
  deny_template_id?: string;
  deny_template_kind?: string;
  deny_template_label?: string;
  deny_template_count?: number;
  description?: string;
  created_at?: string;
  ai_verified?: boolean;
};

type BackendJSResource = {
  task_id?: string;
  version?: number;
  url?: string;
  content?: string;
  response_code?: number;
  headers?: Record<string, string>;
  size?: number;
  fetched_at?: string;
};

type BackendAPIResource = {
  task_id?: string;
  version?: number;
  url?: string;
  method?: string;
  trace_id?: string;
  has_protocol_trace?: boolean;
  request_headers?: Record<string, string>;
  request_body?: string;
  response_headers?: Record<string, string>;
  response_body?: string;
  response_code?: number;
  headers?: Record<string, string>;
  fetched_at?: string;
};

interface DecryptRiskPayload {
  traceId: string;
  ciphertext: string;
  keyHex?: string;
}

interface RuntimeDecryptRiskPayload {
  traceId: string;
  ciphertext: string;
  pageUrl?: string;
  requestUrl?: string;
}

export type ProtocolDecryptPayload = DecryptRiskPayload;

export type ProtocolRuntimeDecryptPayload = RuntimeDecryptRiskPayload;
export interface ProtocolExplainPayload {
  traceId: string;
}

interface TaskVersionOptions {
  version?: number;
}

interface UpdateRiskStatusPayload {
  status: NonNullable<Risk['status']>;
}

interface ProtocolExplainStreamOptions extends TaskVersionOptions {
  signal?: AbortSignal;
  onEvent?: (event: ProtocolExplainStreamEvent) => void;
}

interface CreateTaskPayload {
  id: string;
  name: string;
  targets: string[];
}

interface StartTaskScanPayload {
  taskId: string;
  urls: string[];
}

const VALID_RISK_LEVELS = new Set<Risk['level']>([
  'high',
  'medium',
  'low',
  'info',
]);

export const normalizeRiskLevel = (level: unknown): Risk['level'] =>
  typeof level === 'string' && VALID_RISK_LEVELS.has(level as Risk['level'])
    ? (level as Risk['level'])
    : 'info';

export interface FetchTasksFilters {
  keyword?: string;
  status?: string;
}

export const fetchTasks = (
  page = 1,
  size = 10,
  filters: FetchTasksFilters = {},
) =>
  request.get<PagedResponse<TaskSummary>>('/api/task/records', {
    params: {
      page,
      size,
      ...(filters.keyword ? { keyword: filters.keyword } : {}),
      ...(filters.status ? { status: filters.status } : {}),
    },
  });

const buildVersionParams = (version?: number) =>
  version ? { version } : undefined;

const parseDownloadFilename = (
  contentDisposition: string | null,
  fallback: string,
) => {
  if (!contentDisposition) {
    return fallback;
  }

  const utf8Match = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      return utf8Match[1];
    }
  }

  const basicMatch = contentDisposition.match(/filename="([^"]+)"/i);
  if (basicMatch?.[1]) {
    return basicMatch[1];
  }

  return fallback;
};

export const fetchTaskDetail = async (
  id: string,
  options: TaskVersionOptions = {},
) => {
  const response = await request.get<{ data?: TaskDetailResponse }>(
    `/api/task/${id}`,
    {
      params: buildVersionParams(options.version),
    },
  );
  const task = response?.data;

  if (!task) {
    return null;
  }

  return {
    id: task.task_id || id,
    name: task.task_name || `任务 ${id}`,
    targets: task.targets || [],
    status: task.status || 'unknown',
    createdAt: task.created_at || '',
    progress: task.progress,
  } satisfies TaskSummary;
};

export const fetchTaskVersions = async (
  id: string,
): Promise<TaskVersionSummary[]> => {
  const response = await request.get<{ data?: TaskVersionResponse[] }>(
    `/api/task/${id}/versions`,
  );

  return (response?.data || []).map((item) => ({
    taskId: item.task_id || id,
    version: typeof item.version === 'number' ? item.version : 0,
    targetsSnapshot: item.targets_snapshot || [],
    status: item.status || 'pending',
    progress: typeof item.progress === 'number' ? item.progress : 0,
    highestRiskLevel: item.highest_risk_level,
    triggerType: item.trigger_type || '',
    isLatest: Boolean(item.is_latest),
    startedAt: item.started_at || '',
    finishedAt: item.finished_at || '',
    createdAt: item.created_at || '',
    updatedAt: item.updated_at || '',
  }));
};

export const fetchTaskTree = (id: string, options: TaskVersionOptions = {}) =>
  request.get<TaskTreeResponse>(`/api/task/${id}/tree`, {
    params: buildVersionParams(options.version),
  });

export const downloadTaskHTMLReport = async (
  id: string,
  options: TaskVersionOptions = {},
) => {
  const query = new URLSearchParams();
  query.set('format', 'html');
  if (options.version) {
    query.set('version', String(options.version));
  }

  const token = readStoredAuthToken();
  const response = await fetch(
    `${getApiBaseURL()}/api/task/${id}/report?${query.toString()}`,
    {
      method: 'GET',
      headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    },
  );

  if (!response.ok) {
    throw new Error(`report download failed: ${response.status}`);
  }

  const blob = await response.blob();
  return {
    blob,
    filename: parseDownloadFilename(
      response.headers.get('Content-Disposition'),
      `task_${id}_risk_asset_report.html`,
    ),
  };
};

export const fetchTaskRisks = (id: string, options: TaskVersionOptions = {}) =>
  request.get<TaskRiskResponse>(`/api/task/${id}/vulns`, {
    params: buildVersionParams(options.version),
  });

export const fetchTaskAssets = (id: string, options: TaskVersionOptions = {}) =>
  request
    .get<TaskAssetResponse>(`/api/task/${id}/assets`, {
      params: buildVersionParams(options.version),
    })
    .then((response) => ({
      ...response,
      data: normalizeAssetData(response?.data),
    }));

export const fetchTaskProtocolTraces = (
  id: string,
  options: TaskVersionOptions = {},
) =>
  request.get<TaskProtocolTraceResponse>(`/api/task/${id}/protocol-traces`, {
    params: buildVersionParams(options.version),
  });

export const fetchTaskStaticProtocolAnalysis = (
  id: string,
  options: TaskVersionOptions = {},
) =>
  request.get<TaskStaticProtocolResponse>(
    `/api/task/${id}/static-protocol-analysis`,
    {
      params: buildVersionParams(options.version),
    },
  );

export const fetchTaskJS = (id: string, options: TaskVersionOptions = {}) =>
  request.get<TaskJSResponse>(`/api/task/${id}/js`, {
    params: buildVersionParams(options.version),
  });

export const fetchTaskJSResources = async (
  id: string,
  options: TaskVersionOptions = {},
): Promise<JSResource[]> => {
  const response = await fetchTaskJS(id, options);

  return (response?.data || []).map((item) => ({
    taskId: item.task_id || id,
    version: item.version || 0,
    url: item.url || '',
    content: item.content || '',
    responseCode: item.response_code,
    headers: item.headers || {},
    size: item.size || 0,
    fetchedAt: item.fetched_at || '',
  }));
};

export const fetchTaskAPIs = async (
  id: string,
  options: TaskVersionOptions = {},
): Promise<APIResource[]> => {
  const response = await request.get<TaskAPIResponse>(`/api/task/${id}/apis`, {
    params: buildVersionParams(options.version),
  });

  return (response?.data || []).map((item) => ({
    taskId: item.task_id || id,
    version: item.version || 0,
    url: item.url || '',
    method: item.method || 'GET',
    traceId: item.trace_id || '',
    hasProtocolTrace: Boolean(item.has_protocol_trace),
    requestHeaders: item.request_headers || {},
    requestBody: item.request_body || '',
    responseHeaders: item.response_headers || {},
    responseBody: item.response_body || '',
    responseCode: item.response_code,
    headers: item.headers || {},
    fetchedAt: item.fetched_at || '',
  }));
};

export const decryptProtocolPayload = async (
  taskId: string,
  payload: ProtocolDecryptPayload,
  options: TaskVersionOptions = {},
): Promise<ProtocolDecryptResult | null> => {
  const response = await request.post<ProtocolDecryptResponse>(
    `/api/task/${taskId}/protocol-tools/decrypt`,
    payload,
    {
      params: buildVersionParams(options.version),
    },
  );

  const result = response?.data;
  if (!result) {
    return null;
  }

  return {
    keyHex: result.key_hex || '',
    ciphertext: result.ciphertext || '',
    plaintext: result.plaintext || '',
    mode: result.mode || '',
    source: result.source || '',
    detail: result.detail || '',
    functionHint: result.function_hint || '',
  };
};

export const runtimeDecryptProtocolPayload = async (
  taskId: string,
  payload: ProtocolRuntimeDecryptPayload,
  options: TaskVersionOptions = {},
): Promise<ProtocolDecryptResult | null> => {
  const response = await request.post<ProtocolDecryptResponse>(
    `/api/task/${taskId}/protocol-tools/runtime-decrypt`,
    payload,
    {
      params: buildVersionParams(options.version),
    },
  );

  const result = response?.data;
  if (!result) {
    return null;
  }

  return {
    keyHex: result.key_hex || '',
    ciphertext: result.ciphertext || '',
    plaintext: result.plaintext || '',
    mode: result.mode || '',
    source: result.source || '',
    detail: result.detail || '',
    functionHint: result.function_hint || '',
  };
};

export const decryptRiskResponse = async (
  taskId: string,
  payload: DecryptRiskPayload,
  options: TaskVersionOptions = {},
): Promise<ProtocolDecryptResult | null> =>
  decryptProtocolPayload(taskId, payload, options);

export const runtimeDecryptRiskResponse = async (
  taskId: string,
  payload: RuntimeDecryptRiskPayload,
  options: TaskVersionOptions = {},
): Promise<ProtocolDecryptResult | null> =>
  runtimeDecryptProtocolPayload(taskId, payload, options);

export const explainProtocolTrace = async (
  taskId: string,
  payload: ProtocolExplainPayload,
  options: TaskVersionOptions = {},
): Promise<ProtocolAIExplanationResult | null> => {
  const response = await request.post<ProtocolExplainResponse>(
    `/api/task/${taskId}/protocol-tools/explain`,
    payload,
    {
      params: buildVersionParams(options.version),
    },
  );

  const result = response?.data;
  if (!result) {
    return null;
  }

  return {
    traceId: result.trace_id || '',
    explanation: result.explanation || '',
    model: result.model || '',
  };
};

const parseProtocolExplainStreamEvents = (buffer: string) => {
  const events: Array<{ event: string; data: string }> = [];
  let rest = buffer;
  let separatorIndex = rest.indexOf('\n\n');

  while (separatorIndex >= 0) {
    const rawEvent = rest.slice(0, separatorIndex);
    rest = rest.slice(separatorIndex + 2);

    const lines = rawEvent.split(/\r?\n/);
    let eventName = 'message';
    const dataLines: string[] = [];

    lines.forEach((line) => {
      if (line.startsWith('event:')) {
        eventName = line.slice('event:'.length).trim();
        return;
      }
      if (line.startsWith('data:')) {
        dataLines.push(line.slice('data:'.length).trim());
      }
    });

    if (dataLines.length) {
      events.push({
        event: eventName,
        data: dataLines.join('\n'),
      });
    }

    separatorIndex = rest.indexOf('\n\n');
  }

  return { events, rest };
};

export const explainProtocolTraceStream = async (
  taskId: string,
  payload: ProtocolExplainPayload,
  options: ProtocolExplainStreamOptions = {},
): Promise<ProtocolAIExplanationResult | null> => {
  const params = new URLSearchParams();
  if (options.version) {
    params.set('version', String(options.version));
  }

  const token = readStoredAuthToken();
  const query = params.toString();
  const response = await fetch(
    `${getApiBaseURL()}/api/task/${taskId}/protocol-tools/explain${query ? `?${query}` : ''}`,
    {
      method: 'POST',
      headers: {
        Accept: 'text/event-stream',
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(payload),
      signal: options.signal,
    },
  );

  if (!response.ok) {
    const rawText = await response.text();
    let detail = rawText;

    try {
      const parsed = JSON.parse(rawText);
      detail = parsed?.detail || parsed?.error || rawText;
    } catch {
      // keep raw text
    }

    throw new Error(detail || 'AI 解释生成失败');
  }

  if (!response.body) {
    throw new Error('AI 流式解释未返回响应体');
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let accumulated = '';
  let finalResult: ProtocolAIExplanationResult | null = null;
  let doneReading = false;

  while (!doneReading) {
    const { done, value } = await reader.read();
    doneReading = done;
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });

    const { events, rest } = parseProtocolExplainStreamEvents(buffer);
    buffer = rest;

    events.forEach(({ event, data }) => {
      const parsed = JSON.parse(data);

      if (event === 'start') {
        options.onEvent?.({
          type: 'start',
          traceId: parsed.trace_id || payload.traceId,
        });
        return;
      }

      if (event === 'delta') {
        accumulated += parsed.delta || '';
        options.onEvent?.({
          type: 'delta',
          traceId: parsed.trace_id || payload.traceId,
          delta: parsed.delta || '',
        });
        return;
      }

      if (event === 'done') {
        finalResult = {
          traceId: parsed.trace_id || payload.traceId,
          explanation: parsed.explanation || accumulated,
          model: parsed.model || '',
        };
        options.onEvent?.({
          type: 'done',
          traceId: finalResult.traceId,
          explanation: finalResult.explanation,
          model: finalResult.model,
        });
        return;
      }

      if (event === 'error') {
        throw new Error(parsed.detail || parsed.error || 'AI 解释生成失败');
      }
    });
  }

  return (
    finalResult || {
      traceId: payload.traceId,
      explanation: accumulated,
      model: '',
    }
  );
};

export const deleteTaskRisk = (riskId: string) =>
  request.delete(`/api/vuln/${riskId}`);

export const updateTaskRiskStatus = (
  riskId: string,
  payload: UpdateRiskStatusPayload,
) => request.patch(`/api/vuln/${riskId}/status`, payload);

export const deleteTaskRiskCluster = (
  taskId: string,
  clusterId: string,
  options: TaskVersionOptions = {},
) =>
  request.delete(`/api/task/${taskId}/vuln-clusters/${clusterId}`, {
    params: buildVersionParams(options.version),
  });

export const deleteTaskRecord = (taskId: string) =>
  request.post('/api/task/delete', {
    id: taskId,
  });

export const createTaskRecord = (payload: CreateTaskPayload) =>
  request.post('/api/task/save', {
    ...payload,
    status: 'pending',
    progress: 0,
  });

export const startTaskScan = (payload: StartTaskScanPayload) =>
  request.post('/api/scan/start', payload);

export const stopTaskScan = (taskId: string) =>
  request.post('/api/scan/stop', {
    taskId,
  });

export const clearTaskTestedUrls = (taskId: string) =>
  request.delete(`/api/task/${taskId}/tested-urls`);

export const restartTaskScan = async (
  task: Pick<TaskSummary, 'id' | 'targets'>,
) => {
  const urls = task.targets || [];
  if (!urls.length) {
    throw new Error('任务缺少目标 URL，无法重扫');
  }

  await clearTaskTestedUrls(task.id);
  return startTaskScan({
    taskId: task.id,
    urls,
  });
};

const uniqueSorted = (items: string[]) =>
  Array.from(new Set(items.filter(Boolean))).sort((left, right) =>
    left.localeCompare(right),
  );

const normalizeAssetItemList = (items?: BackendAssetItem[]): AssetValue[] =>
  (items || []).reduce<AssetValue[]>((result, item) => {
    if (typeof item === 'string') {
      result.push(item);
      return result;
    }
    if (!item?.value) {
      return result;
    }
    result.push({
      value: item.value,
      source: item.source,
    });
    return result;
  }, []);

const normalizeAssetData = (
  data?: BackendAssetData | null,
): AssetData | null => {
  if (!data) {
    return null;
  }

  return {
    taskId: data.taskId || '',
    taskName: data.taskName || '',
    email: normalizeAssetItemList(data.email),
    idCard: normalizeAssetItemList(data.idCard),
    phone: normalizeAssetItemList(data.phone),
    ipUrl: normalizeAssetItemList(data.ipUrl),
    apiRoot: normalizeAssetItemList(data.apiRoot || data.apiRoots),
    apiRouter: normalizeAssetItemList(data.apiRouter || data.apiRoutes),
    createdAt: data.createdAt || '',
  };
};

const collectTreeUrls = (nodes: TreeNode[] = []): string[] =>
  nodes.flatMap((node) => [
    ...(node.url ? [node.url] : []),
    ...collectTreeUrls(node.children || []),
  ]);

const normalizeAbsoluteUrl = (value: string) => {
  try {
    const normalized = new URL(value).toString();
    return normalized.endsWith('/') ? normalized.slice(0, -1) : normalized;
  } catch {
    return '';
  }
};

const normalizeApiRoute = (value: string) => {
  try {
    const parsed = new URL(value);
    const path = parsed.pathname || '';
    return path.includes('/api') ? path : '';
  } catch {
    return '';
  }
};

const normalizeApiRoot = (path: string) => {
  const segments = path.split('/').filter(Boolean);
  if (segments.length === 0) {
    return '';
  }

  const apiIndex = segments.findIndex(
    (segment) => segment.toLowerCase() === 'api',
  );
  if (apiIndex === -1) {
    return '';
  }

  return `/${segments.slice(0, apiIndex + 1).join('/')}`;
};

export const deriveAssetData = (
  taskId: string,
  taskName: string,
  treeData: TreeNode[] = [],
  risks: Risk[] = [],
): AssetData => {
  const ipUrlSources = new Map<string, Set<string>>();
  const apiRouterSources = new Map<string, Set<string>>();
  const apiRootSources = new Map<string, Set<string>>();

  const appendSource = (
    target: Map<string, Set<string>>,
    value: string,
    source: string,
  ) => {
    if (!value || !source) {
      return;
    }
    if (!target.has(value)) {
      target.set(value, new Set<string>());
    }
    target.get(value)?.add(source);
  };

  const walkTree = (nodes: TreeNode[] = []) => {
    nodes.forEach((node) => {
      const normalizedURL = normalizeAbsoluteUrl(node.url || '');
      if (normalizedURL) {
        appendSource(
          ipUrlSources,
          normalizedURL,
          node.label ? `站点树 · ${node.label}` : '站点树',
        );
      }
      if (node.children?.length) {
        walkTree(node.children);
      }
    });
  };

  walkTree(treeData);

  risks.forEach((risk) => {
    const normalizedURL = normalizeAbsoluteUrl(risk.url);
    if (!normalizedURL) {
      return;
    }
    appendSource(
      ipUrlSources,
      normalizedURL,
      risk.title ? `风险 · ${risk.title}` : '风险',
    );
  });

  Array.from(ipUrlSources.keys()).forEach((absoluteUrl) => {
    const sources = Array.from(ipUrlSources.get(absoluteUrl) || []);
    const apiRoute = normalizeApiRoute(absoluteUrl);
    if (apiRoute) {
      sources.forEach((source) =>
        appendSource(apiRouterSources, apiRoute, source),
      );
      const apiRoot = normalizeApiRoot(apiRoute);
      if (apiRoot) {
        sources.forEach((source) =>
          appendSource(apiRootSources, apiRoot, source),
        );
      }
    }
  });

  const toAssetValues = (sourceMap: Map<string, Set<string>>): AssetValue[] =>
    uniqueSorted(Array.from(sourceMap.keys())).map((value) => ({
      value,
      source: Array.from(sourceMap.get(value) || []),
    }));

  return {
    taskId,
    taskName,
    email: [],
    idCard: [],
    phone: [],
    ipUrl: toAssetValues(ipUrlSources),
    apiRoot: toAssetValues(apiRootSources),
    apiRouter: toAssetValues(apiRouterSources),
    createdAt: '',
  };
};

export const normalizeRisks = (items: unknown[]): Risk[] =>
  items.map((item) => {
    const risk = item as BackendRisk;

    return {
      id: risk.vuln_id || '',
      title: risk.title || '',
      level: normalizeRiskLevel(risk.level),
      status: risk.status || 'open',
      confidence: risk.confidence || 'medium',
      type: risk.type || '',
      url: risk.url || '',
      method: risk.method,
      request: risk.request,
      response: risk.response,
      traceId: risk.trace_id,
      hasProtocolTrace: Boolean(risk.has_protocol_trace),
      responseCiphertext: risk.response_ciphertext,
      decryptionStatus: risk.decryption_status,
      decryptionDetail: risk.decryption_detail,
      responseLength: risk.response_length || 0,
      staticContexts: (risk.static_contexts || [])
        .map((item) => ({
          sourceUrl: item?.source_url || '',
          snippet: item?.snippet || '',
        }))
        .filter((item) => item.sourceUrl || item.snippet),
      confidenceReason: risk.confidence_reason || '',
      denyTemplateId: risk.deny_template_id || '',
      denyTemplateKind: risk.deny_template_kind || '',
      denyTemplateLabel: risk.deny_template_label || '',
      denyTemplateCount: risk.deny_template_count || 0,
      description: risk.description || '',
      createdAt: risk.created_at || '',
      aiVerified: Boolean(risk.ai_verified),
    };
  });

import type {
  APIResource,
  AssetData,
  AssetValue,
  JSResource,
  PagedResponse,
  Risk,
  TaskSummary,
  TaskTreeData,
  TaskVersionSummary,
  TreeNode,
} from '@/types/task';
import { getApiBaseURL } from '@/utils/apiBase';
import request from '@/utils/request';
import { readStoredAuthToken } from '@/utils/session';

type TaskTreeResponse = TaskTreeData;
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
type TaskJSResponse = { data: BackendJSResource[] };
type TaskAPIResponse = { data: BackendAPIResource[] };
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
  category?: string;
  subcategory?: string;
  business_object?: string;
  naming_source?: Risk['namingSource'];
  url?: string;
  method?: string;
  request?: string;
  response?: string;
  response_plaintext?: string;
  trace_id?: string;
  has_protocol_trace?: boolean;
  response_ciphertext?: string;
  decryption_status?: string;
  decryption_detail?: string;
  response_length?: number;
  data_exposure?: Risk['dataExposure'];
  exposure_reason?: string;
  static_contexts?: Array<{
    source_url?: string;
    snippet?: string;
  }>;
  crypto_key_evidence?: {
    algorithm?: string;
    key_type?: string;
    key_format?: string;
    key_material?: string;
    key_bits?: number;
    fingerprint?: string;
    source_url?: string;
    decoder_path?: string;
    decrypt_function?: string;
    verification?: string;
  };
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

interface TaskVersionOptions {
  version?: number;
}

interface TaskTreeOptions extends TaskVersionOptions {
  page?: number;
  pageSize?: number;
  keyword?: string;
}

interface UpdateRiskStatusPayload {
  status: NonNullable<Risk['status']>;
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

export const fetchTaskTree = (id: string, options: TaskTreeOptions = {}) =>
  request.get<TaskTreeResponse>(`/api/task/${id}/tree`, {
    params: {
      ...buildVersionParams(options.version),
      ...(options.page ? { page: options.page } : {}),
      ...(options.pageSize ? { pageSize: options.pageSize } : {}),
      ...(options.keyword ? { keyword: options.keyword } : {}),
    },
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
      category: risk.category || '',
      subcategory: risk.subcategory || '',
      businessObject: risk.business_object || '',
      namingSource: risk.naming_source || '',
      url: risk.url || '',
      method: risk.method,
      request: risk.request,
      response: risk.response,
      responsePlaintext: risk.response_plaintext,
      traceId: risk.trace_id,
      hasProtocolTrace: Boolean(risk.has_protocol_trace),
      responseCiphertext: risk.response_ciphertext,
      decryptionStatus: risk.decryption_status,
      decryptionDetail: risk.decryption_detail,
      responseLength: risk.response_length || 0,
      dataExposure: risk.data_exposure || '',
      exposureReason: risk.exposure_reason || '',
      staticContexts: (risk.static_contexts || [])
        .map((item) => ({
          sourceUrl: item?.source_url || '',
          snippet: item?.snippet || '',
        }))
        .filter((item) => item.sourceUrl || item.snippet),
      cryptoKeyEvidence: risk.crypto_key_evidence
        ? {
            algorithm: risk.crypto_key_evidence.algorithm || '',
            keyType: risk.crypto_key_evidence.key_type || '',
            keyFormat: risk.crypto_key_evidence.key_format || '',
            keyMaterial: risk.crypto_key_evidence.key_material || '',
            keyBits: risk.crypto_key_evidence.key_bits || 0,
            fingerprint: risk.crypto_key_evidence.fingerprint || '',
            sourceUrl: risk.crypto_key_evidence.source_url || '',
            decoderPath: risk.crypto_key_evidence.decoder_path || '',
            decryptFunction: risk.crypto_key_evidence.decrypt_function || '',
            verification: risk.crypto_key_evidence.verification || '',
          }
        : undefined,
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

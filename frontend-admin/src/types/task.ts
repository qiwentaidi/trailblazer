export type TaskStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'stopped';

export interface TaskSummary {
  id: string;
  name: string;
  status: TaskStatus | string;
  targets?: string[] | null;
  progress?: number;
  vulnCount?: number;
  vulnCountHigh?: number;
  vulnCountMedium?: number;
  vulnCountLow?: number;
  vulnCountInfo?: number;
  createdAt: string;
  highestRiskLevel?: 'high' | 'medium' | 'low' | 'info' | string;
  latestVersion?: number;
  latestStatus?: TaskStatus | string;
  latestProgress?: number;
  versionCount?: number;
  triggerType?: string;
  startedAt?: string;
  finishedAt?: string;
}

export interface TaskVersionSummary {
  taskId: string;
  version: number;
  targetsSnapshot: string[];
  status: TaskStatus | string;
  progress: number;
  highestRiskLevel?: 'high' | 'medium' | 'low' | 'info' | string;
  triggerType?: string;
  isLatest: boolean;
  startedAt?: string;
  finishedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface PageInfo {
  page: number;
  size: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

export interface PagedResponse<T> {
  data: T[];
  pagination: PageInfo;
}

export interface BrowserSessionSummary {
  session_id: string;
  site_host: string;
  entry_url: string;
  status: string;
  mode: string;
  browser_mode?: string;
  proxy_type?: string;
  proxy_address?: string;
  browser_visible: boolean;
  page_count: number;
  request_count: number;
  suspicious_crypto_count: number;
  started_at: string;
  ended_at?: string;
  last_activity_at: string;
  created_at: string;
  updated_at: string;
}

export interface BrowserPageSummary {
  page_id: string;
  session_id: string;
  url: string;
  title?: string;
  is_entry: boolean;
  created_at: string;
  last_seen_at: string;
}

export interface BrowserSessionDetail {
  session: BrowserSessionSummary;
  pages: BrowserPageSummary[];
  requests: BrowserSessionRequestSummary[];
  suspiciousTraces: BrowserSessionTraceSummary[];
}

export interface BrowserSessionRequestSummary {
  id: number;
  session_id: string;
  trace_id?: string;
  url: string;
  method: string;
  resource_type?: string;
  request_headers?: Record<string, string>;
  request_body?: string;
  response_headers?: Record<string, string>;
  response_body?: string;
  response_code?: number;
  mime_type?: string;
  has_protocol_trace?: boolean;
  is_suspicious: boolean;
  suspicious_trace?: string;
  created_at: string;
}

export interface BrowserSessionTraceSummary {
  id: number;
  session_id: string;
  trace_id: string;
  request_url: string;
  method: string;
  algorithms: string[];
  request_before_transform?: string;
  final_request_body?: string;
  request_steps?: ProtocolTraceStep[];
  response_steps?: ProtocolTraceStep[];
  session_materials?: Record<string, string>;
  response_plaintext?: string;
  response_ciphertext?: string;
  suspicious_reason?: string;
  created_at: string;
}

export interface Risk {
  id: string;
  title: string;
  level: 'high' | 'medium' | 'low' | 'info';
  status?: 'open' | 'resolved' | 'ignored' | string;
  confidence?: 'high' | 'medium' | 'low' | string;
  type: string;
  category?: string;
  subcategory?: string;
  businessObject?: string;
  namingSource?: 'ai' | 'rule' | string;
  url: string;
  method?: string;
  request?: string;
  response?: string;
  responsePlaintext?: string;
  traceId?: string;
  hasProtocolTrace?: boolean;
  responseCiphertext?: string;
  decryptionStatus?: string;
  decryptionDetail?: string;
  responseLength?: number;
  dataExposure?:
    | 'public_data'
    | 'basic_reference'
    | 'internal_business'
    | 'sensitive_data'
    | string;
  exposureReason?: string;
  staticContexts?: {
    sourceUrl: string;
    snippet: string;
  }[];
  cryptoKeyEvidence?: {
    algorithm: string;
    keyType: string;
    keyFormat: string;
    keyMaterial: string;
    keyBits?: number;
    fingerprint: string;
    sourceUrl: string;
    decoderPath: string;
    decryptFunction?: string;
    verification?: string;
  };
  confidenceReason?: string;
  denyTemplateId?: string;
  denyTemplateKind?: string;
  denyTemplateLabel?: string;
  denyTemplateCount?: number;
  description: string;
  createdAt: string;
  aiVerified?: boolean;
}

export interface ProtocolDecryptResult {
  keyHex?: string;
  ciphertext?: string;
  plaintext?: string;
  mode?: string;
  source?: string;
  detail?: string;
  functionHint?: string;
}

export interface ProtocolAIExplanationResult {
  traceId?: string;
  explanation?: string;
  model?: string;
}

export interface TreeNode {
  id: string;
  label: string;
  children?: TreeNode[];
  url?: string;
  nodeType?: string;
  code?: string;
  requestBody?: unknown;
  responseBody?: unknown;
  response?: unknown;
  statusCode?: number;
  headers?: Record<string, string>;
}

export interface TaskTreeData {
  data: TreeNode[];
  nodeCount?: number;
  total?: number;
  page?: number;
  pageSize?: number;
  keyword?: string;
  totalNodeCount?: number;
}

export interface AssetData {
  taskId: string;
  taskName: string;
  email: AssetValue[];
  idCard: AssetValue[];
  phone: AssetValue[];
  ipUrl: AssetValue[];
  apiRoot: AssetValue[];
  apiRouter: AssetValue[];
  createdAt: string;
}

export type AssetValue =
  | string
  | {
      value: string;
      source?: string | string[];
    };

export interface JSResource {
  taskId: string;
  version: number;
  url: string;
  content: string;
  responseCode?: number;
  headers?: Record<string, string>;
  size?: number;
  fetchedAt?: string;
}

export interface APIResource {
  taskId: string;
  version: number;
  url: string;
  method: string;
  traceId?: string;
  hasProtocolTrace?: boolean;
  requestHeaders?: Record<string, string>;
  requestBody?: string;
  responseHeaders?: Record<string, string>;
  responseBody?: string;
  responseCode?: number;
  headers?: Record<string, string>;
  fetchedAt?: string;
}

export interface ProtocolTraceStep {
  source: string;
  algorithm?: string;
  input_preview?: string;
  output_preview?: string;
  call_id?: string;
  parent_call_id?: string;
  function_path?: string;
  module_id?: string;
  stack?: string;
  captured_at_ms?: number;
}

export interface ProtocolTrace {
  trace_id: string;
  target_url?: string;
  transport?: string;
  page_url?: string;
  request_url?: string;
  method?: string;
  request_headers?: Record<string, string>;
  request_before_transform?: string;
  final_request_body?: string;
  request_steps?: ProtocolTraceStep[];
  response_steps?: ProtocolTraceStep[];
  signature_fields?: string[];
  dynamic_params?: Record<string, string>;
  session_materials?: Record<string, string>;
  algorithms?: string[];
  stack?: string;
  created_at?: string;
}

export interface StaticProtocolEvidence {
  label: string;
  file_url: string;
  snippet: string;
}

export interface StaticProtocolParam {
  name: string;
  source?: string;
}

export interface StaticProtocolEndpoint {
  path: string;
  method: string;
  client?: string;
  params?: StaticProtocolParam[];
  request_payload_carrier?: string;
  request_payload_format?: string;
  request_payload_preview?: string;
  context?: string[];
  source_file: string;
  snippet: string;
  trace_id?: string;
  page_url?: string;
  request_url?: string;
  request_before_transform?: string;
  final_request_body?: string;
  request_steps?: ProtocolTraceStep[];
  response_steps?: ProtocolTraceStep[];
  session_materials?: Record<string, string>;
  algorithms?: string[];
}

export interface StaticProtocolProfile {
  id: string;
  name: string;
  request_wrapper?: string;
  api_base_urls?: string[];
  matched_files?: string[];
  encryption_enabled?: boolean;
  request_cipher?: string;
  response_cipher?: string;
  key_exchange?: string;
  key_transport_public_key?: string;
  signature_algorithm?: string;
  request_key_derivation?: string;
  signature_formula?: string;
  header_fields?: Record<string, string>;
  control_fields?: string[];
  request_pipeline?: string[];
  response_pipeline?: string[];
  primary_endpoint?: StaticProtocolEndpoint;
  endpoints?: StaticProtocolEndpoint[];
  evidence?: StaticProtocolEvidence[];
}

export interface StaticAPIContext {
  url: string;
  method: string;
  source_file: string;
  snippet: string;
  param_carrier?: string;
  param_preview?: string;
  params?: Array<{
    name: string;
    value?: string;
  }>;
  trace_id?: string;
  has_protocol_trace?: boolean;
  request_headers?: Record<string, string>;
  request_body?: string;
}

export interface StaticProtocolAnalysis {
  task_id: string;
  js_count: number;
  generated_at?: string;
  profiles: StaticProtocolProfile[];
  api_contexts?: StaticAPIContext[];
}

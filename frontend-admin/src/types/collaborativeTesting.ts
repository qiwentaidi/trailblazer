export type CollaborationStage =
  | 'collecting'
  | 'analyzing'
  | 'awaiting_approval'
  | 'completed'
  | 'failed';

export type RiskLevel = 'high' | 'medium' | 'low';

export type ApprovalDecision =
  | 'pending'
  | 'skipped'
  | 'dry-run'
  | 'authorized-replay'
  | 'false-positive'
  | 'more-analysis';

export type TestDecision = 'auto-tested' | 'not-runnable';

export interface RequestParameter {
  name: string;
  location?: string;
  value?: string;
  valueExpr?: string;
  resolved: boolean;
  confidence?: 'high' | 'medium' | 'low';
}

export interface RequestBlueprint {
  id: string;
  path: string;
  method: string;
  confidence: 'high' | 'medium' | 'low';
  baseUrl?: string;
  payloadCarrier?: string;
  payloadFormat?: string;
  payloadPreview?: string;
  params: RequestParameter[];
  headers: Array<{ name: string; source?: string; dynamic?: boolean }>;
  interceptors?: Array<{ client?: string; kind?: string; snippet?: string }>;
  unresolvedSymbols?: string[];
  source?: { file?: string; snippet?: string };
}

export interface CollaborationProgressEvent {
  id: string;
  stage: CollaborationStage;
  state: 'running' | 'completed' | 'waiting' | 'failed';
  title: string;
  detail?: string;
  createdAt: string;
}

export interface EndpointClue {
  id: string;
  path: string;
  method: string;
  confidence: 'high' | 'medium' | 'low';
  unresolvedSymbols?: string[];
  representative: RequestBlueprint;
  evidence: Array<{
    file?: string;
    snippet?: string;
    client?: string;
    baseUrl?: string;
  }>;
}

export interface PendingRiskAction {
  id: string;
  blueprintId: string;
  route: string;
  method: string;
  riskLevel: RiskLevel;
  actionType: string;
  reason: string;
  riskHypotheses: string[];
  suggestedNextStep: string;
  requirements: string[];
  decision: ApprovalDecision;
  decisionNote?: string;
  approvedBy?: string;
  approvedAt?: string;
  execution?: {
    statusCode: number;
    response: string;
    executedAt: string;
  };
  requestPreview: RequestBlueprint;
}

export interface CoverageSummary {
  jsResources: number;
  apiRoutesDiscovered: number;
  requestBlueprintsExtracted: number;
  autoTested: number;
  runtimeRequests: number;
  securityFindings: number;
  pendingReview: number;
  notRunnable: number;
}

export interface TestResult {
  id: string;
  route: string;
  method: string;
  kind: 'runtime-request' | 'security-finding' | 'authorized-replay';
  status: 'recorded' | 'finding' | 'completed';
  statusCode?: number;
  responseSize?: number;
  riskLevel?: string;
  traceId?: string;
  hasProtocolTrace?: boolean;
  summary: string;
  createdAt: string;
}

export interface RuntimeDecryptResult {
  keyHex: string;
  ciphertext: string;
  plaintext: string;
  mode: string;
  source: string;
  detail: string;
  functionHint: string;
}

export interface DecisionRecord {
  id: string;
  route: string;
  method: string;
  decision: ApprovalDecision | TestDecision | 'executed';
  reason: string;
  actor: string;
  createdAt: string;
}

export interface CollaborationSession {
  id: string;
  taskId: string;
  target: string;
  status: 'running' | 'completed' | 'failed';
  stage: CollaborationStage;
  error?: string;
  createdAt: string;
  updatedAt: string;
  coverage: CoverageSummary;
  requestBlueprints: RequestBlueprint[];
  endpointClues: EndpointClue[];
  timeline: CollaborationProgressEvent[];
  testResults: TestResult[];
  attachments: Array<{
    id: string;
    name: string;
    size: number;
    kind: string;
    status: string;
    detail?: string;
  }>;
  pendingRiskActions: PendingRiskAction[];
  testDecisions: DecisionRecord[];
}

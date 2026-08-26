import type { AssetValue, ProtocolTrace, Risk, TreeNode } from '@/types/task';

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

export const countTreeNodes = (nodes: TreeNode[] = []): number =>
  nodes.reduce(
    (total, node) => total + 1 + countTreeNodes(node.children || []),
    0,
  );

export const normalizeAssetBuckets = (
  assets: {
    email?: AssetValue[];
    idCard?: AssetValue[];
    phone?: AssetValue[];
    ipUrl?: AssetValue[];
    apiRoot?: AssetValue[];
    apiRouter?: AssetValue[];
  } | null,
) => ({
  email: normalizeAssetItems(assets?.email),
  idCard: normalizeAssetItems(assets?.idCard),
  phone: normalizeAssetItems(assets?.phone),
  ipUrl: normalizeAssetItems(assets?.ipUrl),
  apiRoot: normalizeAssetItems(assets?.apiRoot),
  apiRouter: normalizeAssetItems(assets?.apiRouter),
});

const normalizeAssetItems = (items?: AssetValue[]) =>
  (items || []).map((item) => {
    if (typeof item === 'string') {
      return {
        value: item,
        sources: [] as string[],
      };
    }

    const sources = Array.isArray(item.source)
      ? item.source.filter(Boolean)
      : item.source
        ? [item.source]
        : [];

    return {
      value: item.value || '',
      sources,
    };
  });

const formatPreviewValue = (value: unknown): string => {
  if (typeof value === 'string') {
    return value;
  }

  if (value == null) {
    return '';
  }

  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
};

export const formatTreeNodePreview = (node: TreeNode): string => {
  const previewSource =
    node.responseBody ??
    node.requestBody ??
    node.response ??
    node.url ??
    node.label ??
    node.code;
  return formatPreviewValue(previewSource) || '暂无数据';
};

export type ProtocolTraceGroup = {
  id: string;
  label: string;
  algorithms: string[];
  traces: ProtocolTrace[];
};

export type ProtocolTraceStackGroup = {
  id: string;
  label: string;
  traces: ProtocolTrace[];
};

export type ProtocolFlowStep = {
  id: string;
  kind: 'request' | 'response';
  title: string;
  source?: string;
  algorithm?: string;
  input?: string;
  output?: string;
  callId?: string;
  parentCallId?: string;
  functionPath?: string;
  moduleId?: string;
  materialKeys?: string[];
  stack?: string;
  capturedAtMs?: number;
};

export type ProtocolTraceFlow = {
  requestLane: ProtocolFlowStep[];
  responseLane: ProtocolFlowStep[];
  summary: {
    hasRequestLane: boolean;
    hasResponseLane: boolean;
    hasResponseCiphertext: boolean;
    hasResponsePlaintext: boolean;
    finalResponseSource: string;
  };
};

const NO_STACK_FINGERPRINT = '无调用栈';

const normalizePreview = (value?: string) => {
  const normalized = value?.trim();
  return normalized || undefined;
};

const isReadablePlaintext = (value?: string) => {
  const normalized = normalizePreview(value);
  if (!normalized) {
    return false;
  }

  if (
    normalized.startsWith('{') ||
    normalized.startsWith('[') ||
    normalized.startsWith('<')
  ) {
    return true;
  }

  const unquoted =
    normalized.startsWith('"') && normalized.endsWith('"')
      ? normalized.slice(1, -1)
      : normalized;

  if (!unquoted) {
    return false;
  }

  if (/[\u4e00-\u9fff\s]/.test(unquoted)) {
    return true;
  }

  if (/[:{},[\]"]/g.test(unquoted)) {
    return true;
  }

  // Long opaque hex/base64-like payloads are usually transport materials,
  // not user-meaningful plaintext.
  if (/^[A-Fa-f0-9+/=]+$/.test(unquoted) && unquoted.length >= 32) {
    return false;
  }

  return /[A-Za-z]/.test(unquoted);
};

const normalizeStackLine = (line: string) =>
  line
    .trim()
    .replace(/^at\s+/, '')
    .replace(/https?:\/\/[^\s)]+/g, '<url>')
    .replace(/:\d+:\d+/g, '')
    .replace(/:\d+/g, '')
    .replace(/\s+/g, ' ');

export const buildProtocolTraceStackFingerprint = (stack?: string) => {
  const lines = (stack || '')
    .split('\n')
    .map((line) => normalizeStackLine(line))
    .filter(Boolean);

  if (!lines.length) {
    return NO_STACK_FINGERPRINT;
  }

  return lines.slice(0, 2).join(' <- ');
};

export const groupProtocolTracesByStackFingerprint = (
  traces: ProtocolTrace[] = [],
): ProtocolTraceStackGroup[] => {
  const groups = new Map<string, ProtocolTraceStackGroup>();

  traces.forEach((trace) => {
    const id = buildProtocolTraceStackFingerprint(trace.stack);
    if (!groups.has(id)) {
      groups.set(id, {
        id,
        label: id,
        traces: [],
      });
    }

    groups.get(id)?.traces.push(trace);
  });

  return Array.from(groups.values()).sort((left, right) => {
    if (left.id === NO_STACK_FINGERPRINT && right.id !== NO_STACK_FINGERPRINT) {
      return 1;
    }
    if (right.id === NO_STACK_FINGERPRINT && left.id !== NO_STACK_FINGERPRINT) {
      return -1;
    }
    return (
      right.traces.length - left.traces.length ||
      left.label.localeCompare(right.label)
    );
  });
};

const appendSyntheticStep = (
  steps: ProtocolFlowStep[],
  step: ProtocolFlowStep,
) => {
  const duplicate = steps.find(
    (candidate) =>
      candidate.title === step.title &&
      candidate.source === step.source &&
      candidate.algorithm === step.algorithm &&
      candidate.input === step.input &&
      candidate.output === step.output,
  );
  if (!duplicate) {
    steps.push(step);
  }
};

const normalizeFlowValueForMatch = (value?: string) => {
  const normalized = normalizePreview(value);
  if (!normalized) {
    return '';
  }

  let candidate = normalized;
  if (
    (candidate.startsWith('"') && candidate.endsWith('"')) ||
    (candidate.startsWith("'") && candidate.endsWith("'"))
  ) {
    candidate = candidate.slice(1, -1).trim();
  }

  if (/^[0-9a-f]+$/i.test(candidate)) {
    candidate = candidate.toLowerCase();
  }

  return candidate;
};

const flowValuesMatch = (left?: string, right?: string) => {
  const leftValue = normalizeFlowValueForMatch(left);
  const rightValue = normalizeFlowValueForMatch(right);
  return Boolean(leftValue && rightValue && leftValue === rightValue);
};

const findHeaderKeyByValue = (
  headers: Record<string, string> | undefined,
  targetValue?: string,
) => {
  if (!headers || !targetValue) {
    return undefined;
  }

  return Object.entries(headers).find(([, value]) =>
    flowValuesMatch(value, targetValue),
  )?.[0];
};

const toFlowStep = (
  trace: ProtocolTrace,
  kind: 'request' | 'response',
  step: NonNullable<ProtocolTrace['request_steps']>[number],
  index: number,
): ProtocolFlowStep => {
  const source = step.source || 'unknown';
  return {
    id: `${trace.trace_id}-${kind}-${index}`,
    kind,
    title: source,
    source,
    algorithm: step.algorithm,
    input: normalizePreview(step.input_preview),
    output: normalizePreview(step.output_preview),
    callId: step.call_id,
    parentCallId: step.parent_call_id,
    functionPath: step.function_path,
    moduleId: step.module_id,
    stack: normalizePreview(step.stack),
    capturedAtMs: step.captured_at_ms,
  };
};

const buildBackwardLinkedFlow = (
  trace: ProtocolTrace,
  kind: 'request' | 'response',
  rawSteps: NonNullable<ProtocolTrace['request_steps']>,
  targetOutput?: string,
) => {
  if (!targetOutput) {
    return [] as ProtocolFlowStep[];
  }

  const steps = rawSteps
    .map((step, index) => toFlowStep(trace, kind, step, index))
    .sort(
      (left, right) => (left.capturedAtMs || 0) - (right.capturedAtMs || 0),
    );

  if (!steps.length) {
    return [] as ProtocolFlowStep[];
  }

  const chain: ProtocolFlowStep[] = [];
  let currentTarget = targetOutput;
  let searchIndex = steps.length - 1;

  while (searchIndex >= 0 && currentTarget) {
    let matchedIndex = -1;
    for (let index = searchIndex; index >= 0; index--) {
      if (flowValuesMatch(steps[index].output, currentTarget)) {
        matchedIndex = index;
        break;
      }
    }
    if (matchedIndex < 0) {
      break;
    }

    const matchedStep = steps[matchedIndex];
    chain.unshift(matchedStep);
    currentTarget = matchedStep.input || '';
    searchIndex = matchedIndex - 1;
  }

  return chain;
};

export const buildProtocolTraceFlow = (
  trace: ProtocolTrace,
): ProtocolTraceFlow => {
  const requestLane: ProtocolFlowStep[] = [];
  const responseLane: ProtocolFlowStep[] = [];
  const sessionMaterials = trace.session_materials || {};
  const requestHeaders = trace.request_headers || {};

  const requestPlaintext = normalizePreview(trace.request_before_transform);
  const requestCiphertext = normalizePreview(trace.final_request_body);
  const responseCiphertext = normalizePreview(
    sessionMaterials.latest_response_ciphertext,
  );
  const requestKeyHex = normalizePreview(
    sessionMaterials.sm4_key_hex || sessionMaterials.crypto_key_raw,
  );
  const requestNonce = normalizePreview(sessionMaterials.nonce);
  const requestTimestamp = normalizePreview(sessionMaterials.timestamp);
  const requestSignature = normalizePreview(sessionMaterials.signature);
  const requestKeyExchangeHeader = normalizePreview(
    sessionMaterials.key_exchange_header,
  );
  const responsePlaintext = isReadablePlaintext(
    sessionMaterials.latest_response_plaintext,
  )
    ? normalizePreview(sessionMaterials.latest_response_plaintext)
    : undefined;
  const keyDerivationSteps = requestKeyHex
    ? buildBackwardLinkedFlow(
        trace,
        'request',
        trace.request_steps || [],
        requestKeyHex,
      )
    : [];
  const linkedRequestSteps = buildBackwardLinkedFlow(
    trace,
    'request',
    trace.request_steps || [],
    requestCiphertext,
  );
  const linkedResponseSteps = buildBackwardLinkedFlow(
    trace,
    'response',
    trace.response_steps || [],
    responsePlaintext,
  );
  const hasResponseStepChain =
    linkedResponseSteps.length > 0 &&
    (!responseCiphertext ||
      flowValuesMatch(linkedResponseSteps[0]?.input, responseCiphertext));
  const shouldSuppressMirroredRequestPlaintext =
    Boolean(requestPlaintext) &&
    Boolean(responsePlaintext) &&
    requestPlaintext === responsePlaintext &&
    linkedRequestSteps.length === 0 &&
    !requestCiphertext;
  const requestEncryptStepIndex = linkedRequestSteps.findIndex(
    (step) =>
      flowValuesMatch(step.output, requestCiphertext) ||
      /encrypt/i.test(step.algorithm || '') ||
      /encrypt/i.test(step.source || ''),
  );
  const requestStepsBeforeEncrypt =
    requestEncryptStepIndex >= 0
      ? linkedRequestSteps.slice(0, requestEncryptStepIndex)
      : linkedRequestSteps;
  const requestStepsFromEncrypt =
    requestEncryptStepIndex >= 0
      ? linkedRequestSteps.slice(requestEncryptStepIndex)
      : [];

  if (requestPlaintext && !shouldSuppressMirroredRequestPlaintext) {
    appendSyntheticStep(requestLane, {
      id: `${trace.trace_id}-request-plaintext`,
      kind: 'request',
      title: '原始请求明文',
      output: requestPlaintext,
      materialKeys: ['request_before_transform'],
    });
  }

  requestStepsBeforeEncrypt.forEach((step) => {
    requestLane.push(step);
  });

  keyDerivationSteps.forEach((step, index) => {
    appendSyntheticStep(requestLane, {
      ...step,
      id: `${step.id}-key-${index}`,
      materialKeys:
        index === keyDerivationSteps.length - 1
          ? ['sm4_key_hex']
          : step.materialKeys,
    });
  });

  if (requestKeyHex) {
    appendSyntheticStep(requestLane, {
      id: `${trace.trace_id}-request-key`,
      kind: 'request',
      title: 'SM4 密钥',
      source: 'session.materials',
      input: normalizePreview(sessionMaterials.session_seed_b),
      output: requestKeyHex,
      materialKeys: ['sm4_key_hex', 'session_seed_b'].filter((key) =>
        Boolean(sessionMaterials[key]),
      ),
    });
  }

  if (requestNonce) {
    const nonceHeaderKey = findHeaderKeyByValue(requestHeaders, requestNonce);
    appendSyntheticStep(requestLane, {
      id: `${trace.trace_id}-request-nonce`,
      kind: 'request',
      title: 'Nonce / IV',
      source: 'request.headers',
      input: nonceHeaderKey,
      output: requestNonce,
      materialKeys: ['nonce', nonceHeaderKey].filter(Boolean) as string[],
    });
  }

  requestStepsFromEncrypt.forEach((step) => {
    requestLane.push(step);
  });

  const headerAssembly: Record<string, string> = {};
  const headerMaterialKeys: string[] = [];
  (
    [
      ['nonce', requestNonce],
      ['timestamp', requestTimestamp],
      ['signature', requestSignature],
      ['key_exchange_header', requestKeyExchangeHeader],
    ] as Array<[string, string | undefined]>
  ).forEach(([materialKey, value]) => {
    const headerKey = findHeaderKeyByValue(requestHeaders, value);
    if (!headerKey || !value) {
      return;
    }

    headerAssembly[headerKey] = value;
    headerMaterialKeys.push(materialKey, headerKey);
  });

  if (Object.keys(headerAssembly).length > 0) {
    appendSyntheticStep(requestLane, {
      id: `${trace.trace_id}-request-headers`,
      kind: 'request',
      title: '请求头组装',
      source: 'request.headers',
      output: formatPreviewValue(headerAssembly),
      materialKeys: Array.from(new Set(headerMaterialKeys)),
    });
  }

  if (responseCiphertext) {
    responseLane.push({
      id: `${trace.trace_id}-response-cipher`,
      kind: 'response',
      title: '原始响应密文',
      output: responseCiphertext,
      materialKeys: ['latest_response_ciphertext'],
    });
  }

  if (hasResponseStepChain) {
    linkedResponseSteps.forEach((step) => {
      responseLane.push(step);
    });
  }

  if (requestCiphertext) {
    appendSyntheticStep(requestLane, {
      id: `${trace.trace_id}-request-final`,
      kind: 'request',
      title: '最终发包请求体',
      input: requestPlaintext,
      output: requestCiphertext,
      materialKeys: ['final_request_body'],
    });
  }

  if (responsePlaintext) {
    appendSyntheticStep(responseLane, {
      id: `${trace.trace_id}-response-plain`,
      kind: 'response',
      title: '响应明文',
      output: responsePlaintext,
      materialKeys: ['latest_response_plaintext'],
    });
  }

  return {
    requestLane,
    responseLane,
    summary: {
      hasRequestLane: requestLane.length > 0,
      hasResponseLane: responseLane.length > 0,
      hasResponseCiphertext: Boolean(responseCiphertext),
      hasResponsePlaintext: Boolean(responsePlaintext),
      finalResponseSource: responsePlaintext
        ? hasResponseStepChain
          ? '捕获到的响应明文'
          : '捕获到的响应明文（未关联到可验证解密步骤）'
        : '未捕获到响应明文',
    },
  };
};

export const groupProtocolTracesByAlgorithms = (
  traces: ProtocolTrace[] = [],
): ProtocolTraceGroup[] => {
  const groups = new Map<string, ProtocolTraceGroup>();

  traces.forEach((trace) => {
    const algorithms = Array.from(
      new Set((trace.algorithms || []).filter(Boolean)),
    ).sort((left, right) => left.localeCompare(right));
    const id = algorithms.length ? algorithms.join(' | ') : 'unclassified';

    if (!groups.has(id)) {
      groups.set(id, {
        id,
        label: algorithms.length ? algorithms.join(' + ') : '未识别算法',
        algorithms,
        traces: [],
      });
    }

    groups.get(id)?.traces.push(trace);
  });

  return Array.from(groups.values()).sort((left, right) => {
    if (left.algorithms.length === 0 && right.algorithms.length > 0) {
      return 1;
    }
    if (right.algorithms.length === 0 && left.algorithms.length > 0) {
      return -1;
    }
    return (
      right.traces.length - left.traces.length ||
      left.label.localeCompare(right.label)
    );
  });
};

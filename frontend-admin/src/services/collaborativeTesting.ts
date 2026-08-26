import type {
  ApprovalDecision,
  CollaborationSession,
  RuntimeDecryptResult,
} from '@/types/collaborativeTesting';
import { getApiBaseURL } from '@/utils/apiBase';
import request from '@/utils/request';
import { readStoredAuthToken } from '@/utils/session';

type CollaborativeSessionResponse = { data: CollaborationSession };

export const validateCollaborativeTarget = (value: string) => {
  try {
    const url = new URL(value.trim());
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
};

export const createCollaborativeSession = async (
  target: string,
  attachments: File[] = [],
) => {
  if (attachments.length > 0) {
    const payload = new FormData();
    payload.append('target', target.trim());
    attachments.forEach((file) => payload.append('attachments', file));
    const response = await request.post<CollaborativeSessionResponse>(
      '/api/collaborative-tests',
      payload,
    );
    return response.data;
  }
  const response = await request.post<CollaborativeSessionResponse>(
    '/api/collaborative-tests',
    { target: target.trim() },
  );
  return response.data;
};

export const fetchCollaborativeSession = async (sessionId: string) => {
  const response = await request.get<CollaborativeSessionResponse>(
    `/api/collaborative-tests/${sessionId}`,
  );
  return response.data;
};

export const streamCollaborativeSession = (
  sessionId: string,
  handlers: {
    onSession: (session: CollaborationSession) => void;
    onError?: (error: Error) => void;
  },
) => {
  let stopped = false;
  let retryTimer: number | undefined;
  let controller: AbortController | undefined;

  const connect = async () => {
    controller = new AbortController();
    try {
      const token = readStoredAuthToken();
      const response = await fetch(
        `${getApiBaseURL()}/api/collaborative-tests/${sessionId}/events`,
        {
          headers: {
            Accept: 'text/event-stream',
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          signal: controller.signal,
        },
      );
      if (!response.ok || !response.body) {
        throw new Error('协同测试实时连接不可用');
      }

      const reader = response.body
        .pipeThrough(new TextDecoderStream())
        .getReader();
      let buffer = '';
      while (!stopped) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += value;
        const frames = buffer.split('\n\n');
        buffer = frames.pop() || '';
        frames.forEach((frame) => {
          const event = frame.match(/^event:\s*(.+)$/m)?.[1];
          const data = frame
            .split('\n')
            .filter((line) => line.startsWith('data:'))
            .map((line) => line.slice(5).trimStart())
            .join('\n');
          if (event !== 'session' || !data) return;
          try {
            handlers.onSession(JSON.parse(data) as CollaborationSession);
          } catch {
            // Ignore malformed frames; a later full session snapshot recovers.
          }
        });
      }
    } catch (error) {
      if (!stopped && error instanceof Error && error.name !== 'AbortError') {
        handlers.onError?.(error);
      }
    } finally {
      if (!stopped) retryTimer = window.setTimeout(() => void connect(), 1500);
    }
  };

  void connect();
  return () => {
    stopped = true;
    if (retryTimer) window.clearTimeout(retryTimer);
    controller?.abort();
  };
};

export const decideCollaborativeAction = async (
  sessionId: string,
  actionId: string,
  payload: {
    decision: Exclude<ApprovalDecision, 'pending'>;
    note?: string;
    testEnvironment?: string;
    testIdentity?: string;
    authorizationScope?: string;
  },
) => {
  const response = await request.post<CollaborativeSessionResponse>(
    `/api/collaborative-tests/${sessionId}/actions/${actionId}`,
    payload,
  );
  return response.data;
};

export const executeCollaborativeAction = async (
  sessionId: string,
  actionId: string,
  payload: { body?: string; headers?: Record<string, string> },
) => {
  const response = await request.post<CollaborativeSessionResponse>(
    `/api/collaborative-tests/${sessionId}/actions/${actionId}/execute`,
    payload,
  );
  return response.data;
};

export const runtimeDecryptCollaborativeResult = async (
  sessionId: string,
  resultId: string,
): Promise<RuntimeDecryptResult> => {
  const response = await request.post<{
    data: {
      key_hex?: string;
      ciphertext?: string;
      plaintext?: string;
      mode?: string;
      source?: string;
      detail?: string;
      function_hint?: string;
    };
  }>(
    `/api/collaborative-tests/${sessionId}/test-results/${resultId}/runtime-decrypt`,
  );
  const result = response.data;
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

export const stageLabel: Record<CollaborationSession['stage'], string> = {
  collecting: '正在采集',
  analyzing: '正在分析',
  awaiting_approval: '等待审批',
  completed: '已完成',
  failed: '失败',
};

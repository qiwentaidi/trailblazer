import type {
  BrowserSessionDetail,
  BrowserSessionSummary,
  PagedResponse,
} from '@/types/task';
import request from '@/utils/request';

export interface FetchBrowserSessionsFilters {
  keyword?: string;
  status?: string;
  siteHost?: string;
}

export const fetchBrowserSessions = (
  page = 1,
  size = 10,
  filters: FetchBrowserSessionsFilters = {},
) =>
  request.get<PagedResponse<BrowserSessionSummary>>('/api/browser-sessions', {
    params: {
      page,
      size,
      ...(filters.keyword ? { keyword: filters.keyword } : {}),
      ...(filters.status ? { status: filters.status } : {}),
      ...(filters.siteHost ? { siteHost: filters.siteHost } : {}),
    },
  });

type BrowserSessionDetailResponse = {
  data: BrowserSessionDetail;
};

export const fetchBrowserSessionDetail = (sessionId: string) =>
  request.get<BrowserSessionDetailResponse>(
    `/api/browser-sessions/${sessionId}`,
  );

export interface LaunchBrowserSessionPayload {
  targetUrl: string;
  mode?: string;
  browserVisible?: boolean;
  proxyServer?: string;
  proxyBypassList?: string;
  proxyType?: string;
  captureDurationSeconds?: number;
  timeoutSeconds?: number;
}

type LaunchBrowserSessionResponse = {
  data: {
    sessionId: string;
    status: string;
    siteHost: string;
    entryUrl: string;
  };
};

export const launchBrowserSession = (payload: LaunchBrowserSessionPayload) =>
  request.post<LaunchBrowserSessionResponse>(
    '/api/browser-sessions/launch',
    payload,
  );

export const deleteBrowserSession = (sessionId: string) =>
  request.delete(`/api/browser-sessions/${sessionId}`);

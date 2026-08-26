import request from 'umi-request'

import { getApiBaseURL } from './apiBase'
import { clearAuthSession, readStoredAuthToken } from './session'

type RequestOptions = {
  method?: string
  headers?: Record<string, string>
  params?: Record<string, string | number | boolean>
  body?: unknown
  data?: unknown
  timeout?: number
}

type RequestClient = {
  get: <T = unknown>(url: string, options?: RequestOptions) => Promise<T>
  post: <T = unknown>(url: string, body?: unknown, options?: RequestOptions) => Promise<T>
  put: <T = unknown>(url: string, body?: unknown, options?: RequestOptions) => Promise<T>
  patch: <T = unknown>(url: string, body?: unknown, options?: RequestOptions) => Promise<T>
  delete: <T = unknown>(url: string, options?: RequestOptions) => Promise<T>
}

const LOGIN_PATH = '/api/auth/login'
const DEFAULT_TIMEOUT = 15000
const resolveRequestURL = (url: string) => {
  if (/^https?:\/\//i.test(url)) {
    return url
  }
  return `${getApiBaseURL()}${url}`
}

(request as any).interceptors.request.use((url: string, options: RequestOptions) => {
  const token = readStoredAuthToken()
  const data = options.body ?? options.data

  return {
    url,
    options: {
      ...options,
      data: data as unknown,
      headers: {
        ...(options.headers ?? {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    },
  }
});

(request as any).interceptors.response.use(async (response: Response) => {
  if (response.status === 401) {
    const responsePath = new URL(response.url, window.location.origin).pathname

    if (responsePath === LOGIN_PATH) {
      return response
    }

    clearAuthSession()
    window.location.href = '/login'
  }
  return response
});

const baseRequest = request as any

const client: RequestClient = {
  get: (url, options = {}) =>
    baseRequest(resolveRequestURL(url), {
      timeout: DEFAULT_TIMEOUT,
      ...options,
      method: 'GET',
    }) as Promise<any>,
  post: (url, body, options = {}) =>
    baseRequest(resolveRequestURL(url), {
      timeout: DEFAULT_TIMEOUT,
      ...options,
      method: 'POST',
      data: body,
    }) as Promise<any>,
  put: (url, body, options = {}) =>
    baseRequest(resolveRequestURL(url), {
      timeout: DEFAULT_TIMEOUT,
      ...options,
      method: 'PUT',
      data: body,
    }) as Promise<any>,
  patch: (url, body, options = {}) =>
    baseRequest(resolveRequestURL(url), {
      timeout: DEFAULT_TIMEOUT,
      ...options,
      method: 'PATCH',
      data: body,
    }) as Promise<any>,
  delete: (url, options = {}) =>
    baseRequest(resolveRequestURL(url), {
      timeout: DEFAULT_TIMEOUT,
      ...options,
      method: 'DELETE',
    }) as Promise<any>,
}

export default client

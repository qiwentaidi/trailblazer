import request from '@/utils/request'
import type { LoginRequest, LoginResponse, User } from '@/types/auth'

export const login = (payload: LoginRequest) =>
  request.post<LoginResponse>('/api/auth/login', payload)

export const fetchUserInfo = () => request.get<User>('/api/user/info')

export const checkESHealth = () =>
  request.get<{ connected: boolean; message?: string }>('/api/health/es')

import type {
  AuthStatus,
  ChangePasswordRequest,
  InitAccountRequest,
  LoginRequest,
  LoginResponse,
  User,
} from '@/types/auth';
import request from '@/utils/request';

export const getAuthStatus = () => request.get<AuthStatus>('/api/auth/status');

export const initializeAccount = (payload: InitAccountRequest) =>
  request.post<{ message: string }>('/api/auth/initialize', payload);

export const login = (payload: LoginRequest) =>
  request.post<LoginResponse>('/api/auth/login', payload);

export const fetchUserInfo = () => request.get<User>('/api/user/info');

export const changePassword = (payload: ChangePasswordRequest) =>
  request.post<{ message: string }>('/api/auth/change-password', payload);

export const checkESHealth = () =>
  request.get<{ connected: boolean; message?: string }>('/api/health/es');

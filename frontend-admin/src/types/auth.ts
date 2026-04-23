export interface User {
  id: number;
  username: string;
  role: string;
  is_active: boolean;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface AuthStatus {
  initialized: boolean;
}

export interface InitAccountRequest {
  username: string;
  password: string;
}

export interface ChangePasswordRequest {
  oldPassword: string;
  newPassword: string;
}

export interface LoginResponse {
  token: string;
  username: string;
  role: string;
  message: string;
}

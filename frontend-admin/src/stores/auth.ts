import { create } from 'zustand'

import * as authService from '@/services/auth'
import type { LoginRequest, User } from '@/types/auth'
import {
  clearAuthSession,
  persistStoredAuthToken,
  readStoredAuthToken,
  registerAuthSessionClearHandler,
} from '@/utils/session'

interface AuthState {
  token: string | null
  user: User | null
  loading: boolean
  initialize: () => Promise<boolean>
  login: (payload: LoginRequest) => Promise<boolean>
  logout: () => void
}

const getErrorStatus = (error: unknown) =>
  (error as {
    response?: { status?: number }
    status?: number
  })?.response?.status ?? (error as { status?: number })?.status

export const useAuthStore = create<AuthState>((set) => ({
  token: readStoredAuthToken(),
  user: null,
  loading: false,
  initialize: async () => {
    const token = readStoredAuthToken()
    if (!token) return false

    try {
      const user = await authService.fetchUserInfo()
      if (readStoredAuthToken() !== token) return false

      set({ token, user })
      persistStoredAuthToken(token)
      return true
    } catch (error) {
      if (readStoredAuthToken() !== token) return false

      if (getErrorStatus(error) === 401) {
        clearAuthSession()
        set({ token: null, user: null })
        return false
      }

      set({ token, user: null })
      return true
    }
  },
  login: async (payload) => {
    set({ loading: true })
    try {
      const result = await authService.login(payload)
      persistStoredAuthToken(result.token)
      set({
        token: result.token,
        user: {
          id: 0,
          username: result.username,
          role: result.role,
          is_active: true,
        },
        loading: false,
      })
      return true
    } catch {
      set({ loading: false })
      return false
    }
  },
  logout: () => {
    clearAuthSession()
    set({ token: null, user: null })
  },
}))

registerAuthSessionClearHandler(() => {
  useAuthStore.setState({ token: null, user: null, loading: false })
})

export default useAuthStore

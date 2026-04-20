const AUTH_TOKEN_KEY = 'auth_token'
const LEGACY_AUTH_TOKEN_KEY = 'app-auth-token'

const clearHandlers = new Set<() => void>()

export const readStoredAuthToken = () => {
  return (
    localStorage.getItem(AUTH_TOKEN_KEY) ||
    localStorage.getItem(LEGACY_AUTH_TOKEN_KEY)
  )
}

export const persistStoredAuthToken = (token: string) => {
  localStorage.setItem(AUTH_TOKEN_KEY, token)
  localStorage.setItem(LEGACY_AUTH_TOKEN_KEY, token)
}

export const clearStoredAuthTokens = () => {
  localStorage.removeItem(AUTH_TOKEN_KEY)
  localStorage.removeItem(LEGACY_AUTH_TOKEN_KEY)
}

export const registerAuthSessionClearHandler = (handler: () => void) => {
  clearHandlers.add(handler)
  return () => clearHandlers.delete(handler)
}

export const clearAuthSession = () => {
  clearStoredAuthTokens()
  clearHandlers.forEach((handler) => {
    handler()
  })
}

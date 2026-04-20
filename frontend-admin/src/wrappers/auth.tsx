import { Spin } from 'antd'
import { useEffect, useState } from 'react'
import { Navigate, Outlet } from 'umi'

import adminService from '@/services/admin'
import { useAuthStore } from '@/stores/auth'
import useGlobalStore from '@/store/useGlobalStore'
import { readStoredAuthToken } from '@/utils/session'

export default function AuthWrapper({ children }: { children: React.ReactNode }) {
  const initialize = useAuthStore((state) => state.initialize)
  const token = useAuthStore((state) => state.token)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    let active = true
    initialize().finally(() => {
      if (active) setReady(true)
    })

    return () => {
      active = false
    }
  }, [initialize])

  useEffect(() => {
    if (!ready || !token) return

    let active = true
    const sessionToken = readStoredAuthToken()

    ;(async () => {
      try {
        const admin = await adminService.currentAdmin()
        if (!active || !admin || readStoredAuthToken() !== sessionToken) return
        useGlobalStore.getState().setCurrentUser(admin)
      } catch {
        // Best-effort only: keep the authenticated session even if the
        // secondary admin bootstrap fails.
      }
    })()

    return () => {
      active = false
    }
  }, [ready, token])

  if (!ready) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Spin size="large" />
      </div>
    )
  }

  if (!token) {
    return <Navigate to="/login" replace />
  }

  return <>{children || <Outlet />}</>
}

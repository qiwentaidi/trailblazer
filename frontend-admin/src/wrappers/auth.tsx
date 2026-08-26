import { Spin } from 'antd';
import { useEffect, useState } from 'react';
import { Navigate, Outlet } from 'umi';

import { useAuthStore } from '@/stores/auth';

export default function AuthWrapper({
  children,
}: {
  children: React.ReactNode;
}) {
  const initialize = useAuthStore((state) => state.initialize);
  const token = useAuthStore((state) => state.token);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let active = true;
    initialize().finally(() => {
      if (active) setReady(true);
    });

    return () => {
      active = false;
    };
  }, [initialize]);

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
    );
  }

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  return <>{children || <Outlet />}</>;
}

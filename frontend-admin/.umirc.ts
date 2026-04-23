import { defineConfig } from 'umi';

export default defineConfig({
  esbuildMinifyIIFE: true,
  routes: [
    { path: '/login', component: '@/pages/login' },
    {
      path: '/',
      wrappers: ['@/wrappers/auth'],
      routes: [
        { path: '/', redirect: '/dashboard' },
        { path: '/dashboard', component: '@/pages/dashboard' },
        { path: '/tasks', component: '@/pages/tasks' },
        { path: '/tasks/:id', component: '@/pages/tasks/detail/[id]' },
        { path: '/browser-sessions', component: '@/pages/browser-sessions' },
        {
          path: '/browser-sessions/:id',
          component: '@/pages/browser-sessions/detail/[id]',
        },
        { path: '/search', component: '@/pages/search' },
        { path: '/settings', component: '@/pages/settings' },
      ],
    },
  ],
});

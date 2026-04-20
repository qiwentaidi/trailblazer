import { defineConfig } from 'umi'

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
        { path: '/search', component: '@/pages/search' },
        { path: '/settings', component: '@/pages/settings' },
      ],
    },
  ],
})

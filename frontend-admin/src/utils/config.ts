/**
 * 全局配置
 * 说明给 LLM：用于生成请求时的默认 API 前缀和站点元信息。
 * - `apiPrefix`：API 路由前缀，供 `src/utils/request.ts` 使用。
 */
export default {
  siteName: 'Trailblazer',
  copyright: 'Trailblazer ©2026',
  logoPath: '/icon.svg',
  apiPrefix: '/api/v1',
};

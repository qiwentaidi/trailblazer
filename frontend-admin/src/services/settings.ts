import request from '@/utils/request'
import type {
  LFISettings,
  OpenAISettings,
  RedirectSettings,
  SettingsConfig,
  SQLInjectionSettings,
  SSRFSettings,
  SystemStatus,
  UploadSettings,
  VulnDetectionSettings,
  XSSSettings,
} from '@/types/settings'

const DEFAULT_OPENAI: OpenAISettings = {
  api_key: '',
  base_url: 'https://api.openai.com/v1',
  model: 'qwen-plus',
  enabled: false,
}

const DEFAULT_SQLI: SQLInjectionSettings = {
  enabled: true,
  payloads: [],
  matchKeywords: [],
  rules: [],
}

const DEFAULT_LFI: LFISettings = {
  enabled: true,
  paramKeywords: ['file', 'include', 'path', 'doc', 'template', 'view', 'filepath'],
  payloads: [],
  matchKeywords: [],
  rules: [],
}

const DEFAULT_SSRF: SSRFSettings = {
  enabled: true,
  paramKeywords: ['url', 'link', 'src', 'target'],
}

const DEFAULT_REDIRECT: RedirectSettings = {
  enabled: true,
  paramKeywords: ['url', 'redirect', 'return_url', 'next'],
}

const DEFAULT_XSS: XSSSettings = {
  enabled: true,
  payloads: [],
  matchKeywords: [],
  rules: [],
}

const DEFAULT_UPLOAD: UploadSettings = {
  enabled: true,
  paramKeywords: [],
  testContent: '<h1>uploadtest</h1>',
  testFileName: 'test.html',
}

const DEFAULT_VULN_DETECTION: VulnDetectionSettings = {
  enabled: true,
  sqlInjection: DEFAULT_SQLI,
  lfi: DEFAULT_LFI,
  ssrf: DEFAULT_SSRF,
  redirect: DEFAULT_REDIRECT,
  xss: DEFAULT_XSS,
  upload: DEFAULT_UPLOAD,
}

const DEFAULT_SETTINGS: SettingsConfig = {
  openai: DEFAULT_OPENAI,
  blackDomain: [],
  highRiskRouter: [],
  authentication: [],
  placeholder: {},
  vulnDetection: DEFAULT_VULN_DETECTION,
}

const normalizeStringArray = (
  value: unknown,
  fallback: string[] = [],
) => (Array.isArray(value) ? value.filter((item) => typeof item === 'string') : fallback.slice())

const normalizeStringRecord = (
  value: unknown,
  fallback: Record<string, string> = {},
) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { ...fallback }
  }

  return Object.entries(value as Record<string, unknown>).reduce<Record<string, string>>(
    (acc, [key, nextValue]) => {
      if (typeof nextValue === 'string') {
        acc[key] = nextValue
      }
      return acc
    },
    { ...fallback },
  )
}

const normalizeOpenAI = (
  value: Partial<OpenAISettings> | undefined,
): OpenAISettings => {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {}

  return {
    api_key: typeof source.api_key === 'string' ? source.api_key : DEFAULT_OPENAI.api_key,
    base_url: typeof source.base_url === 'string' ? source.base_url : DEFAULT_OPENAI.base_url,
    model: typeof source.model === 'string' ? source.model : DEFAULT_OPENAI.model,
    enabled: typeof source.enabled === 'boolean' ? source.enabled : DEFAULT_OPENAI.enabled,
  }
}

const normalizeSQLi = (value: Partial<SQLInjectionSettings> | undefined): SQLInjectionSettings => ({
  ...DEFAULT_SQLI,
  ...value,
  payloads: normalizeStringArray(value?.payloads, DEFAULT_SQLI.payloads),
  matchKeywords: normalizeStringArray(
    value?.matchKeywords,
    DEFAULT_SQLI.matchKeywords,
  ),
  rules: Array.isArray(value?.rules) ? value.rules.map((rule) => ({
    payloads: normalizeStringArray(rule?.payloads),
    type: typeof rule?.type === 'string' ? rule.type : 'error-based',
    minDelayMs: typeof rule?.minDelayMs === 'number' ? rule.minDelayMs : 0,
    bodyContains: normalizeStringArray(rule?.bodyContains),
  })) : [],
})

const normalizeLFI = (value: Partial<LFISettings> | undefined): LFISettings => ({
  ...DEFAULT_LFI,
  ...value,
  paramKeywords: normalizeStringArray(
    value?.paramKeywords,
    DEFAULT_LFI.paramKeywords,
  ),
  payloads: normalizeStringArray(value?.payloads, DEFAULT_LFI.payloads),
  matchKeywords: normalizeStringArray(
    value?.matchKeywords,
    DEFAULT_LFI.matchKeywords,
  ),
  rules: Array.isArray(value?.rules) ? value.rules.map((rule) => ({
    payloads: normalizeStringArray(rule?.payloads),
    matchType: typeof rule?.matchType === 'string' ? rule.matchType : 'regex',
    regex: normalizeStringArray(rule?.regex),
    words: normalizeStringArray(rule?.words),
    condition: typeof rule?.condition === 'string' ? rule.condition : 'or',
  })) : [],
})

const normalizeSSRF = (value: Partial<SSRFSettings> | undefined): SSRFSettings => ({
  ...DEFAULT_SSRF,
  ...value,
  paramKeywords: normalizeStringArray(
    value?.paramKeywords,
    DEFAULT_SSRF.paramKeywords,
  ),
})

const normalizeRedirect = (
  value: Partial<RedirectSettings> | undefined,
): RedirectSettings => ({
  ...DEFAULT_REDIRECT,
  ...value,
  paramKeywords: normalizeStringArray(
    value?.paramKeywords,
    DEFAULT_REDIRECT.paramKeywords,
  ),
})

const normalizeXSS = (value: Partial<XSSSettings> | undefined): XSSSettings => ({
  ...DEFAULT_XSS,
  ...value,
  payloads: normalizeStringArray(value?.payloads, DEFAULT_XSS.payloads),
  matchKeywords: normalizeStringArray(
    value?.matchKeywords,
    DEFAULT_XSS.matchKeywords,
  ),
  rules: Array.isArray(value?.rules) ? value.rules.map((rule) => ({
    payloads: normalizeStringArray(rule?.payloads),
    payload: typeof rule?.payload === 'string' ? rule.payload : undefined,
    type: typeof rule?.type === 'string' ? rule.type : 'reflected',
    statusEquals: typeof rule?.statusEquals === 'number' ? rule.statusEquals : 0,
    words: normalizeStringArray(rule?.words),
    condition: typeof rule?.condition === 'string' ? rule.condition : undefined,
    headerContains: normalizeStringRecord(rule?.headerContains),
    bodyContains: normalizeStringArray(rule?.bodyContains),
  })) : [],
})

const normalizeUpload = (
  value: Partial<UploadSettings> | undefined,
): UploadSettings => ({
  ...DEFAULT_UPLOAD,
  ...value,
  paramKeywords: normalizeStringArray(
    value?.paramKeywords,
    DEFAULT_UPLOAD.paramKeywords,
  ),
})

const normalizeVulnDetection = (
  value: Partial<VulnDetectionSettings> | undefined,
): VulnDetectionSettings => ({
  enabled: typeof value?.enabled === 'boolean' ? value.enabled : true,
  sqlInjection: normalizeSQLi(value?.sqlInjection),
  lfi: normalizeLFI(value?.lfi),
  ssrf: normalizeSSRF(value?.ssrf),
  redirect: normalizeRedirect(value?.redirect),
  xss: normalizeXSS(value?.xss),
  upload: normalizeUpload(value?.upload),
})

export const createDefaultSettings = (): SettingsConfig => ({
  openai: { ...DEFAULT_SETTINGS.openai },
  blackDomain: [...DEFAULT_SETTINGS.blackDomain],
  highRiskRouter: [...DEFAULT_SETTINGS.highRiskRouter],
  authentication: [...DEFAULT_SETTINGS.authentication],
  placeholder: { ...DEFAULT_SETTINGS.placeholder },
  vulnDetection: normalizeVulnDetection(DEFAULT_SETTINGS.vulnDetection),
})

export const normalizeSettings = (
  value: Partial<SettingsConfig> | undefined,
): SettingsConfig => ({
  openai: normalizeOpenAI(value?.openai),
  blackDomain: normalizeStringArray(value?.blackDomain, DEFAULT_SETTINGS.blackDomain),
  highRiskRouter: normalizeStringArray(
    value?.highRiskRouter,
    DEFAULT_SETTINGS.highRiskRouter,
  ),
  authentication: normalizeStringArray(
    value?.authentication,
    DEFAULT_SETTINGS.authentication,
  ),
  placeholder: normalizeStringRecord(value?.placeholder, DEFAULT_SETTINGS.placeholder),
  vulnDetection: normalizeVulnDetection(value?.vulnDetection),
})

export const getSettings = async (): Promise<SettingsConfig> => {
  const response = await request.get<{ data?: SettingsConfig }>('/api/config')
  return normalizeSettings(response?.data)
}

export const saveSettings = async (settings: SettingsConfig) =>
  request.post('/api/config', settings)

export const checkEsHealth = async (): Promise<SystemStatus> =>
  request.get<SystemStatus>('/api/health/es')

export default {
  createDefaultSettings,
  normalizeSettings,
  getSettings,
  saveSettings,
  checkEsHealth,
}

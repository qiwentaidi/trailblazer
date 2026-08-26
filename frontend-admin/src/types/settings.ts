export interface OpenAISettings {
  api_key: string
  base_url: string
  model: string
  enabled: boolean
}

export interface SQLiPayloadRule {
  payloads: string[]
  type: 'error-based' | 'boolean-based' | string
  bodyContains: string[]
}

export interface SQLInjectionSettings {
  enabled: boolean
  payloads: string[]
  matchKeywords: string[]
  rules: SQLiPayloadRule[]
}

export interface LFIPayloadRule {
  payloads: string[]
  matchType: 'regex' | 'word' | string
  regex: string[]
  words: string[]
  condition: 'and' | 'or' | string
}

export interface LFISettings {
  enabled: boolean
  paramKeywords: string[]
  payloads: string[]
  matchKeywords: string[]
  rules: LFIPayloadRule[]
}

export interface SSRFSettings {
  enabled: boolean
  paramKeywords: string[]
}

export interface RedirectSettings {
  enabled: boolean
  paramKeywords: string[]
}

export interface XSSPayloadRule {
  payloads: string[]
  payload?: string
  type: 'reflected' | 'dom-based' | string
  statusEquals: number
  words?: string[]
  condition?: 'and' | 'or' | string
  headerContains: Record<string, string>
  bodyContains?: string[]
}

export interface XSSSettings {
  enabled: boolean
  payloads: string[]
  matchKeywords: string[]
  rules: XSSPayloadRule[]
}

export interface UploadSettings {
  enabled: boolean
  paramKeywords: string[]
  testContent: string
  testFileName: string
}

export interface VulnDetectionSettings {
  enabled: boolean
  sqlInjection: SQLInjectionSettings
  lfi: LFISettings
  ssrf: SSRFSettings
  redirect: RedirectSettings
  xss: XSSSettings
  upload: UploadSettings
}

export interface SettingsConfig {
  openai: OpenAISettings
  blackDomain: string[]
  highRiskRouter: string[]
  authentication: string[]
  learnedAuthentication: string[]
  placeholder: Record<string, string>
  vulnDetection: VulnDetectionSettings
}

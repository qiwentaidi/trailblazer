import {
  checkEsHealth,
  createDefaultSettings,
  getSettings,
  saveSettings,
} from './settings'
import request from '@/utils/request'

jest.mock('@/utils/request', () => ({
  __esModule: true,
  default: {
    get: jest.fn(),
    post: jest.fn(),
  },
}))

describe('settings service', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  test('builds the admin settings defaults used by the settings page', () => {
    const settings = createDefaultSettings()

    expect(settings.openai).toEqual({
      api_key: '',
      base_url: 'https://api.openai.com/v1',
      model: 'qwen-plus',
      enabled: false,
    })
    expect(settings.vulnDetection.sqlInjection.rules).toEqual([])
    expect(settings.vulnDetection.enabled).toBe(true)
    expect(settings.vulnDetection.lfi.paramKeywords).toEqual([
      'file',
      'include',
      'path',
      'doc',
      'template',
      'view',
      'filepath',
    ])
    expect(settings.vulnDetection.upload).toEqual({
      enabled: true,
      paramKeywords: [],
      testContent: '<h1>uploadtest</h1>',
      testFileName: 'test.html',
    })
    expect(settings.learnedAuthentication).toEqual([])
  })

  test('loads settings from the config endpoint', async () => {
    await getSettings()

    expect(request.get).toHaveBeenCalledWith('/api/config')
  })

  test('normalizes the config payload from the response data envelope', async () => {
    ;(request.get as jest.Mock).mockResolvedValueOnce({
      data: {
        openai: {
          api_key: 'key',
          enabled: true,
        },
        blackDomain: ['a', 1, 'b'],
        learnedAuthentication: ['请先完成统一身份认证后再访问', 1],
        vulnDetection: {
          enabled: false,
        },
      },
    })

    const settings = await getSettings()

    expect(settings.openai).toEqual({
      api_key: 'key',
      base_url: 'https://api.openai.com/v1',
      model: 'qwen-plus',
      enabled: true,
    })
    expect(settings.blackDomain).toEqual(['a', 'b'])
    expect(settings.learnedAuthentication).toEqual(['请先完成统一身份认证后再访问'])
    expect(settings.vulnDetection.enabled).toBe(false)
  })

  test('saves settings back to the config endpoint', async () => {
    const settings = createDefaultSettings()

    await saveSettings(settings)

    expect(request.post).toHaveBeenCalledWith('/api/config', settings)
  })

  test('checks the es health endpoint', async () => {
    await checkEsHealth()

    expect(request.get).toHaveBeenCalledWith('/api/health/es')
  })
})

import request from '@/utils/request'

import {
  createSearchRule,
  deleteSearchRule,
  fetchSearchRules,
  searchJSContent,
} from './search'

jest.mock('@/utils/request', () => ({
  __esModule: true,
  default: {
    get: jest.fn(),
    post: jest.fn(),
    delete: jest.fn(),
  },
}))

describe('search service', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  test('searches js content through the existing backend endpoint', async () => {
    await searchJSContent({
      pattern: 'token',
      isRegex: false,
      caseSensitive: true,
    })

    expect(request.post).toHaveBeenCalledWith('/api/search/js', {
      pattern: 'token',
      isRegex: false,
      caseSensitive: true,
    }, {
      timeout: 120000,
    })
  })

  test('loads saved js search rules', async () => {
    ;(request.get as jest.Mock).mockResolvedValue({
      data: [{ id: 1, label: 'Token', value: 'token' }],
    })

    const result = await fetchSearchRules()

    expect(request.get).toHaveBeenCalledWith('/api/search/js/rules')
    expect(result).toEqual([{ id: 1, label: 'Token', value: 'token' }])
  })

  test('creates a saved search rule', async () => {
    await createSearchRule({
      label: '解密函数',
      value: 'decrypt\\(',
    })

    expect(request.post).toHaveBeenCalledWith('/api/search/js/rules', {
      label: '解密函数',
      value: 'decrypt\\(',
    })
  })

  test('deletes a saved search rule', async () => {
    await deleteSearchRule(7)

    expect(request.delete).toHaveBeenCalledWith('/api/search/js/rules/7')
  })
})

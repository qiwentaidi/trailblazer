import request from '@/utils/request'

export interface SearchMatch {
  line: number
  content: string
  matchStart: number
  matchEnd: number
  originalText: string
}

export interface SearchResult {
  id: string
  url: string
  taskId: string
  matches: SearchMatch[]
  totalMatches: number
}

export interface SearchRule {
  id?: number
  label: string
  value: string
  created_at?: string
}

export interface SearchPayload {
  pattern: string
  isRegex: boolean
  caseSensitive: boolean
}

type SearchResultResponse = {
  data?: SearchResult[]
}

type SearchRuleResponse = {
  data?: SearchRule[]
}

type CreateSearchRuleResponse = {
  data?: {
    id?: number
  }
}

export const searchJSContent = (payload: SearchPayload) =>
  request.post<SearchResultResponse>('/api/search/js', payload, {
    timeout: 120000,
  })

export const fetchSearchRules = async (): Promise<SearchRule[]> => {
  const response = await request.get<SearchRuleResponse>('/api/search/js/rules')
  return response?.data || []
}

export const createSearchRule = (payload: Pick<SearchRule, 'label' | 'value'>) =>
  request.post<CreateSearchRuleResponse>('/api/search/js/rules', payload)

export const deleteSearchRule = (id: number) =>
  request.delete(`/api/search/js/rules/${id}`)

export default {
  searchJSContent,
  fetchSearchRules,
  createSearchRule,
  deleteSearchRule,
}

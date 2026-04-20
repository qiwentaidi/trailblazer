import { formatDateTime } from './datetime'

describe('formatDateTime', () => {
  test('treats timezone-less timestamps as Shanghai local time', () => {
    expect(formatDateTime('2026-04-14 11:33:47')).toBe(
      '2026-04-14 11:33:47',
    )
  })

  test('formats timestamps with fractional seconds into plain display time', () => {
    expect(formatDateTime('2026-04-14T11:33:47.412461+08:00')).toBe(
      '2026-04-14 11:33:47',
    )
  })

  test('converts other offsets into Shanghai time', () => {
    expect(formatDateTime('2026-04-14T03:33:47.123456Z')).toBe(
      '2026-04-14 11:33:47',
    )
  })

  test('returns a fallback dash for empty values', () => {
    expect(formatDateTime('')).toBe('-')
    expect(formatDateTime(undefined)).toBe('-')
  })
})
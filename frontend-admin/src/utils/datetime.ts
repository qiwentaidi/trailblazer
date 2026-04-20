const pad = (value: number, width = 2) => String(value).padStart(width, '0')

const SHANGHAI_OFFSET = '+08:00'

const normalizeOffset = (value: string) => {
  if (/^[+-]\d{2}:\d{2}$/.test(value)) {
    return value
  }
  if (/^[+-]\d{4}$/.test(value)) {
    return `${value.slice(0, 3)}:${value.slice(3)}`
  }
  if (value === 'Z') {
    return '+00:00'
  }
  return value
}

const normalizeInput = (value: string) =>
  {
    const trimmed = value.trim().replace(' ', 'T')
    const normalizedOffset = trimmed.replace(/([+-]\d{4}|Z)$/, (_, offset) => normalizeOffset(offset))

    if (!/(Z|[+-]\d{2}:?\d{2})$/.test(normalizedOffset)) {
      return `${normalizedOffset}${SHANGHAI_OFFSET}`
    }

    return normalizedOffset
  }

const formatShanghaiParts = (date: Date) => {
  const formatter = new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  })

  const parts = formatter.formatToParts(date)
  const find = (type: Intl.DateTimeFormatPartTypes) =>
    parts.find((part) => part.type === type)?.value || ''

  return {
    year: find('year'),
    month: find('month'),
    day: find('day'),
    hour: find('hour'),
    minute: find('minute'),
    second: find('second'),
  }
}

export const formatDateTime = (value?: string | null) => {
  if (!value) {
    return '-'
  }

  const normalized = normalizeInput(value)
  const parsed = new Date(normalized)
  if (Number.isNaN(parsed.getTime())) {
    return value
  }

  const shanghai = formatShanghaiParts(parsed)

  return `${shanghai.year}-${shanghai.month}-${shanghai.day} ${shanghai.hour}:${shanghai.minute}:${shanghai.second}`
}

export default formatDateTime
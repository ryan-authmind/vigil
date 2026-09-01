import { describe, expect, it } from 'vitest'
import { formatRelative } from './FederationSection'

describe('formatRelative', () => {
  const now = Date.parse('2026-08-17T16:26:33Z')

  it('treats timezone-naive API timestamps as UTC', () => {
    expect(formatRelative('2026-08-17T16:24:55.859678', now)).toBe('1m ago')
  })

  it('preserves timestamps with an explicit timezone', () => {
    expect(formatRelative('2026-08-17T09:24:55-07:00', now)).toBe('1m ago')
  })

  it('never renders a negative age for future timestamps', () => {
    expect(formatRelative('2026-08-17T16:30:00Z', now)).toBe('0s ago')
  })

  it('renders missing or invalid timestamps as never', () => {
    expect(formatRelative(null, now)).toBe('never')
    expect(formatRelative('invalid', now)).toBe('never')
  })
})

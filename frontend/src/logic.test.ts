import { describe, expect, it } from 'vitest'
import { buildMessages, describeHttpError, routeLabel } from './logic'

describe('request construction', () => {
  const history = [
    { role: 'user' as const, content: 'Earlier' },
    { role: 'assistant' as const, content: 'Answer' },
  ]
  it('sends only the current turn for routing tests', () => {
    expect(buildMessages('single', history, 'Now')).toEqual([{ role: 'user', content: 'Now' }])
  })
  it('resends selected history for continuous chat', () => {
    expect(buildMessages('chat', history, 'Now')).toEqual([
      ...history,
      { role: 'user', content: 'Now' },
    ])
  })
})

describe('visible errors and route identity', () => {
  it.each([
    [403, 'The request was denied.'],
    [409, 'The conversation is busy. Retry after the active request finishes.'],
    [410, 'The conversation is closed. Start a new conversation.'],
    [502, 'The upstream provider failed.'],
    [503, 'A required gateway service is unavailable.'],
    [504, 'The upstream provider timed out.'],
  ])('describes HTTP %i in English', (status, expected) => {
    expect(describeHttpError(status)).toBe(expected)
  })
  it('uses the server error code when it gives a more precise reason', () => {
    expect(describeHttpError(409, 'CONVERSATION_BUSY')).toContain('Retry with the same ID')
    expect(describeHttpError(503, 'AUDIT_UNAVAILABLE')).toBe('Audit storage is unavailable.')
  })
  it('identifies simulated local routing by actual destination', () => {
    expect(routeLabel('LOCAL', 'EXTERNAL', true)).toBe('Cloud-simulated local route')
  })
})

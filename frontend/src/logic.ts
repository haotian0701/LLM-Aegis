export type Message = { role: 'user' | 'assistant'; content: string }
export type SendMode = 'single' | 'chat'

export function buildMessages(mode: SendMode, history: Message[], text: string): Message[] {
  return mode === 'single'
    ? [{ role: 'user', content: text }]
    : [...history, { role: 'user', content: text }]
}

export function describeHttpError(status: number, code?: string | null): string {
  const descriptions: Record<string, string> = {
    POLICY_BLOCKED: 'The policy blocked this request before model dispatch.',
    CONVERSATION_BUSY: 'This conversation is processing another request. Retry with the same ID.',
    CONVERSATION_CLOSED: 'This conversation is closed. Start a new conversation.',
    PROVIDER_ERROR: 'The selected model provider failed.',
    PROVIDER_TIMEOUT: 'The selected model provider timed out.',
    SECURITY_UNAVAILABLE: 'Security detection or masking could not complete.',
    ROUTE_UNAVAILABLE: 'The selected route has no configured provider.',
    LOCAL_UNAVAILABLE: 'No local provider is available.',
    AUDIT_UNAVAILABLE: 'Audit storage is unavailable.',
    UNAUTHORIZED: 'The temporary demo session is invalid. Reload the page.',
  }
  if (code && descriptions[code]) return descriptions[code]
  if (status === 403) return 'The request was denied.'
  if (status === 409) return 'The conversation is busy. Retry after the active request finishes.'
  if (status === 410) return 'The conversation is closed. Start a new conversation.'
  if (status === 502) return 'The upstream provider failed.'
  if (status === 503) return 'A required gateway service is unavailable.'
  if (status === 504) return 'The upstream provider timed out.'
  return `Request failed (HTTP ${status}).`
}

export function routeLabel(
  action: string | null,
  destination: string,
  simulation: boolean,
): string {
  if (!action) return 'No policy decision'
  if (action === 'LOCAL' && destination === 'EXTERNAL' && simulation) {
    return 'Cloud-simulated local route'
  }
  if (action === 'MASK_CLOUD') return 'Masked cloud route'
  if (action === 'BLOCK') return 'Blocked by policy'
  if (action === 'CLOUD') return 'Cloud route'
  return 'Local route'
}

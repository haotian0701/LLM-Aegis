import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { buildMessages, describeHttpError, routeLabel, type Message, type SendMode } from './logic'
import styles from './App.module.css'

type Bootstrap = { token: string; models: string[]; local_mode: string }
type WorkspaceBootstrap = { token: string; models: string[]; root: string }
type Source = { source: string; version: string }
type AuditStep = {
  step_id: string
  sequence: number
  kind: string
  source: string
  target: string
  input_summary: string
  policy_version: string
  matched_rules: string[]
  data_categories: string[]
  decision: string
  execution_status: string
  executed: boolean | null
  actual_destination: string
  started_at: string | null
  finished_at: string | null
  error_code: string | null
}
type Audit = {
  request_id: string
  conversation_id: string | null
  status: string
  policy_action: string | null
  actual_destination: string
  simulation: boolean
  detected_categories: string[]
  detection_status: string
  semantic_call_status: string | null
  masking_status: string | null
  model_call_status: string | null
  error_code: string | null
  started_at: string | null
  finished_at: string | null
  conversation_state_before: string | null
  conversation_state_after: string | null
  conversation_state_version: number | null
  provider_name: string | null
  provider_model: string | null
  detector_durations_ms: Record<string, number> | null
  total_duration_ms: number | null
  masked_messages: Array<Record<string, unknown>> | null
  task_type?: string
  steps?: AuditStep[] | null
}
type Conversation = {
  conversation_id: string
  state: string
  state_version: number
  active_request: boolean
  updated_at: string | null
}
type Result = {
  kind: 'CHAT' | 'AGENT'
  httpStatus: number
  content: string | null
  code: string | null
  requestId: string | null
  conversationId: string | null
  action: string | null
  destination: string
  simulation: boolean
  workflowStatus: string | null
  sources: Source[]
}
type Filters = { policy_action: string; status: string; conversation_id: string }

const examples = [
  {
    key: 'CLOUD',
    title: 'Cloud',
    text: 'Hello, please reply with a short greeting.',
    tone: 'blue',
  },
  {
    key: 'MASK_CLOUD',
    title: 'Mask + cloud',
    text: 'Please greet demo.user@example.com.',
    tone: 'violet',
  },
  { key: 'BLOCK', title: 'Block', text: 'api_key=abcdefghijklmnop12345', tone: 'red' },
  {
    key: 'LOCAL',
    title: 'Local follow-up',
    text: 'Hello again. What route handles this turn?',
    tone: 'amber',
  },
] as const

const blankFilters: Filters = { policy_action: '', status: '', conversation_id: '' }
type SectionId = 'workspace' | 'decision' | 'audit' | 'conversation'
const sectionIds: SectionId[] = ['workspace', 'decision', 'audit', 'conversation']
const sectionFromHash = (): SectionId => {
  const hash = window.location.hash.slice(1)
  return sectionIds.find((section) => section === hash) ?? 'workspace'
}

const shown = (value: string | number | null | undefined) =>
  value === null || value === undefined || value === '' ? '—' : String(value)
const time = (value: string | null | undefined) =>
  value
    ? new Date(value).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'medium' })
    : '—'

function Field({
  label,
  value,
  copy,
}: {
  label: string
  value: string | number | null | undefined
  copy?: boolean
}) {
  return (
    <div className={styles.field}>
      <span>{label}</span>
      <div className={styles.fieldValue}>
        <strong title={String(value ?? '')}>{shown(value)}</strong>
        {copy && value && (
          <button
            className={styles.copy}
            type="button"
            onClick={() => void navigator.clipboard.writeText(String(value))}
            aria-label={`Copy ${label}`}
          >
            Copy
          </button>
        )}
      </div>
    </div>
  )
}

function StatusPill({ value, kind }: { value: string | null; kind?: string }) {
  const tone =
    value === 'BLOCK' || value === 'BLOCKED' || value === 'FAILED'
      ? styles.danger
      : value === 'LOCAL' || value === 'MASK_CLOUD' || kind === 'warning'
        ? styles.warning
        : value === 'CLOUD' || value === 'SUCCEEDED'
          ? styles.success
          : styles.neutral
  return <span className={`${styles.pill} ${tone}`}>{value ?? 'Not decided'}</span>
}

function AuditDetails({ audit }: { audit: Audit }) {
  return (
    <div className={styles.auditDetail} aria-live="polite">
      <div className={styles.detailHeading}>
        <div>
          <span className={styles.eyebrow}>SELECTED AUDIT RECORD</span>
          <h3>{audit.request_id}</h3>
        </div>
        <StatusPill value={audit.policy_action} />
      </div>
      <div className={styles.detailGrid}>
        <Field label="Started" value={time(audit.started_at)} />
        <Field label="Task type" value={audit.task_type ?? 'CHAT'} />
        <Field label="Finished" value={time(audit.finished_at)} />
        <Field label="Conversation ID" value={audit.conversation_id} copy />
        <Field label="Status" value={audit.status} />
        <Field label="Policy action" value={audit.policy_action} />
        <Field label="Actual destination" value={audit.actual_destination} />
        <Field label="Simulation" value={audit.simulation ? 'Yes' : 'No'} />
        <Field label="Provider" value={audit.provider_name} />
        <Field label="Provider model" value={audit.provider_model} />
        <Field label="Categories" value={audit.detected_categories.join(', ')} />
        <Field label="Detection" value={audit.detection_status} />
        <Field label="Semantic call" value={audit.semantic_call_status} />
        <Field label="Masking" value={audit.masking_status} />
        <Field label="Model call" value={audit.model_call_status} />
        <Field label="State before" value={audit.conversation_state_before} />
        <Field label="State after" value={audit.conversation_state_after} />
        <Field label="State version" value={audit.conversation_state_version} />
        <Field
          label="Detection time"
          value={
            audit.detector_durations_ms
              ? Object.entries(audit.detector_durations_ms)
                  .map(([key, value]) => `${key}: ${value} ms`)
                  .join(', ')
              : null
          }
        />
        <Field
          label="Total time"
          value={audit.total_duration_ms === null ? null : `${audit.total_duration_ms} ms`}
        />
        <Field label="Error code" value={audit.error_code} />
      </div>
      {!!audit.steps?.length && (
        <section className={styles.stepTimeline} aria-label="Task step timeline">
          <h4>Task steps</h4>
          <ol>
            {audit.steps.map((step) => (
              <li key={step.step_id}>
                <div className={styles.stepHeading}>
                  <strong>
                    {step.sequence}. {step.kind}
                  </strong>
                  <StatusPill value={step.decision} />
                </div>
                <p>
                  {step.source} → {step.target}
                </p>
                <p>{step.input_summary}</p>
                <div className={styles.stepMeta}>
                  <span>Execution: {step.execution_status}</span>
                  <span>
                    Executed: {step.executed === null ? 'Unknown' : step.executed ? 'Yes' : 'No'}
                  </span>
                  <span>Destination: {step.actual_destination}</span>
                  <span>Rule: {step.matched_rules.join(', ') || '—'}</span>
                  <span>Policy: {step.policy_version.slice(0, 12)}</span>
                  {step.error_code && <span>Error: {step.error_code}</span>}
                </div>
              </li>
            ))}
          </ol>
        </section>
      )}
      {audit.policy_action === 'MASK_CLOUD' && (
        <section className={styles.maskedPreview} aria-label="Masked model messages">
          <h4>Masked messages prepared for model</h4>
          {audit.masked_messages ? (
            <pre>{JSON.stringify(audit.masked_messages, null, 2)}</pre>
          ) : (
            <p>No saved masked messages for this record.</p>
          )}
        </section>
      )}
    </div>
  )
}

export default function App() {
  const [activeSection, setActiveSection] = useState<SectionId>(sectionFromHash)
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null)
  const [workspace, setWorkspace] = useState<WorkspaceBootstrap | null>(null)
  const [bootError, setBootError] = useState('')
  const [exampleError, setExampleError] = useState('')
  const [mode, setMode] = useState<SendMode>('single')
  const [useProjectFiles, setUseProjectFiles] = useState(false)
  const [model, setModel] = useState('')
  const [text, setText] = useState('')
  const [conversationId, setConversationId] = useState('')
  const [history, setHistory] = useState<Message[]>([])
  const [sending, setSending] = useState(false)
  const [result, setResult] = useState<Result | null>(null)
  const [audit, setAudit] = useState<Audit | null>(null)
  const [auditError, setAuditError] = useState('')
  const [selectedAudit, setSelectedAudit] = useState<Audit | null>(null)
  const [selectedAuditId, setSelectedAuditId] = useState<string | null>(null)
  const [selectedAuditError, setSelectedAuditError] = useState('')
  const [selectedAuditLoading, setSelectedAuditLoading] = useState(false)
  const auditDrawerRef = useRef<HTMLDialogElement>(null)
  const [lookupId, setLookupId] = useState('')
  const [filters, setFilters] = useState<Filters>(blankFilters)
  const [appliedFilters, setAppliedFilters] = useState<Filters>(blankFilters)
  const [audits, setAudits] = useState<Audit[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [listError, setListError] = useState('')
  const [loadingList, setLoadingList] = useState(false)
  const [conversation, setConversation] = useState<Conversation | null>(null)
  const [conversationError, setConversationError] = useState('')

  useEffect(() => {
    const syncSection = () => setActiveSection(sectionFromHash())
    window.addEventListener('hashchange', syncSection)
    return () => window.removeEventListener('hashchange', syncSection)
  }, [])

  useEffect(() => {
    void fetch('/workspace/bootstrap', { cache: 'no-store' })
      .then(async (response) => {
        if (response.ok) setWorkspace((await response.json()) as WorkspaceBootstrap)
      })
      .catch(() => undefined)
  }, [])

  useEffect(() => {
    void fetch('/demo/bootstrap', { cache: 'no-store' })
      .then(async (response) => {
        if (!response.ok) throw new Error('Demo bootstrap is unavailable.')
        return response.json() as Promise<Bootstrap>
      })
      .then((data) => {
        setBootstrap(data)
        setModel(data.models[0] ?? '')
      })
      .catch(() =>
        setBootError('Could not start the demo console. Check the local gateway and reload.'),
      )
  }, [])

  const getAudit = useCallback(async (requestId: string, token: string) => {
    setAuditError('')
    try {
      const response = await fetch(`/demo/audit/${encodeURIComponent(requestId)}`, {
        headers: { Authorization: `Bearer ${token}` },
        cache: 'no-store',
      })
      if (!response.ok)
        throw new Error(
          response.status === 404
            ? 'Audit record was not found.'
            : `Audit lookup failed (HTTP ${response.status}).`,
        )
      const detail = (await response.json()) as Audit
      setAudit(detail)
      return detail
    } catch (error) {
      setAudit(null)
      setAuditError(error instanceof Error ? error.message : 'Audit lookup failed.')
      return null
    }
  }, [])

  const inspectAudit = async (requestId: string) => {
    if (!bootstrap) return
    setLookupId(requestId)
    setSelectedAuditId(requestId)
    setSelectedAudit(null)
    setSelectedAuditError('')
    setSelectedAuditLoading(true)
    if (!auditDrawerRef.current?.open) auditDrawerRef.current?.showModal()
    try {
      const response = await fetch(`/demo/audit/${encodeURIComponent(requestId)}`, {
        headers: { Authorization: `Bearer ${bootstrap.token}` },
        cache: 'no-store',
      })
      if (!response.ok)
        throw new Error(
          response.status === 404
            ? 'Audit record was not found.'
            : `Audit lookup failed (HTTP ${response.status}).`,
        )
      setSelectedAudit((await response.json()) as Audit)
    } catch (error) {
      setSelectedAuditError(error instanceof Error ? error.message : 'Audit lookup failed.')
    } finally {
      setSelectedAuditLoading(false)
    }
  }

  const getConversation = useCallback(async (id: string, token: string) => {
    setConversationError('')
    try {
      const response = await fetch(`/demo/conversations/${encodeURIComponent(id)}`, {
        headers: { Authorization: `Bearer ${token}` },
        cache: 'no-store',
      })
      if (!response.ok)
        throw new Error(
          response.status === 404
            ? 'Conversation was not found.'
            : `Conversation lookup failed (HTTP ${response.status}).`,
        )
      setConversation((await response.json()) as Conversation)
    } catch (error) {
      setConversation(null)
      setConversationError(error instanceof Error ? error.message : 'Conversation lookup failed.')
    }
  }, [])

  const loadAudits = useCallback(async (token: string, selected: Filters, cursor?: string) => {
    setLoadingList(true)
    setListError('')
    try {
      const params = new URLSearchParams({ limit: '20' })
      if (selected.policy_action) params.set('policy_action', selected.policy_action)
      if (selected.status) params.set('status', selected.status)
      if (selected.conversation_id) params.set('conversation_id', selected.conversation_id)
      if (cursor) params.set('cursor', cursor)
      const response = await fetch(`/demo/audits?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
        cache: 'no-store',
      })
      if (!response.ok) throw new Error(`Audit list failed (HTTP ${response.status}).`)
      const page = (await response.json()) as { items: Audit[]; next_cursor: string | null }
      setAudits((previous) => (cursor ? [...previous, ...page.items] : page.items))
      setNextCursor(page.next_cursor)
    } catch (error) {
      setListError(error instanceof Error ? error.message : 'Audit list failed.')
    } finally {
      setLoadingList(false)
    }
  }, [])

  useEffect(() => {
    if (bootstrap) void loadAudits(bootstrap.token, appliedFilters)
  }, [bootstrap, appliedFilters, loadAudits])

  const messages = useMemo(
    () => buildMessages(useProjectFiles ? 'single' : mode, history, text.trim()),
    [useProjectFiles, mode, history, text],
  )
  const chooseExample = (key: string, sample: string) => {
    setUseProjectFiles(false)
    if (
      key === 'LOCAL' &&
      (!conversationId ||
        conversation?.conversation_id !== conversationId ||
        conversation.state !== 'SENSITIVE')
    ) {
      setExampleError(
        'Run the Block example first, then send a follow-up in the same conversation.',
      )
      return
    }
    setExampleError('')
    setMode('single')
    setText(sample)
    document.getElementById('message')?.focus()
  }
  const startNew = () => {
    setUseProjectFiles(false)
    setConversationId('')
    setHistory([])
    setResult(null)
    setAudit(null)
    setConversation(null)
    setAuditError('')
    setExampleError('')
    setConversationError('')
    setText('')
  }
  const changeConversationId = (value: string) => {
    setConversationId(value)
    setConversation(null)
    setHistory([])
  }
  const send = async (event: FormEvent) => {
    event.preventDefault()
    if (!bootstrap || !model || !text.trim() || sending || (useProjectFiles && !workspace)) return
    setSending(true)
    setAudit(null)
    setAuditError('')
    const input = text.trim()
    try {
      if (useProjectFiles) {
        const headers: Record<string, string> = {
          Authorization: `Bearer ${bootstrap.token}`,
          'Content-Type': 'application/json',
        }
        if (conversationId.trim()) headers['X-Aegis-Conversation-Id'] = conversationId.trim()
        const response = await fetch('/v1/workflows/workspace', {
          method: 'POST',
          headers,
          body: JSON.stringify({ model, input }),
        })
        const body = await response.json()
        const requestId = response.headers.get('X-Aegis-Request-Id') ?? body?.task_id ?? null
        const returnedId = response.headers.get('X-Aegis-Conversation-Id')
        const code: string | null = body?.error?.code ?? null
        setResult({
          kind: 'AGENT',
          httpStatus: response.status,
          content: response.ok
            ? (body?.answer ?? null)
            : (body?.error?.message ?? describeHttpError(response.status, code)),
          code,
          requestId,
          conversationId: returnedId,
          action: null,
          destination: 'NONE',
          simulation: false,
          workflowStatus: response.ok ? (body?.status ?? null) : null,
          sources: response.ok && Array.isArray(body?.sources) ? body.sources : [],
        })
        if (returnedId) setConversationId(returnedId)
        if (response.ok) setText('')
        if (requestId) {
          setLookupId(requestId)
          const detail = await getAudit(requestId, bootstrap.token)
          if (detail) {
            setResult((previous) =>
              previous && previous.requestId === requestId
                ? {
                    ...previous,
                    action: detail.policy_action,
                    destination: detail.actual_destination,
                    simulation: detail.simulation,
                  }
                : previous,
            )
          }
          if (!response.ok || body?.status === 'SOURCE_EXCLUDED') await inspectAudit(requestId)
        }
        if (returnedId) await getConversation(returnedId, bootstrap.token)
        void loadAudits(bootstrap.token, appliedFilters)
        return
      }
      const headers: Record<string, string> = {
        Authorization: `Bearer ${bootstrap.token}`,
        'Content-Type': 'application/json',
      }
      if (conversationId.trim()) headers['X-Aegis-Conversation-Id'] = conversationId.trim()
      const response = await fetch('/v1/chat/completions', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model,
          messages: buildMessages(mode, history, input),
          stream: false,
        }),
      })
      const body = await response.json()
      const requestId = response.headers.get('X-Aegis-Request-Id')
      const returnedId = response.headers.get('X-Aegis-Conversation-Id')
      const code: string | null = body?.error?.code ?? null
      const content: string | null = response.ok
        ? (body?.choices?.[0]?.message?.content ?? null)
        : null
      const action = response.headers.get('X-Aegis-Policy-Action')
      const destination = response.headers.get('X-Aegis-Actual-Destination') ?? 'NONE'
      const simulation = response.headers.get('X-Aegis-Simulation') === 'true'
      setResult({
        kind: 'CHAT',
        httpStatus: response.status,
        content: response.ok ? content : describeHttpError(response.status, code),
        code,
        requestId,
        conversationId: returnedId,
        action,
        destination,
        simulation,
        workflowStatus: null,
        sources: [],
      })
      if (returnedId) setConversationId(returnedId)
      if (response.ok && content && mode === 'chat')
        setHistory((previous) => [
          ...previous,
          { role: 'user', content: input },
          { role: 'assistant', content },
        ])
      if (response.ok) setText('')
      if (requestId) {
        setLookupId(requestId)
        await getAudit(requestId, bootstrap.token)
      }
      if (returnedId) await getConversation(returnedId, bootstrap.token)
      void loadAudits(bootstrap.token, appliedFilters)
    } catch {
      setResult({
        kind: useProjectFiles ? 'AGENT' : 'CHAT',
        httpStatus: 0,
        content: 'Could not reach the local gateway.',
        code: null,
        requestId: null,
        conversationId: null,
        action: null,
        destination: 'NONE',
        simulation: false,
        workflowStatus: null,
        sources: [],
      })
    } finally {
      setSending(false)
    }
  }

  return (
    <div className={styles.shell}>
      <aside className={styles.sidebar}>
        <div className={styles.brand}>
          <span className={styles.brandMark}>A</span>
          <span>
            <strong>AEGIS</strong>
            <small>DECISION CONSOLE</small>
          </span>
        </div>
        <div className={styles.sideSection}>WORKSPACE</div>
        <nav aria-label="Main navigation">
          <a
            className={activeSection === 'workspace' ? styles.navActive : undefined}
            href="#workspace"
            aria-current={activeSection === 'workspace' ? 'location' : undefined}
          >
            <span>◫</span> Request lab
          </a>
          <a
            className={activeSection === 'decision' ? styles.navActive : undefined}
            href="#decision"
            aria-current={activeSection === 'decision' ? 'location' : undefined}
          >
            <span>◈</span> Decision detail
          </a>
          <a
            className={activeSection === 'audit' ? styles.navActive : undefined}
            href="#audit"
            aria-current={activeSection === 'audit' ? 'location' : undefined}
          >
            <span>▤</span> Audit trail
          </a>
          <a
            className={activeSection === 'conversation' ? styles.navActive : undefined}
            href="#conversation"
            aria-current={activeSection === 'conversation' ? 'location' : undefined}
          >
            <span>◎</span> Conversation
          </a>
        </nav>
        <div className={styles.sideBottom}>
          <span className={styles.onlineDot} />{' '}
          {bootstrap ? 'Demo session active' : 'Connecting to gateway'}
          <small>Local demo environment</small>
        </div>
      </aside>

      <main className={styles.main}>
        <header className={styles.topbar}>
          <div>
            <span className={styles.eyebrow}>SECURITY ROUTING / OVERVIEW</span>
            <h1>Decision Console</h1>
            <p>Send a request, inspect the route, and trace its audit record.</p>
          </div>
          <div className={styles.modeBadge}>
            <span className={styles.onlineDot} /> DEMO MODE
          </div>
        </header>
        {bootError && (
          <div className={styles.alert} role="alert">
            {bootError}
          </div>
        )}
        <section className={styles.examples} aria-label="Example requests">
          <div className={styles.sectionHeading}>
            <div>
              <span className={styles.eyebrow}>QUICK START</span>
              <h2>Explore policy outcomes</h2>
            </div>
            <span className={styles.muted}>Select an example to fill the request.</span>
          </div>
          <div className={styles.exampleGrid}>
            {examples.map((example, index) => (
              <button
                key={example.key}
                type="button"
                className={styles.exampleCard}
                onClick={() => chooseExample(example.key, example.text)}
              >
                <span className={`${styles.exampleIcon} ${styles[example.tone]}`}>
                  {['↗', '◌', '⊘', '↪'][index]}
                </span>
                <span>
                  <strong>{example.title}</strong>
                  <small>
                    {example.key === 'LOCAL'
                      ? 'Reuses the current conversation'
                      : `Expected ${example.key} decision`}
                  </small>
                </span>
                <span className={styles.exampleArrow}>→</span>
              </button>
            ))}
          </div>
          {exampleError && (
            <p className={styles.inlineError} role="alert">
              {exampleError}
            </p>
          )}
        </section>

        <div className={styles.columns}>
          <section id="workspace" className={styles.panel} aria-labelledby="workspace-title">
            <div className={styles.panelHeader}>
              <div>
                <span className={styles.eyebrow}>01 / REQUEST WORKSPACE</span>
                <h2 id="workspace-title">Compose a request</h2>
              </div>
              <button className={styles.secondary} type="button" onClick={startNew}>
                New conversation
              </button>
            </div>
            <form onSubmit={(event) => void send(event)}>
              <div className={styles.formRow}>
                <label className={styles.formField}>
                  Model alias
                  <select
                    value={model}
                    onChange={(event) => setModel(event.target.value)}
                    disabled={!bootstrap}
                  >
                    {bootstrap?.models.map((value) => (
                      <option key={value}>{value}</option>
                    ))}
                  </select>
                </label>
                <label className={styles.formField}>
                  Conversation ID
                  <input
                    value={conversationId}
                    onChange={(event) => changeConversationId(event.target.value)}
                    placeholder="Generated on first request"
                    maxLength={128}
                    disabled={sending}
                  />
                </label>
              </div>
              {!useProjectFiles && (
                <div className={styles.formField}>
                  <span>Send mode</span>
                  <div className={styles.segmented} role="group" aria-label="Send mode">
                    <button
                      type="button"
                      className={mode === 'single' ? styles.selected : ''}
                      onClick={() => setMode('single')}
                    >
                      Single-turn test
                    </button>
                    <button
                      type="button"
                      className={mode === 'chat' ? styles.selected : ''}
                      onClick={() => setMode('chat')}
                    >
                      Continuous chat
                    </button>
                  </div>
                </div>
              )}
              <label className={styles.formField} htmlFor="message">
                Message
                <textarea
                  id="message"
                  rows={5}
                  value={text}
                  onChange={(event) => setText(event.target.value)}
                  placeholder={
                    useProjectFiles
                      ? 'Ask a question about this project...'
                      : 'Type a message to test how Aegis routes it...'
                  }
                  disabled={sending}
                />
              </label>
              {workspace && (
                <label className={styles.toolOption}>
                  <input
                    type="checkbox"
                    checked={useProjectFiles}
                    onChange={(event) => setUseProjectFiles(event.target.checked)}
                    disabled={sending}
                  />
                  <span>
                    <strong>Use project files</strong>
                    <small>
                      Allow the agent to search and read tracked files in {workspace.root}.
                    </small>
                  </span>
                </label>
              )}
              <details className={styles.preview}>
                <summary>
                  {useProjectFiles ? 'Project question preview' : 'Request preview'}{' '}
                  <span>
                    {messages.length} message{messages.length === 1 ? '' : 's'}
                  </span>
                </summary>
                <div className={styles.previewBody}>
                  {messages.map((message, index) => (
                    <div key={index}>
                      <strong>{message.role}</strong>
                      <p>{message.content || 'Current message is empty.'}</p>
                    </div>
                  ))}
                </div>
              </details>
              <div className={styles.formFooter}>
                <span>
                  {useProjectFiles
                    ? 'Only this question is sent. Tool calls and file content are screened and audited.'
                    : mode === 'single'
                      ? 'Only this message is sent. Conversation safety state still persists.'
                      : `${history.length} previous messages will be sent with this turn.`}
                </span>
                <button
                  className={styles.primary}
                  type="submit"
                  disabled={!bootstrap || !model || !text.trim() || sending}
                >
                  {sending
                    ? 'Processing...'
                    : useProjectFiles
                      ? 'Run with project files ->'
                      : 'Send request ->'}
                </button>
              </div>
            </form>
          </section>

          <section id="decision" className={styles.panel} aria-labelledby="decision-title">
            <div className={styles.panelHeader}>
              <div>
                <span className={styles.eyebrow}>02 / RESULT</span>
                <h2 id="decision-title">Decision detail</h2>
              </div>
              {result && (
                <StatusPill
                  value={
                    result.kind === 'AGENT'
                      ? (audit?.status ?? result.workflowStatus)
                      : result.action
                  }
                />
              )}
            </div>
            {!result ? (
              <div className={styles.empty}>
                <span className={styles.emptyIcon}>◇</span>
                <strong>No request yet</strong>
                <p>Send a request to see its policy decision and actual destination.</p>
              </div>
            ) : (
              <div className={styles.result} aria-live="polite">
                <div className={styles.resultHero}>
                  <span className={styles.eyebrow}>
                    {result.kind === 'AGENT' ? 'PROJECT FILE TASK' : 'ROUTING OUTCOME'}
                  </span>
                  <h3>
                    {result.kind === 'AGENT'
                      ? result.workflowStatus === 'SOURCE_EXCLUDED'
                        ? 'Project content excluded'
                        : result.httpStatus >= 200 && result.httpStatus < 300
                          ? 'Agent task completed'
                          : 'Agent task failed'
                      : routeLabel(result.action, result.destination, result.simulation)}
                  </h3>
                  <p>
                    HTTP {result.httpStatus || 'network error'}
                    {result.code ? ` · ${result.code}` : ''}
                  </p>
                </div>
                <div className={styles.resultGrid}>
                  <Field label="Policy action" value={result.action} />
                  <Field label="Actual destination" value={result.destination} />
                  <Field label="Simulation" value={result.simulation ? 'Yes' : 'No'} />
                  <Field label="Audit status" value={audit?.status} />
                  {result.kind === 'AGENT' && (
                    <Field label="Task result" value={result.workflowStatus} />
                  )}
                </div>
                <div className={styles.reply}>
                  <span className={styles.eyebrow}>
                    {result.httpStatus >= 200 &&
                    result.httpStatus < 300 &&
                    result.workflowStatus !== 'SOURCE_EXCLUDED'
                      ? result.kind === 'AGENT'
                        ? 'AGENT ANSWER'
                        : 'MODEL RESPONSE'
                      : 'GATEWAY RESPONSE'}
                  </span>
                  <p>{result.content || 'No response content returned.'}</p>
                </div>
                {result.kind === 'AGENT' && result.sources.length > 0 && (
                  <div className={styles.sourceList}>
                    <strong>Files used</strong>
                    <ul>
                      {result.sources.map((source) => (
                        <li key={source.source}>
                          <code>{source.source}</code>
                        </li>
                      ))}
                    </ul>
                    <small>Model answers may be inaccurate; check the listed files.</small>
                  </div>
                )}
                <Field label="Request ID" value={result.requestId} copy />
                <Field label="Conversation ID" value={result.conversationId} copy />
              </div>
            )}
          </section>
        </div>

        <section id="audit" className={styles.panel} aria-labelledby="audit-title">
          <div className={styles.panelHeader}>
            <div>
              <span className={styles.eyebrow}>03 / TRACEABILITY</span>
              <h2 id="audit-title">Audit trail</h2>
            </div>
            <span className={styles.muted}>Masked preview in details</span>
          </div>
          <div className={styles.auditToolbar}>
            <form
              className={styles.lookup}
              onSubmit={(event) => {
                event.preventDefault()
                if (lookupId.trim()) void inspectAudit(lookupId.trim())
              }}
            >
              <label htmlFor="lookup">Find request ID</label>
              <div>
                <input
                  id="lookup"
                  value={lookupId}
                  onChange={(event) => setLookupId(event.target.value)}
                  placeholder="Paste a request ID"
                />
                <button
                  className={styles.secondary}
                  type="submit"
                  disabled={!bootstrap || !lookupId.trim()}
                >
                  Find
                </button>
              </div>
            </form>
            <form
              className={styles.filters}
              onSubmit={(event) => {
                event.preventDefault()
                setAppliedFilters({ ...filters })
              }}
            >
              <label>
                Action
                <select
                  value={filters.policy_action}
                  onChange={(event) =>
                    setFilters({ ...filters, policy_action: event.target.value })
                  }
                >
                  <option value="">All actions</option>
                  {['CLOUD', 'MASK_CLOUD', 'BLOCK', 'LOCAL'].map((value) => (
                    <option key={value}>{value}</option>
                  ))}
                </select>
              </label>
              <label>
                Status
                <select
                  value={filters.status}
                  onChange={(event) => setFilters({ ...filters, status: event.target.value })}
                >
                  <option value="">All statuses</option>
                  {['SUCCEEDED', 'BLOCKED', 'FAILED', 'REJECTED', 'PENDING'].map((value) => (
                    <option key={value}>{value}</option>
                  ))}
                </select>
              </label>
              <label>
                Conversation
                <input
                  value={filters.conversation_id}
                  onChange={(event) =>
                    setFilters({ ...filters, conversation_id: event.target.value })
                  }
                  placeholder="Any conversation"
                />
              </label>
              <button className={styles.secondary} type="submit">
                Apply filters
              </button>
            </form>
          </div>
          {listError && (
            <p className={styles.inlineError} role="alert">
              {listError}
            </p>
          )}
          <div className={styles.tableWrap}>
            <table>
              <thead>
                <tr>
                  <th>Time / Request</th>
                  <th>Action</th>
                  <th>Destination</th>
                  <th>Status</th>
                  <th>Duration</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {audits.map((item) => (
                  <tr
                    key={item.request_id}
                    className={
                      selectedAuditId === item.request_id ? styles.selectedAuditRow : undefined
                    }
                  >
                    <td>
                      <strong>{time(item.started_at)}</strong>
                      <small>{item.request_id}</small>
                      <small>{item.task_type ?? 'CHAT'}</small>
                    </td>
                    <td>
                      <StatusPill value={item.policy_action} />
                    </td>
                    <td>
                      {item.actual_destination}
                      {item.simulation ? <small>Simulated</small> : null}
                    </td>
                    <td>
                      <StatusPill value={item.status} />
                    </td>
                    <td>
                      {item.total_duration_ms === null ? '—' : `${item.total_duration_ms} ms`}
                    </td>
                    <td>
                      <button
                        className={styles.textButton}
                        type="button"
                        onClick={() => void inspectAudit(item.request_id)}
                      >
                        Inspect →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!loadingList && audits.length === 0 && !listError && (
              <div className={styles.listEmpty}>No audit records match these filters.</div>
            )}
          </div>
          <div className={styles.tableFooter}>
            <span>
              {audits.length} record{audits.length === 1 ? '' : 's'} loaded
            </span>
            <button
              className={styles.secondary}
              type="button"
              disabled={!bootstrap || !nextCursor || loadingList}
              onClick={() => {
                if (bootstrap && nextCursor)
                  void loadAudits(bootstrap.token, appliedFilters, nextCursor)
              }}
            >
              {loadingList ? 'Loading…' : 'Load more'}
            </button>
          </div>
          {auditError && (
            <p className={styles.inlineError} role="alert">
              {auditError}
            </p>
          )}
        </section>

        <dialog
          ref={auditDrawerRef}
          className={styles.auditDrawer}
          aria-labelledby="audit-drawer-title"
          onClick={(event) => {
            if (event.target === event.currentTarget) event.currentTarget.close()
          }}
        >
          <div className={styles.auditDrawerHeader}>
            <div>
              <span className={styles.eyebrow}>TRACEABILITY</span>
              <h2 id="audit-drawer-title">Audit record details</h2>
            </div>
            <button
              className={styles.secondary}
              type="button"
              onClick={() => auditDrawerRef.current?.close()}
            >
              Close
            </button>
          </div>
          <div className={styles.auditDrawerBody}>
            {selectedAuditLoading && <p className={styles.muted}>Loading audit record…</p>}
            {selectedAuditError && (
              <p className={styles.inlineError} role="alert">
                {selectedAuditError}
              </p>
            )}
            {selectedAudit && <AuditDetails audit={selectedAudit} />}
          </div>
        </dialog>

        <section id="conversation" className={styles.panel} aria-labelledby="conversation-title">
          <div className={styles.panelHeader}>
            <div>
              <span className={styles.eyebrow}>04 / PERSISTENT STATE</span>
              <h2 id="conversation-title">Conversation state</h2>
            </div>
            {conversation && (
              <StatusPill
                value={conversation.state}
                kind={conversation.state === 'SENSITIVE' ? 'warning' : ''}
              />
            )}
          </div>
          <div className={styles.conversationContent}>
            <form
              className={styles.lookup}
              onSubmit={(event) => {
                event.preventDefault()
                if (bootstrap && conversationId.trim())
                  void getConversation(conversationId.trim(), bootstrap.token)
              }}
            >
              <label htmlFor="conversation-lookup">Conversation ID</label>
              <div>
                <input
                  id="conversation-lookup"
                  value={conversationId}
                  onChange={(event) => changeConversationId(event.target.value)}
                  placeholder="Generated on first request"
                />
                <button
                  className={styles.secondary}
                  type="submit"
                  disabled={!bootstrap || !conversationId.trim()}
                >
                  View state
                </button>
              </div>
            </form>
            {conversation ? (
              <div className={styles.conversationStats}>
                <Field label="Current state" value={conversation.state} />
                <Field label="State version" value={conversation.state_version} />
                <Field label="Active request" value={conversation.active_request ? 'Yes' : 'No'} />
                <Field label="Last updated" value={time(conversation.updated_at)} />
              </div>
            ) : (
              <p className={styles.muted}>
                Enter a conversation ID or send a request to see its current security state.
              </p>
            )}
          </div>
          {conversationError && (
            <p className={styles.inlineError} role="alert">
              {conversationError}
            </p>
          )}
        </section>
        <footer className={styles.footer}>
          Aegis · Local demo console{' '}
          <span>
            Conversation IDs retain security state. Chat context is sent by the client; project
            tasks use only the current question.
          </span>
        </footer>
      </main>
    </div>
  )
}

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import styles from './ConnectedApp.module.css'

type Bootstrap = { models: string[]; github_repo: string }
type Source = { document_id: string; title: string; source: string; version: string }
type Step = {
  step_id: string
  sequence: number
  kind: string
  target: string
  decision: string
  execution_status: string
  executed: boolean | null
  actual_destination: string
  matched_rules: string[]
  error_code: string | null
}
type Audit = {
  request_id: string
  status: string
  policy_action: string | null
  actual_destination: string
  error_code: string | null
  steps: Step[] | null
}
type TaskResult = {
  task_id: string
  status: string
  answer: string
  sources: Source[]
  approval_id: string | null
  preview: string | null
  write_attempted: boolean
}
type Pending = {
  approval_id: string
  task_id: string
  repo: string
  issue_number: number
  expires_at: string
  preview: string
}

export default function ConnectedApp({ bootstrap }: { bootstrap: Bootstrap }) {
  const [token, setToken] = useState('')
  const [model, setModel] = useState(bootstrap.models[0] ?? '')
  const [issueUrl, setIssueUrl] = useState('')
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<TaskResult | null>(null)
  const [message, setMessage] = useState('')
  const [audits, setAudits] = useState<Audit[]>([])
  const [selected, setSelected] = useState<Audit | null>(null)
  const [pending, setPending] = useState<Pending[]>([])

  const headers = useCallback(() => ({ Authorization: `Bearer ${token.trim()}` }), [token])
  const refresh = useCallback(async () => {
    if (!token.trim()) return
    try {
      const [auditResponse, approvalResponse] = await Promise.all([
        fetch('/connected/audits', { headers: headers(), cache: 'no-store' }),
        fetch('/connected/approvals', { headers: headers(), cache: 'no-store' }),
      ])
      if (!auditResponse.ok || !approvalResponse.ok) throw new Error('Could not load activity.')
      setAudits((await auditResponse.json()).items)
      setPending((await approvalResponse.json()).items)
    } catch {
      setMessage('Could not load activity. Check your Aegis API key.')
    }
  }, [headers, token])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const inspect = async (taskId: string) => {
    try {
      const response = await fetch(`/connected/audit/${taskId}`, {
        headers: headers(),
        cache: 'no-store',
      })
      if (!response.ok) throw new Error('Audit unavailable.')
      setSelected((await response.json()) as Audit)
    } catch {
      setMessage('Audit unavailable.')
    }
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (!token.trim() || !model || !issueUrl.trim() || !input.trim() || busy) return
    setBusy(true)
    setMessage('')
    setResult(null)
    try {
      const response = await fetch('/v1/workflows/github-issues', {
        method: 'POST',
        headers: { ...headers(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, issue_url: issueUrl.trim(), input: input.trim() }),
      })
      const body = await response.json()
      if (!response.ok) {
        const failedId = response.headers.get('X-Aegis-Request-Id')
        if (failedId) await inspect(failedId)
        throw new Error(body?.error?.code ?? `HTTP ${response.status}`)
      }
      const item = body as TaskResult
      setResult(item)
      await Promise.all([inspect(item.task_id), refresh()])
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Task failed.')
      await refresh()
    } finally {
      setBusy(false)
    }
  }

  const decide = async (approvalId: string, action: 'approve' | 'deny') => {
    setBusy(true)
    try {
      const response = await fetch(`/v1/approvals/${approvalId}/${action}`, {
        method: 'POST',
        headers: headers(),
      })
      const body = await response.json()
      if (!response.ok) throw new Error(body?.error?.message ?? `HTTP ${response.status}`)
      setMessage(body.message)
      if (result?.approval_id === approvalId) await inspect(result.task_id)
      await refresh()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Approval failed.')
      await refresh()
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className={styles.shell}>
      <header className={styles.header}>
        <div>
          <span className={styles.eyebrow}>AEGIS / LIVE WORKFLOW</span>
          <h1>GitHub Issue assistant</h1>
          <p>Read a real issue, inspect each decision, and approve a proposed comment.</p>
          <p>
            GitHub content goes to the configured external screening service. Approved context goes
            to the configured cloud model under the recorded route.
          </p>
        </div>
        <span className={styles.repo}>{bootstrap.github_repo}</span>
      </header>

      <div className={styles.columns}>
        <section className={styles.card} aria-labelledby="request-heading">
          <h2 id="request-heading">Request</h2>
          <form onSubmit={submit} className={styles.form}>
            <label>
              Aegis API key
              <input
                type="password"
                autoComplete="off"
                value={token}
                onChange={(event) => setToken(event.target.value)}
                placeholder="Configured API token"
              />
            </label>
            <label>
              Model
              <select value={model} onChange={(event) => setModel(event.target.value)}>
                {bootstrap.models.map((name) => (
                  <option key={name}>{name}</option>
                ))}
              </select>
            </label>
            <label>
              GitHub Issue URL
              <input
                type="url"
                value={issueUrl}
                onChange={(event) => setIssueUrl(event.target.value)}
                placeholder={`https://github.com/${bootstrap.github_repo}/issues/123`}
              />
            </label>
            <label>
              What should the assistant do?
              <textarea
                value={input}
                onChange={(event) => setInput(event.target.value)}
                placeholder="Summarize this issue and suggest a response."
                rows={5}
              />
            </label>
            <button disabled={busy || !token || !issueUrl || !input} type="submit">
              {busy ? 'Working…' : 'Run workflow'}
            </button>
          </form>
          {message && (
            <p role="status" className={styles.notice}>
              {message}
            </p>
          )}
        </section>

        <section className={styles.card} aria-labelledby="result-heading">
          <h2 id="result-heading">Result</h2>
          {!result ? (
            <p className={styles.empty}>Run a GitHub Issue workflow to see its result.</p>
          ) : (
            <>
              <p className={styles.status}>{result.status}</p>
              <p>{result.answer}</p>
              <p>
                Comment write: {result.write_attempted ? 'Proposed for approval' : 'Not attempted'}
              </p>
              {result.sources.length > 0 && (
                <div>
                  <h3>Sources</h3>
                  {result.sources.map((source) => (
                    <p key={source.document_id}>
                      <a href={source.source} target="_blank" rel="noreferrer">
                        {source.document_id}
                      </a>
                    </p>
                  ))}
                </div>
              )}
              <small>Task ID: {result.task_id}</small>
            </>
          )}
        </section>
      </div>

      <section className={styles.card} aria-labelledby="approval-heading">
        <div className={styles.row}>
          <h2 id="approval-heading">Pending approvals</h2>
          <button className={styles.secondary} onClick={() => void refresh()} type="button">
            Refresh
          </button>
        </div>
        {pending.length === 0 ? (
          <p className={styles.empty}>No proposed writes.</p>
        ) : (
          pending.map((item) => (
            <article className={styles.approval} key={item.approval_id}>
              <strong>
                {item.repo}#{item.issue_number} · Add comment
              </strong>
              <p>Expires {new Date(item.expires_at).toLocaleString()}</p>
              <pre>{item.preview}</pre>
              <div className={styles.actions}>
                <button disabled={busy} onClick={() => void decide(item.approval_id, 'approve')}>
                  Approve and post
                </button>
                <button
                  className={styles.secondary}
                  disabled={busy}
                  onClick={() => void decide(item.approval_id, 'deny')}
                >
                  Deny
                </button>
              </div>
            </article>
          ))
        )}
      </section>

      <section className={styles.card} aria-labelledby="activity-heading">
        <h2 id="activity-heading">Activity</h2>
        {audits.length === 0 ? (
          <p className={styles.empty}>No activity yet.</p>
        ) : (
          <div className={styles.activity}>
            {audits.map((item) => (
              <button key={item.request_id} onClick={() => void inspect(item.request_id)}>
                <span>{item.request_id.slice(0, 12)}</span>
                <span>{item.status}</span>
              </button>
            ))}
          </div>
        )}
        {selected && (
          <div className={styles.timeline} aria-label="Task step timeline">
            <h3>Task {selected.request_id}</h3>
            <p>
              {selected.status} · Model route: {selected.policy_action ?? 'none'} · Destination:{' '}
              {selected.actual_destination}
            </p>
            {selected.error_code && <p>Error: {selected.error_code}</p>}
            <ol>
              {(selected.steps ?? []).map((step) => (
                <li key={step.step_id}>
                  <strong>{step.kind}</strong> → {step.target}
                  <p>
                    {step.decision} · {step.execution_status} · Executed:{' '}
                    {step.executed === null ? 'Unknown' : step.executed ? 'Yes' : 'No'} ·{' '}
                    {step.actual_destination}
                  </p>
                  <small>Rule: {step.matched_rules.join(', ') || 'none'}</small>
                  {step.error_code && <small> · Error: {step.error_code}</small>}
                </li>
              ))}
            </ol>
          </div>
        )}
      </section>
    </main>
  )
}

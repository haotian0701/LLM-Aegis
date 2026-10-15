import { useEffect, useState } from 'react'
import styles from './ConnectedApp.module.css'

type Bootstrap = { token: string; models: string[]; root: string }
type Source = { source: string; version: string }
type Result = { task_id: string; status: string; answer: string; sources: Source[] }
type Audit = { request_id: string; status: string; task_type: string }
type Step = {
  step_id: string
  kind: string
  target: string
  decision: string
  execution_status: string
  executed: boolean | null
  actual_destination: string
  matched_rules: string[]
  error_code: string | null
}
type Detail = Audit & { policy_action: string | null; steps: Step[]; error_code: string | null }

export default function WorkspaceApp({ bootstrap }: { bootstrap: Bootstrap }) {
  const [model, setModel] = useState(bootstrap.models[0] ?? '')
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [result, setResult] = useState<Result | null>(null)
  const [audits, setAudits] = useState<Audit[]>([])
  const [selected, setSelected] = useState<Detail | null>(null)
  const headers = () => ({ Authorization: `Bearer ${bootstrap.token}` })

  async function refresh() {
    const response = await fetch('/demo/audits?limit=30', { headers: headers(), cache: 'no-store' })
    if (!response.ok) return
    const body = await response.json()
    setAudits((body.items as Audit[]).filter((item) => item.task_type === 'AGENT'))
  }

  async function inspect(taskId: string) {
    const response = await fetch(`/demo/audit/${taskId}`, {
      headers: headers(),
      cache: 'no-store',
    })
    if (response.ok) setSelected(await response.json())
  }

  useEffect(() => {
    void refresh()
  }, [])

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage('')
    setResult(null)
    try {
      const response = await fetch('/v1/workflows/workspace', {
        method: 'POST',
        headers: { ...headers(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, input }),
      })
      const body = await response.json()
      if (!response.ok) {
        const taskId = response.headers.get('X-Aegis-Request-Id')
        if (taskId) await inspect(taskId)
        throw new Error(body?.error?.message ?? `HTTP ${response.status}`)
      }
      setResult(body)
      await inspect(body.task_id)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Task failed.')
    } finally {
      await refresh()
      setBusy(false)
    }
  }

  return (
    <main className={styles.shell}>
      <header className={styles.header}>
        <div>
          <span className={styles.eyebrow}>AEGIS / PROJECT AGENT</span>
          <h1>Ask about this project</h1>
          <p>Ask a free text question. The agent searches and reads tracked project files.</p>
          <p>
            Project text is screened by the configured external classifier. Approved text goes to
            the configured cloud model under the recorded route. Tools only read local files.
          </p>
          <a href="/?view=console">Decision Console</a>
        </div>
        <span className={styles.repo}>{bootstrap.root}</span>
      </header>

      <div className={styles.columns}>
        <section className={styles.card} aria-labelledby="request-heading">
          <h2 id="request-heading">Project question</h2>
          <form onSubmit={submit} className={styles.form}>
            <label>
              Model
              <select value={model} onChange={(event) => setModel(event.target.value)}>
                {bootstrap.models.map((name) => <option key={name}>{name}</option>)}
              </select>
            </label>
            <label>
              What do you want to know?
              <textarea
                value={input}
                onChange={(event) => setInput(event.target.value)}
                placeholder="Where does the chat API make its routing decision? Cite the source files."
                rows={5}
              />
            </label>
            <button disabled={busy || !input.trim()} type="submit">
              {busy ? 'Inspecting project…' : 'Run agent'}
            </button>
          </form>
          {message && <p role="status" className={styles.notice}>{message}</p>}
        </section>

        <section className={styles.card} aria-labelledby="result-heading">
          <h2 id="result-heading">Result</h2>
          {!result ? <p className={styles.empty}>The answer and real file sources appear here.</p> : (
            <>
              <p className={styles.status}>{result.status}</p>
              <p style={{ whiteSpace: 'pre-wrap' }}>{result.answer}</p>
              {result.sources.length > 0 && (
                <div>
                  <h3>Files used</h3>
                  {result.sources.map((source) => (
                    <p key={source.source}><code>{source.source}</code></p>
                  ))}
                </div>
              )}
              <small>Task ID: {result.task_id}</small>
            </>
          )}
        </section>
      </div>

      <section className={styles.card} aria-labelledby="activity-heading">
        <div className={styles.row}>
          <h2 id="activity-heading">Activity and decisions</h2>
          <button className={styles.secondary} onClick={() => void refresh()} type="button">
            Refresh
          </button>
        </div>
        {audits.length === 0 ? <p className={styles.empty}>No tasks yet.</p> : (
          <div className={styles.activity}>
            {audits.map((item) => (
              <button key={item.request_id} onClick={() => void inspect(item.request_id)}>
                <span>{item.request_id.slice(0, 12)}</span><span>{item.status}</span>
              </button>
            ))}
          </div>
        )}
        {selected && (
          <div className={styles.timeline} aria-label="Task step timeline">
            <h3>Task {selected.request_id}</h3>
            <p>{selected.status} · Model route: {selected.policy_action ?? 'none'}</p>
            {selected.error_code && <p>Error: {selected.error_code}</p>}
            <ol>
              {(selected.steps ?? []).map((step) => (
                <li key={step.step_id}>
                  <strong>{step.kind}</strong> → {step.target}
                  <p>
                    {step.decision} · {step.execution_status} · Executed: {step.executed === null ? 'Unknown' : step.executed ? 'Yes' : 'No'} · {step.actual_destination}
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

import React from 'react'
import ReactDOM from 'react-dom/client'
import { useEffect, useState } from 'react'
import App from './App'
import ConnectedApp from './ConnectedApp'
import './styles.css'

function Root() {
  const [mode, setMode] = useState<'loading' | 'demo' | 'connected'>('loading')
  const [bootstrap, setBootstrap] = useState<{ models: string[]; github_repo: string } | null>(null)

  useEffect(() => {
    void fetch('/connected/bootstrap', { cache: 'no-store' })
      .then(async (response) => {
        if (!response.ok) {
          setMode('demo')
          return
        }
        setBootstrap(await response.json())
        setMode('connected')
      })
      .catch(() => setMode('demo'))
  }, [])

  if (mode === 'loading') return null
  if (mode === 'connected' && bootstrap) return <ConnectedApp bootstrap={bootstrap} />
  return <App />
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
)

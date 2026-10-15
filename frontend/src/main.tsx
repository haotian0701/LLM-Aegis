import React from 'react'
import ReactDOM from 'react-dom/client'
import { useEffect, useState } from 'react'
import App from './App'
import ConnectedApp from './ConnectedApp'
import WorkspaceApp from './WorkspaceApp'
import './styles.css'

function Root() {
  const [mode, setMode] = useState<'loading' | 'demo' | 'connected' | 'workspace'>('loading')
  const [bootstrap, setBootstrap] = useState<{ models: string[]; github_repo: string } | null>(null)
  const [workspace, setWorkspace] = useState<{ token: string; models: string[]; root: string } | null>(null)

  useEffect(() => {
    void fetch('/connected/bootstrap', { cache: 'no-store' })
      .then(async (response) => {
        if (!response.ok) {
          void fetch('/workspace/bootstrap', { cache: 'no-store' })
            .then(async (workspaceResponse) => {
              if (!workspaceResponse.ok || window.location.search.includes('view=console')) {
                setMode('demo')
                return
              }
              setWorkspace(await workspaceResponse.json())
              setMode('workspace')
            })
            .catch(() => setMode('demo'))
          return
        }
        setBootstrap(await response.json())
        setMode('connected')
      })
      .catch(() => setMode('demo'))
  }, [])

  if (mode === 'loading') return null
  if (mode === 'connected' && bootstrap) return <ConnectedApp bootstrap={bootstrap} />
  if (mode === 'workspace' && workspace) return <WorkspaceApp bootstrap={workspace} />
  return <App />
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
)

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { chromium } from 'playwright'

const url = 'http://127.0.0.1:8767/'
const python =
  process.env.AEGIS_PYTHON ??
  (process.platform === 'win32' ? '.venv/Scripts/python.exe' : 'python3')
const chrome =
  process.env.AEGIS_CHROME ??
  (process.platform === 'win32'
    ? 'C:/Program Files/Google/Chrome/Application/chrome.exe'
    : undefined)
const server = spawn(python, ['-m', 'tests.api.browser_workspace_server'], {
  cwd: '..',
  stdio: 'ignore',
  windowsHide: true,
})

async function waitForServer() {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (server.exitCode !== null) throw new Error(`Browser fixture exited with ${server.exitCode}`)
    try {
      if ((await fetch(`${url}healthz`)).ok) return
    } catch {
      /* retry */
    }
    await new Promise((resolve) => setTimeout(resolve, 200))
  }
  throw new Error('Browser fixture did not start')
}

let browser
try {
  await waitForServer()
  browser = await chromium.launch({ executablePath: chrome, headless: true })
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
  await page.goto(url)
  await page.getByRole('heading', { name: 'Ask about this project' }).waitFor()
  await page.getByLabel('What do you want to know?').fill('Where is routing implemented?')
  await page.getByRole('button', { name: 'Run agent' }).click()
  await page.getByText('Routing is implemented in src/aegis/main.py.').waitFor()
  await page.locator('[aria-label="Task step timeline"]').getByText('TOOL_CALL').waitFor()
  assert.ok(await page.getByText('README.md').first().isVisible())
} finally {
  await browser?.close()
  server.kill()
}

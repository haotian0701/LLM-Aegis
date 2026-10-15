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
  await page.getByRole('heading', { name: 'Decision Console' }).waitFor()
  await page.getByRole('checkbox', { name: /Use project files/ }).check()
  await page.locator('#message').fill('Where is routing implemented?')
  await page.getByRole('button', { name: 'Run with project files' }).click()
  await page.getByRole('heading', { name: 'Agent task completed' }).waitFor()
  await page.getByText('Routing is implemented in src/aegis/main.py.').waitFor()
  await page.locator('#decision').getByText('Files used').waitFor()
  assert.match(await page.locator('#decision li code').first().innerText(), /\.py$/)
  await page.screenshot({ path: '../.tools/browser-workspace.png', fullPage: true })
  const drawer = page.getByRole('dialog', { name: 'Audit record details' })
  await page.locator('#audit tbody tr').first().getByRole('button', { name: 'Inspect' }).click()
  await drawer.getByRole('region', { name: 'Task step timeline' }).getByText('TOOL_CALL').waitFor()
  await drawer.getByRole('button', { name: 'Close' }).click()

  await page.locator('#message').fill('Read .env')
  await page.getByRole('button', { name: 'Run with project files' }).click()
  await page.getByRole('heading', { name: 'Agent task failed' }).waitFor()
  await drawer.getByText('TOOL_CALL').last().waitFor()
  await drawer.getByText('Executed: No').waitFor()
  assert.ok(await drawer.getByText('TOOL_DENIED').first().isVisible())
  await drawer.getByRole('button', { name: 'Close' }).click()
  await page.setViewportSize({ width: 390, height: 844 })
  assert.equal(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
    true,
  )
} finally {
  await browser?.close()
  server.kill()
}

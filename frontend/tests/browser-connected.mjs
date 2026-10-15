import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { chromium } from 'playwright'

const url = 'http://127.0.0.1:8766/'
const python =
  process.env.AEGIS_PYTHON ??
  (process.platform === 'win32' ? '.venv/Scripts/python.exe' : 'python3')
const chrome =
  process.env.AEGIS_CHROME ??
  (process.platform === 'win32'
    ? 'C:/Program Files/Google/Chrome/Application/chrome.exe'
    : undefined)
const server = spawn(python, ['-m', 'tests.api.browser_connected_server'], {
  cwd: '..',
  stdio: 'ignore',
  windowsHide: true,
})

async function waitForServer() {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (server.exitCode !== null)
      throw new Error(`Connected fixture exited with ${server.exitCode}`)
    try {
      if ((await fetch(`${url}healthz`)).ok) return
    } catch {
      /* retry */
    }
    await new Promise((resolve) => setTimeout(resolve, 200))
  }
  throw new Error('Connected fixture did not start')
}

let browser
try {
  await waitForServer()
  browser = await chromium.launch({ executablePath: chrome, headless: true })
  const page = await browser.newPage({ viewport: { width: 1350, height: 900 } })
  await page.goto(url)
  await page.getByRole('heading', { name: 'GitHub Issue assistant' }).waitFor()
  assert.equal(await page.getByText('Deterministic fixture').count(), 0)
  assert.equal(await page.getByText('Controlled task').count(), 0)
  await page.getByLabel('Aegis API key').fill('alice-secret-token')
  await page.getByLabel('GitHub Issue URL').fill('https://github.com/alice/sandbox/issues/4')
  await page.getByLabel('What should the assistant do?').fill('Summarize the issue.')
  await page.getByRole('button', { name: 'Run workflow' }).click()
  await page.getByText('The issue needs investigation.').waitFor()
  await page.getByRole('heading', { name: /Task [0-9a-f]{32}/ }).waitFor()
  await page.getByRole('heading', { name: 'Sources' }).waitFor()

  await page.getByLabel('What should the assistant do?').fill('Draft a comment on this issue.')
  await page.getByRole('button', { name: 'Run workflow' }).click()
  await page.getByText('I will investigate this bug.').waitFor()
  await page.getByRole('button', { name: 'Deny' }).click()
  await page.getByText('Comment rejected.').waitFor()
  await page.getByText('No proposed writes.').waitFor()

  await page
    .getByLabel('What should the assistant do?')
    .fill('Draft another comment on this issue.')
  await page.getByRole('button', { name: 'Run workflow' }).click()
  await page.getByRole('button', { name: 'Approve and post' }).click()
  await page.getByText('Comment posted to GitHub.').waitFor()
  await page.getByText('No proposed writes.').waitFor()
  await page.setViewportSize({ width: 390, height: 844 })
  assert.equal(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
    true,
  )
  console.log('Connected browser smoke passed: Issue read, timeline, deny, approve, narrow layout.')
} finally {
  await browser?.close()
  server.kill()
}

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { chromium } from 'playwright'

const url = 'http://127.0.0.1:8765/'
const python = process.env.AEGIS_PYTHON ?? '.venv/Scripts/python.exe'
const chrome = process.env.AEGIS_CHROME ?? 'C:/Program Files/Google/Chrome/Application/chrome.exe'
const server = spawn(python, ['tests/browser_demo_server.py'], {
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
  for (const [sample, result] of [
    ['Expected CLOUD decision', 'Cloud route'],
    ['Expected MASK_CLOUD decision', 'Masked cloud route'],
    ['Expected BLOCK decision', 'Blocked by policy'],
  ]) {
    await page.getByRole('button', { name: 'New conversation' }).click()
    await page.getByText(sample).click()
    await page.getByRole('button', { name: 'Send request' }).click()
    await page.getByRole('heading', { name: result }).waitFor()
    assert.ok(
      await page
        .locator('#decision')
        .getByText(/Request ID/)
        .isVisible(),
    )
  }
  const blockedConversationId = await page.locator('#conversation-lookup').inputValue()
  await page.locator('#conversation').getByText('SENSITIVE', { exact: true }).first().waitFor()
  await page.getByText('Reuses the current conversation').click()
  await page.getByRole('button', { name: 'Send request' }).click()
  await page.getByRole('heading', { name: 'Cloud-simulated local route' }).waitFor()
  assert.equal(await page.locator('#conversation-lookup').inputValue(), blockedConversationId)
  await page.getByText('SENSITIVE', { exact: true }).first().waitFor()
  const requestId = await page.locator('#lookup').inputValue()
  assert.match(requestId, /^[0-9a-f]{32}$/)
  await page.getByRole('button', { name: 'Find', exact: true }).click()
  await page.getByText('SELECTED AUDIT RECORD').waitFor()
  await page.locator('#lookup').fill('f'.repeat(32))
  await page.getByRole('button', { name: 'Find', exact: true }).click()
  await page.getByText('Audit record was not found.').waitFor()
  await page.locator('#lookup').fill(requestId)
  await page.getByRole('button', { name: 'Find', exact: true }).click()
  await page.getByText('SELECTED AUDIT RECORD').waitFor()
  await page.getByRole('button', { name: 'Apply filters' }).click()
  await page.getByText(requestId).first().waitFor()
  await page.screenshot({ path: '../.tools/browser-wide.png', fullPage: true })

  await page.getByRole('button', { name: 'New conversation' }).click()
  await page.getByRole('button', { name: 'Continuous chat' }).click()
  await page.locator('#message').fill('First chat turn')
  await page.getByRole('button', { name: 'Send request' }).click()
  await page.getByRole('heading', { name: 'Cloud route' }).waitFor()
  await page.locator('#message').fill('Second chat turn')
  await page.locator('summary').click()
  await page.getByText('3 messages', { exact: true }).waitFor()
  assert.ok(await page.getByText('First chat turn').first().isVisible())

  await page.setViewportSize({ width: 390, height: 844 })
  assert.equal(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
    true,
  )
  await page.getByRole('button', { name: 'New conversation' }).focus()
  await page.keyboard.press('Enter')
  assert.equal(await page.locator('#conversation-lookup').inputValue(), '')
  await page.screenshot({ path: '../.tools/browser-narrow.png', fullPage: true })
  console.log(
    'Browser smoke passed: four routes, audit lookup, chat preview, narrow layout, keyboard action.',
  )
} finally {
  await browser?.close()
  server.kill()
}

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { chromium } from 'playwright'

const url = 'http://127.0.0.1:8765/'
const python =
  process.env.AEGIS_PYTHON ??
  (process.platform === 'win32' ? '.venv/Scripts/python.exe' : 'python3')
const chrome =
  process.env.AEGIS_CHROME ??
  (process.platform === 'win32'
    ? 'C:/Program Files/Google/Chrome/Application/chrome.exe'
    : undefined)
const server = spawn(python, ['-m', 'tests.api.browser_demo_server'], {
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
  assert.equal(await page.getByRole('checkbox', { name: /Use project files/ }).count(), 0)
  const drawer = page.getByRole('dialog', { name: 'Audit record details' })
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
    if (sample === 'Expected MASK_CLOUD decision') {
      await page.getByRole('button', { name: 'Find', exact: true }).click()
      const preview = drawer.getByRole('region', { name: 'Masked model messages' })
      await preview.getByText('Masked messages prepared for model').waitFor()
      assert.match(await preview.locator('pre').innerText(), /\[\[AEGIS_[A-F0-9]{24}_EMAIL_001\]\]/)
      assert.doesNotMatch(await preview.locator('pre').innerText(), /demo\.user@example\.com/)
      await drawer.getByRole('button', { name: 'Close' }).click()
    }
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
  await drawer.getByText('SELECTED AUDIT RECORD').waitFor()
  assert.ok((await drawer.boundingBox()).x > 800)
  await page.keyboard.press('Escape')
  await drawer.waitFor({ state: 'hidden' })
  await page.locator('#lookup').fill('f'.repeat(32))
  await page.getByRole('button', { name: 'Find', exact: true }).click()
  await drawer.getByText('Audit record was not found.').waitFor()
  await drawer.getByRole('button', { name: 'Close' }).click()
  await page.locator('#lookup').fill(requestId)
  await page.getByRole('button', { name: 'Find', exact: true }).click()
  await drawer.getByText('SELECTED AUDIT RECORD').waitFor()
  await drawer.getByRole('button', { name: 'Close' }).click()
  await page.getByRole('button', { name: 'Apply filters' }).click()
  await page.getByText(requestId).first().waitFor()
  await page.locator('#audit tbody tr').first().getByRole('button', { name: 'Inspect' }).click()
  await drawer.getByText('SELECTED AUDIT RECORD').waitFor()
  const listScrollPosition = await page.evaluate(() => window.scrollY)
  await drawer.getByRole('button', { name: 'Close' }).click()
  assert.equal(await page.evaluate(() => window.scrollY), listScrollPosition)
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
  await page.locator('#audit tbody tr').first().getByRole('button', { name: 'Inspect' }).click()
  await drawer.getByText('SELECTED AUDIT RECORD').waitFor()
  const mobileDrawer = await drawer.boundingBox()
  assert.equal(Math.round(mobileDrawer.x), 0)
  assert.equal(Math.round(mobileDrawer.width), 390)
  await page.keyboard.press('Escape')
  await drawer.waitFor({ state: 'hidden' })
  assert.equal(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
    true,
  )
  await page.getByRole('button', { name: 'New conversation' }).focus()
  await page.keyboard.press('Enter')
  assert.equal(await page.locator('#conversation-lookup').inputValue(), '')
  await page.screenshot({ path: '../.tools/browser-narrow.png', fullPage: true })
  console.log(
    'Browser smoke passed: four routes, audit inspect, chat preview, narrow layout, keyboard action.',
  )
} finally {
  await browser?.close()
  server.kill()
}

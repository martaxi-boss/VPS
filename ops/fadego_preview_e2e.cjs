/* FADEGO local-only interactive demo: real browser regression proof, never contacts FADEGO live APIs. */
const assert = require("node:assert/strict")
const { resolve } = require("node:path")
const { chromium } = require("/tmp/fadego-preview-playwright/node_modules/playwright")

async function main() {
  const browser = await chromium.launch({
    channel: "chrome", headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  })
  try {
    const page = await browser.newPage({
      viewport: { width: 390, height: 844 },
      locale: "pt-PT",
      timezoneId: "Europe/Lisbon",
    })
    const errors = []
    page.on("pageerror", (error) => errors.push(error.message))
    const url = process.env.FADEGO_PREVIEW_TEST_URL || ("file://" + resolve("ops/fadego_preview.html"))
    await page.goto(url, { waitUntil: "load" })
    await page.getByText("Uma agenda leve.").first().waitFor()

    await page.locator('nav [data-view="barbearia"]').click()
    await page.getByRole("heading", { name: "Visão geral" }).waitFor()
    await page.locator('aside [data-nav="servicos"]').click()
    await page.locator('form[data-form="service"] input[name="name"]').fill("Lavagem de teste")
    await page.locator('form[data-form="service"] button').click()
    await page.getByText("Lavagem de teste").waitFor()

    await page.locator('nav [data-view="cliente"]').click()
    await page.getByRole("heading", { name: "Marca o próximo corte." }).waitFor()
    await page.locator('form[data-form="booking"] input[name="name"]').fill("Cliente da demonstração")
    await page.locator('form[data-form="booking"] input[name="email"]').fill("teste@example.test")
    await page.locator('form[data-form="booking"] button.primary').click()
    await page.getByText(/Reserva fictícia criada/).waitFor()

    await page.locator('nav [data-view="barbearia"]').click()
    await page.locator('aside [data-nav="agenda"]').click()
    await page.getByText(/Cliente da demonstração/).first().waitFor()
    await page.locator('nav [data-view="plataforma"]').click()
    await page.getByText("Visão geral FADEGO").first().waitFor()

    const dimensions = await page.evaluate(() => ({
      width: document.documentElement.clientWidth,
      total: document.documentElement.scrollWidth,
    }))
    assert.ok(dimensions.total <= dimensions.width + 2, JSON.stringify(dimensions))
    assert.deepEqual(errors, [])
    await page.screenshot({ path: process.env.RUNNER_TEMP + "/fadego-mobile-qa.png", fullPage: true })
    console.log("FADEGO_PREVIEW_REAL_BROWSER=PASS; mobile, menus, services, booking, agenda and owner panel")
  } finally {
    await browser.close()
  }
}
main().catch((err) => { console.error(err.message); process.exitCode = 1 })

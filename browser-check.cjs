#!/usr/bin/env node

const { chromium } = require("/usr/local/lib/node_modules/playwright");

function parseArgs(argv) {
  const options = { waitMs: 500, includeDom: false };
  for (let index = 0; index < argv.length; index += 1) {
    switch (argv[index]) {
      case "--url":
        options.url = argv[++index];
        break;
      case "--wait-ms":
        options.waitMs = Number.parseInt(argv[++index], 10);
        break;
      case "--include-dom":
        options.includeDom = true;
        break;
      default:
        throw new Error(`unknown argument: ${argv[index]}`);
    }
  }
  if (!options.url) {
    throw new Error("--url is required");
  }
  if (!Number.isInteger(options.waitMs) || options.waitMs < 0) {
    throw new Error("--wait-ms must be a non-negative integer");
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium",
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  try {
    const page = await browser.newPage();
    const dialogs = [];
    const consoleMessages = [];
    const pageErrors = [];
    page.on("dialog", async (dialog) => {
      dialogs.push({ type: dialog.type(), message: dialog.message() });
      await dialog.dismiss();
    });
    page.on("console", (message) => {
      consoleMessages.push({ type: message.type(), text: message.text() });
    });
    page.on("pageerror", (error) => pageErrors.push(error.message));

    const response = await page.goto(options.url, {
      waitUntil: "domcontentloaded",
      timeout: 60_000,
    });
    await page.waitForTimeout(options.waitMs);
    const result = {
      requestedUrl: options.url,
      finalUrl: page.url(),
      status: response ? response.status() : null,
      title: await page.title(),
      dialogs,
      console: consoleMessages,
      pageErrors,
    };
    if (options.includeDom) {
      const dom = await page.content();
      result.dom = dom.slice(0, 200_000);
      result.domTruncated = dom.length > 200_000;
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});

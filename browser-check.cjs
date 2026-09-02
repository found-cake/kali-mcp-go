#!/usr/bin/env node

const { chromium } = require("/usr/local/lib/node_modules/playwright");
const { writeFile } = require("node:fs/promises");
const {
  browserLaunchOptions,
  createBoundedCollector,
  truncateEvidenceText,
} = require("./browser-evidence.cjs");

const maxEvidenceEvents = 100;

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
      case "--capture-network":
        options.captureNetwork = true;
        break;
      case "--capture-screenshot":
        options.captureScreenshot = true;
        break;
      case "--screenshot-path":
        options.screenshotPath = argv[++index];
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
  const executablePath = process.env.CHROMIUM_PATH || "/usr/bin/chromium";
  const browser = await chromium.launch(browserLaunchOptions(executablePath));
  try {
    const page = await browser.newPage();
    const dialogs = createBoundedCollector(maxEvidenceEvents);
    const consoleMessages = createBoundedCollector(maxEvidenceEvents);
    const pageErrors = createBoundedCollector(maxEvidenceEvents);
    const network = createBoundedCollector(maxEvidenceEvents);
    const recordNetwork = (event) => {
      if (!options.captureNetwork) return;
      network.record(event);
    };
    page.on("dialog", async (dialog) => {
      dialogs.record({ type: dialog.type(), message: truncateEvidenceText(dialog.message(), 2048) });
      await dialog.dismiss();
    });
    page.on("console", (message) => {
      consoleMessages.record({ type: message.type(), text: truncateEvidenceText(message.text(), 4096) });
    });
    page.on("pageerror", (error) => pageErrors.record(truncateEvidenceText(error.message, 4096)));
    page.on("response", (response) => {
      const request = response.request();
      recordNetwork({
        method: request.method(),
        url: redactQueryValues(request.url()).slice(0, 2048),
        resourceType: request.resourceType(),
        status: response.status(),
      });
    });
    page.on("requestfailed", (request) => {
      recordNetwork({
        method: request.method(),
        url: redactQueryValues(request.url()).slice(0, 2048),
        resourceType: request.resourceType(),
        status: null,
        failure: (request.failure()?.errorText || "request_failed").slice(0, 512),
      });
    });

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
      dialogs: dialogs.items,
      dialogsTruncated: dialogs.truncated,
      console: consoleMessages.items,
      consoleTruncated: consoleMessages.truncated,
      pageErrors: pageErrors.items,
      pageErrorsTruncated: pageErrors.truncated,
      networkCaptured: options.captureNetwork,
      network: network.items,
      networkTruncated: network.truncated,
    };
    if (options.includeDom) {
      const dom = await page.content();
      result.dom = dom.slice(0, 200_000);
      result.domTruncated = dom.length > 200_000;
    }
    if (options.captureScreenshot) {
      if (!options.screenshotPath) throw new Error("--screenshot-path is required with --capture-screenshot");
      const screenshot = await page.screenshot({ type: "jpeg", quality: 50, fullPage: false });
      if (screenshot.length <= 512 * 1024) {
        await writeFile(options.screenshotPath, screenshot, { mode: 0o600 });
        result.screenshotCaptured = true;
        result.screenshotMediaType = "image/jpeg";
      } else {
        result.screenshotError = "screenshot_exceeds_512kb";
      }
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    await browser.close();
  }
}

function redactQueryValues(value) {
  try {
    const parsed = new URL(value);
    for (const name of new Set(parsed.searchParams.keys())) {
      parsed.searchParams.set(name, "[REDACTED]");
    }
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return "[INVALID_URL]";
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});

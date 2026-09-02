const assert = require("node:assert/strict");
const test = require("node:test");

const {
  browserLaunchOptions,
  createBoundedCollector,
  truncateEvidenceText,
} = require("./browser-evidence.cjs");

test("collector rejects events after its evidence limit", () => {
  const collector = createBoundedCollector(2);

  assert.equal(collector.record("first"), true);
  assert.equal(collector.record("second"), true);
  assert.equal(collector.record("third"), false);

  assert.deepEqual(collector.items, ["first", "second"]);
  assert.equal(collector.truncated, true);
});

test("text evidence is limited to the configured length", () => {
  assert.equal(truncateEvidenceText("abcdef", 4), "abcd");
});

test("browser launch keeps the Chromium sandbox enabled", () => {
  const options = browserLaunchOptions("/usr/bin/chromium");

  assert.equal(options.chromiumSandbox, true);
  assert.equal(options.args.includes("--no-sandbox"), false);
});

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  browserLaunchOptions,
  createBoundedCollector,
  navigationEvidence,
  networkEvidenceURL,
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

test("navigation evidence reports the main document response", () => {
  // Given: Chromium returned a response for the main document navigation.
  const response = {
    status: () => 200,
    url: () => "https://example.test/app",
  };

  // When: the response is normalized for browser evidence.
  const evidence = navigationEvidence(response);

  // Then: consumers receive the response URL and HTTP status explicitly.
  assert.deepEqual(evidence, {
    navigationResponseReceived: true,
    navigationStatus: 200,
    navigationResponseUrl: "https://example.test/app",
  });
});

test("navigation evidence distinguishes same-document routes without a response", () => {
  // Given: a same-document or fragment navigation returned no new response.
  const response = null;

  // When: the missing response is normalized for browser evidence.
  const evidence = navigationEvidence(response);

  // Then: null status is not confused with a failed HTTP response.
  assert.deepEqual(evidence, {
    navigationResponseReceived: false,
    navigationStatus: null,
    navigationResponseUrl: null,
  });
});

test("network evidence preserves raw query and fragment values", () => {
  // Given: a browser request URL carrying reproducibility and fragment evidence.
  const url = "https://example.test/main.js?v=build-42&token=test-secret#/search?q=xss";

  // When: the URL is bounded for network evidence.
  const evidence = networkEvidenceURL(url);

  // Then: the browser value remains exact when no caller redaction was requested.
  assert.equal(evidence, url);
});

function createBoundedCollector(limit) {
  const items = [];
  let truncated = false;
  return {
    items,
    get truncated() {
      return truncated;
    },
    record(value) {
      if (items.length >= limit) {
        truncated = true;
        return false;
      }
      items.push(value);
      return true;
    },
  };
}

function truncateEvidenceText(value, limit) {
  return String(value).slice(0, limit);
}

function browserLaunchOptions(executablePath) {
  return {
    executablePath,
    headless: true,
    chromiumSandbox: true,
    args: ["--disable-dev-shm-usage"],
  };
}

module.exports = { browserLaunchOptions, createBoundedCollector, truncateEvidenceText };

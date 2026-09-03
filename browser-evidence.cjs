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

function networkEvidenceURL(value) {
  return truncateEvidenceText(value, 2048);
}

function browserLaunchOptions(executablePath) {
  return {
    executablePath,
    headless: true,
    chromiumSandbox: true,
    args: ["--disable-dev-shm-usage"],
  };
}

function navigationEvidence(response) {
  if (!response) {
    return {
      navigationResponseReceived: false,
      navigationStatus: null,
      navigationResponseUrl: null,
    };
  }
  return {
    navigationResponseReceived: true,
    navigationStatus: response.status(),
    navigationResponseUrl: response.url(),
  };
}

module.exports = {
  browserLaunchOptions,
  createBoundedCollector,
  navigationEvidence,
  networkEvidenceURL,
  truncateEvidenceText,
};

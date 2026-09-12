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

function browserAuthentication(headers, targetURL) {
  const extraHTTPHeaders = {};
  const cookies = [];
  const origin = new URL(targetURL).origin;

  for (const [name, value] of Object.entries(headers || {})) {
    if (name.toLowerCase() !== "cookie") {
      extraHTTPHeaders[name] = value;
      continue;
    }
    for (const segment of value.split(";")) {
      const separator = segment.indexOf("=");
      const cookieName = segment.slice(0, separator).trim();
      if (separator <= 0 || cookieName === "") {
        throw new Error("Cookie header must contain name=value pairs");
      }
      cookies.push({
        name: cookieName,
        value: segment.slice(separator + 1).trim(),
        url: origin,
      });
    }
  }
  return { extraHTTPHeaders, cookies };
}

function browserRequestInScope(requestURL, targetURL) {
  return new URL(requestURL).origin === new URL(targetURL).origin;
}

function initializeLocalStorage(payload, locationValue = window.location, storage = window.localStorage) {
  if (locationValue.origin !== payload.origin) return;
  for (const [key, value] of payload.entries) {
    storage.setItem(key, value);
  }
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
  browserAuthentication,
  browserLaunchOptions,
  browserRequestInScope,
  createBoundedCollector,
  initializeLocalStorage,
  navigationEvidence,
  networkEvidenceURL,
  truncateEvidenceText,
};

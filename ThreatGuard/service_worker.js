const allowOnce = new Map();
const allowDurationMs = 60 * 1000;

const isExtensionUrl = (url) => url.startsWith(chrome.runtime.getURL(""));

const isAllowedOnce = (url) => {
  const entry = allowOnce.get(url);
  if (!entry) {
    return false;
  }
  if (Date.now() - entry > allowDurationMs) {
    allowOnce.delete(url);
    return false;
  }
  allowOnce.delete(url);
  return true;
};

const buildWarningUrl = (url, score) => {
  const params = new URLSearchParams({
    url,
    score: String(score)
  });
  return chrome.runtime.getURL(`warning.html?${params.toString()}`);
};

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (isExtensionUrl(details.url)) {
      return {};
    }

    if (isAllowedOnce(details.url)) {
      return {};
    }

    const score = Math.floor(Math.random() * 101);

    if (score < 20) {
      return {};
    }

    const redirectUrl = buildWarningUrl(details.url, score);
    return { redirectUrl };
  },
  { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] },
  ["blocking"]
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "ALLOW_ONCE" && typeof message.url === "string") {
    allowOnce.set(message.url, Date.now());
    sendResponse({ ok: true });
    return true;
  }

  sendResponse({ ok: false });
  return false;
});

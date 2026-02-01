const statusEl = document.getElementById("status");

const getTabId = async () => {
  try {
    const tab = await chrome.tabs.getCurrent();
    if (tab?.id != null) {
      return tab.id;
    }
  } catch (error) {
    console.warn("Unable to read current tab.", error);
  }

  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return activeTab?.id ?? null;
};

const requestScore = async () => {
  const tabId = await getTabId();
  if (tabId == null) {
    statusEl.textContent = "Unable to find the current tab.";
    return;
  }
  const response = await chrome.runtime.sendMessage({ type: "CHECK_URL", tabId });
  if (!response?.ok) {
    statusEl.textContent = "Unable to check the URL. Please try again.";
  }
};

requestScore().catch((error) => {
  console.warn("Failed to request score.", error);
  statusEl.textContent = "Unable to check the URL. Please try again.";
});

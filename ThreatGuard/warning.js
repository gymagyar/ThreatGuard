const params = new URLSearchParams(window.location.search);
let url = params.get("url") || "";
let score = Number(params.get("score"));

const targetEl = document.getElementById("targetUrl");
const messageEl = document.getElementById("message");
const continueBtn = document.getElementById("continueBtn");

const loadBlockedInfo = async () => {
  if (url) {
    return { url, score };
  }
  const tab = await chrome.tabs.getCurrent();
  if (!tab?.id) {
    return { url: "", score: Number.NaN };
  }
  const response = await chrome.runtime.sendMessage({
    type: "GET_BLOCK_INFO",
    tabId: tab.id
  });
  if (response?.ok && response.entry) {
    return {
      url: response.entry.url || "",
      score: Number(response.entry.score)
    };
  }
  return { url: "", score: Number.NaN };
};

const init = async () => {
  const result = await loadBlockedInfo();
  url = result.url;
  score = result.score;

  targetEl.textContent = url;

  if (Number.isNaN(score)) {
    messageEl.textContent = "ThreatGuard could not score this site.";
    continueBtn.hidden = true;
  } else if (score < 60) {
    const details = document.createElement("details");
    details.className = "details";
    const summary = document.createElement("summary");
    summary.textContent = "Potentially risky site, click continue to proceed";
    const info = document.createElement("p");
    info.textContent = `Threat score: ${score}/100`;
    details.append(summary, info);
    messageEl.append(details);

    continueBtn.addEventListener("click", async () => {
      await chrome.runtime.sendMessage({ type: "ALLOW_ONCE", url });
      window.location.replace(url);
    });
  } else {
    const message = document.createElement("p");
    message.className = "message";
    message.textContent = "Site is a potential phishing site. Access to it blocked";
    messageEl.append(message);
    continueBtn.hidden = true;
  }
};

init().catch((error) => {
  console.warn("Failed to load blocked info.", error);
  messageEl.textContent = "ThreatGuard could not score this site.";
  continueBtn.hidden = true;
});

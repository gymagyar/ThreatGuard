const params = new URLSearchParams(window.location.search);
const url = params.get("url") || "";
const score = Number(params.get("score"));

const targetEl = document.getElementById("targetUrl");
const messageEl = document.getElementById("message");
const continueBtn = document.getElementById("continueBtn");

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

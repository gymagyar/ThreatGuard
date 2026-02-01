const toggleBtn = document.getElementById("toggleOptions");
const optionsPanel = document.getElementById("optionsPanel");
const scoreOptions = Array.from(
  document.querySelectorAll('input[name="scoreSource"]')
);
const scoreModeKey = "scoreMode";
const gtiApiKeyInput = document.getElementById("gtiApiKey");
const gtiApiKeyKey = "gtiApiKey";
const toggleGtiKeyBtn = document.getElementById("toggleGtiKey");
const kpiCached = document.getElementById("kpiCached");
const kpiDailyLoads = document.getElementById("kpiDailyLoads");
const kpiGtiAvg = document.getElementById("kpiGtiAvg");
const scoreStoreKey = "cachedScores";
const dailyPageLoadDateKey = "dailyPageLoadDate";
const dailyPageLoadCountKey = "dailyPageLoadCount";
const gtiTimingKey = "gtiTiming";

const getLocalDateKey = () => {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
};

const setExpanded = (expanded) => {
  toggleBtn.setAttribute("aria-expanded", String(expanded));
  optionsPanel.hidden = !expanded;
};

toggleBtn.addEventListener("click", () => {
  const expanded = toggleBtn.getAttribute("aria-expanded") === "true";
  setExpanded(!expanded);
});

const updateSelection = (mode) => {
  scoreOptions.forEach((option) => {
    option.checked = option.value === mode;
  });
};

chrome.storage.local
  .get({
    [scoreModeKey]: "demo",
    [gtiApiKeyKey]: "",
    [scoreStoreKey]: [],
    [dailyPageLoadDateKey]: "",
    [dailyPageLoadCountKey]: 0,
    [gtiTimingKey]: { totalMs: 0, count: 0 }
  })
  .then((data) => {
    updateSelection(data[scoreModeKey] || "demo");
    gtiApiKeyInput.value = data[gtiApiKeyKey] || "";
    const cached = Array.isArray(data[scoreStoreKey]) ? data[scoreStoreKey].length : 0;
    kpiCached.textContent = String(cached);
    const today = getLocalDateKey();
    const dailyCount =
      data[dailyPageLoadDateKey] === today
        ? Number(data[dailyPageLoadCountKey] || 0)
        : 0;
    kpiDailyLoads.textContent = String(dailyCount);
    const timing = data[gtiTimingKey] || { totalMs: 0, count: 0 };
    const avg =
      timing.count > 0 ? `${(timing.totalMs / timing.count).toFixed(1)} ms` : "–";
    kpiGtiAvg.textContent = avg;
  });

scoreOptions.forEach((option) => {
  option.addEventListener("change", () => {
    if (option.checked) {
      chrome.storage.local.set({ [scoreModeKey]: option.value });
    }
  });
});

gtiApiKeyInput.addEventListener("input", () => {
  chrome.storage.local.set({ [gtiApiKeyKey]: gtiApiKeyInput.value });
});

toggleGtiKeyBtn.addEventListener("click", () => {
  const isHidden = gtiApiKeyInput.type === "password";
  gtiApiKeyInput.type = isHidden ? "text" : "password";
  toggleGtiKeyBtn.setAttribute(
    "aria-label",
    isHidden ? "Hide GTI API Key" : "Show GTI API Key"
  );
  toggleGtiKeyBtn.title = isHidden ? "Hide GTI API Key" : "Show GTI API Key";
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") {
    return;
  }
  if (changes[scoreStoreKey]?.newValue) {
    const cached = Array.isArray(changes[scoreStoreKey].newValue)
      ? changes[scoreStoreKey].newValue.length
      : 0;
    kpiCached.textContent = String(cached);
  }
  if (changes[dailyPageLoadCountKey]?.newValue !== undefined) {
    const today = getLocalDateKey();
    const storedDate = changes[dailyPageLoadDateKey]?.newValue;
    const count = changes[dailyPageLoadCountKey].newValue || 0;
    kpiDailyLoads.textContent =
      storedDate && storedDate !== today ? "0" : String(count);
  }
  if (changes[dailyPageLoadDateKey]?.newValue) {
    const today = getLocalDateKey();
    if (changes[dailyPageLoadDateKey].newValue !== today) {
      kpiDailyLoads.textContent = "0";
    }
  }
  if (changes[gtiTimingKey]?.newValue) {
    const timing = changes[gtiTimingKey].newValue || { totalMs: 0, count: 0 };
    const avg =
      timing.count > 0 ? `${(timing.totalMs / timing.count).toFixed(1)} ms` : "–";
    kpiGtiAvg.textContent = avg;
  }
});

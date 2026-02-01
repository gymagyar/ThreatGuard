const allowDurationMs = 60 * 1000;
const lastScoredByTab = new Map();
const blockedUrls = new Set();
const allowUrls = new Map();
const cachedScores = new Map();
const pendingUrls = new Map();
const blockedInfoByTab = new Map();
const blockedStoreKey = "blockedUrls";
const allowStoreKey = "allowUrls";
const scoreStoreKey = "cachedScores";
const pendingStoreKey = "pendingUrls";
const blockedInfoStoreKey = "blockedInfoByTab";
const scoreModeKey = "scoreMode";
const gtiApiKeyKey = "gtiApiKey";
const dailyPageLoadDateKey = "dailyPageLoadDate";
const dailyPageLoadCountKey = "dailyPageLoadCount";
const gtiTimingKey = "gtiTiming";
const blockThreshold = 60;
let scoreMode = "demo";
let gtiApiKey = "";

const isExtensionUrl = (url) => url.startsWith(chrome.runtime.getURL(""));
const isRestrictedUrl = (url) =>
  url.startsWith("chrome://") ||
  url.startsWith("devtools://") ||
  url.startsWith("chrome-extension://");
const generateScoreDemo = (url) => {
  const score = Math.floor(Math.random() * 101);
  if (url) {
    console.log(`Threat score generated for URL:`);
    console.log(`  ${url}`);
    console.log(`Score: ${score}/100`);
  } else {
    console.log(`Threat score generated: ${score}/100`);
  }
  return score;
};


// UTF-8 safe Base64
function urlSafeBase64Encode(str) {
  const utf8Bytes = new TextEncoder().encode(str);

  let binary = "";
  utf8Bytes.forEach(b => {
    binary += String.fromCharCode(b);
  });

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, ""); // strip "="
}

const getGTIScore = async (url) => {
  console.log("GTI threat score for URL:");
  console.log(`  ${url}`);
  const urlToCheck = urlSafeBase64Encode(url);
  const apiUrl = "https://www.virustotal.com/api/v3/urls/" + urlToCheck;

  const headers = {
    accept: "application/json",
    "X-Apikey": gtiApiKey, // ⚠️ don’t hardcode in production
  };

  const response = await fetch(apiUrl, { headers });
  const responseText = await response.text();
  // Treat VT "URL not found" as score 0 instead of raising an error.
  if (response.status === 404) {
    console.warn("GTI URL not found, treating score as 0.");
    return 0;
  }
  if (!response.ok) {
    throw new Error(`GTI request failed (${response.status}): ${responseText}`);
  }
  const data = JSON.parse(responseText);

    const stats =
      data?.data?.attributes?.last_analysis_stats ?? {};

    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);

    const total = malicious + suspicious + harmless + undetected;
    const score = total
      ? Math.round(((malicious + suspicious) / total) * 100)
      : 0;
  const attributes = data?.data?.attributes || {};
  const lastAnalysisDate = attributes.last_analysis_date;
  if (lastAnalysisDate) {
    console.log("Last analysis date (raw):",lastAnalysisDate);
    console.log("Last analysis date (ISO):",new Date(lastAnalysisDate * 1000).toISOString());
  } else {
    console.log("Last analysis date: not available");
  }
  console.log("Stats:", stats);
  console.log(`Score: ${score}/100`);
  return score;
};



const buildWarningUrl = (url, score) => {
  const params = new URLSearchParams({
    url,
    score: String(score)
  });
  return chrome.runtime.getURL(`warning.html?${params.toString()}`);
};

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const buildRuleId = (prefix, url) => {
  const input = `${prefix}:${url}`;
  let hash = 2166136261;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  const id = hash & 0x7fffffff;
  if (id <= 1) {
    return id + 2;
  }
  return id;
};

const buildBlockRule = (url, score = blockThreshold) => {
  return {
    id: buildRuleId("block", url),
    priority: 3,
    action: {
      type: "redirect",
      redirect: {
        extensionPath: "/warning.html"
      }
    },
    condition: {
      regexFilter: `^${escapeRegex(url)}$`,
      resourceTypes: ["main_frame"]
    }
  };
};

const buildAllowRule = (url) => ({
  id: buildRuleId("allow", url),
  priority: 2,
  action: { type: "allow" },
  condition: {
    regexFilter: `^${escapeRegex(url)}$`,
    resourceTypes: ["main_frame"]
  }
});

const buildGlobalRedirectRule = () => ({
  id: 1,
  priority: 1,
  action: {
    type: "redirect",
    redirect: {
      extensionPath: "/checking.html"
    }
  },
  condition: {
    regexFilter: "^https?://.*",
    resourceTypes: ["main_frame"]
  }
});

const syncDynamicRules = async () => {
  const desiredRules = [
    buildGlobalRedirectRule(),
    ...Array.from(blockedUrls, (url) => buildBlockRule(url)),
    ...Array.from(allowUrls.keys(), (url) => buildAllowRule(url))
  ];

  const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
  const existingIds = existingRules.map((rule) => rule.id);

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existingIds,
    addRules: desiredRules
  });
};

const normalizeUrl = (url) => {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}${parsed.search}`;
  } catch {
    return url;
  }
};

const loadBlockedUrls = (() => {
  let pending;
  return () => {
    if (pending) {
      return pending;
    }
    pending = chrome.storage.local
      .get({
        [blockedStoreKey]: [],
        [allowStoreKey]: [],
        [scoreStoreKey]: [],
        [scoreModeKey]: "demo",
        [gtiApiKeyKey]: ""
      })
      .then((data) => {
        const stored = data[blockedStoreKey];
        if (Array.isArray(stored)) {
          stored.forEach((entry) => blockedUrls.add(entry));
        }
        const storedAllow = data[allowStoreKey];
        if (Array.isArray(storedAllow)) {
          storedAllow.forEach((entry) => {
            if (!entry || typeof entry.url !== "string") {
              return;
            }
            if (typeof entry.expiresAt !== "number") {
              return;
            }
            if (entry.expiresAt > Date.now()) {
              allowUrls.set(entry.url, entry.expiresAt);
            }
          });
        }
        const storedScores = data[scoreStoreKey];
        if (Array.isArray(storedScores)) {
          storedScores.forEach((entry) => {
            if (!entry || typeof entry.score !== "number") {
              return;
            }
            if (typeof entry.key === "string") {
              cachedScores.set(entry.key, entry.score);
              return;
            }
            if (typeof entry.url === "string") {
              cachedScores.set(`demo::${entry.url}`, entry.score);
            }
          });
        }
        if (typeof data[scoreModeKey] === "string") {
          scoreMode = data[scoreModeKey];
        }
        if (typeof data[gtiApiKeyKey] === "string") {
          gtiApiKey = data[gtiApiKeyKey];
        }
      })
      .then(() =>
        chrome.storage.session
          .get({ [pendingStoreKey]: {}, [blockedInfoStoreKey]: {} })
          .then((sessionData) => {
            const storedPending = sessionData[pendingStoreKey] || {};
            Object.entries(storedPending).forEach(([tabId, entry]) => {
              if (!entry || typeof entry.url !== "string") {
                return;
              }
              pendingUrls.set(Number(tabId), entry);
            });
            const storedBlockedInfo = sessionData[blockedInfoStoreKey] || {};
            Object.entries(storedBlockedInfo).forEach(([tabId, entry]) => {
              if (!entry || typeof entry.url !== "string") {
                return;
              }
              blockedInfoByTab.set(Number(tabId), entry);
            });
          })
          .catch((error) => {
            console.warn("Failed to load pending URLs.", error);
          })
      )
      .then(() => syncDynamicRules())
      .catch((error) => {
        console.warn("Failed to load blocked URLs.", error);
      });
    return pending;
  };
})();

const persistBlockedUrls = () =>
  chrome.storage.local
    .set({ [blockedStoreKey]: Array.from(blockedUrls) })
    .catch((error) => {
      console.warn("Failed to persist blocked URLs.", error);
    });

const persistAllowUrls = () =>
  chrome.storage.local
    .set({
      [allowStoreKey]: Array.from(allowUrls.entries()).map(([url, expiresAt]) => ({
        url,
        expiresAt
      }))
    })
    .catch((error) => {
      console.warn("Failed to persist allow URLs.", error);
    });

const persistCachedScores = () =>
  chrome.storage.local
    .set({
      [scoreStoreKey]: Array.from(cachedScores.entries()).map(([key, score]) => ({
        key,
        score
      }))
    })
    .catch((error) => {
      console.warn("Failed to persist cached scores.", error);
    });

const buildCacheKey = (mode, normalizedUrl) => `${mode}::${normalizedUrl}`;

const shouldScore = (tabId, url) => {
  const lastUrl = lastScoredByTab.get(tabId);
  if (lastUrl === url) {
    return false;
  }
  lastScoredByTab.set(tabId, url);
  return true;
};

const updatePendingUrl = (tabId, url) => {
  pendingUrls.set(tabId, { url, timestamp: Date.now() });
  const payload = {};
  pendingUrls.forEach((entry, key) => {
    payload[key] = entry;
  });
  chrome.storage.session.set({ [pendingStoreKey]: payload }).catch((error) => {
    console.warn("Failed to persist pending URLs.", error);
  });
};

const getLocalDateKey = () => {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
};

const incrementDailyPageLoad = () => {
  const today = getLocalDateKey();
  chrome.storage.local
    .get({ [dailyPageLoadDateKey]: "", [dailyPageLoadCountKey]: 0 })
    .then((data) => {
      const lastDate = data[dailyPageLoadDateKey];
      const lastCount = Number(data[dailyPageLoadCountKey] || 0);
      const nextCount = lastDate === today ? lastCount + 1 : 1;
      return chrome.storage.local.set({
        [dailyPageLoadDateKey]: today,
        [dailyPageLoadCountKey]: nextCount
      });
    })
    .catch((error) => {
      console.warn("Failed to update daily page loads.", error);
    });
};

const recordGtiTiming = (durationMs) => {
  chrome.storage.local
    .get({ [gtiTimingKey]: { totalMs: 0, count: 0 } })
    .then((data) => {
      const timing = data[gtiTimingKey] || { totalMs: 0, count: 0 };
      const totalMs = Number(timing.totalMs || 0) + durationMs;
      const count = Number(timing.count || 0) + 1;
      return chrome.storage.local.set({
        [gtiTimingKey]: { totalMs, count }
      });
    })
    .catch((error) => {
      console.warn("Failed to record GTI timing.", error);
    });
};

const setBlockedInfo = (tabId, url, score) => {
  blockedInfoByTab.set(tabId, { url, score, timestamp: Date.now() });
  const payload = {};
  blockedInfoByTab.forEach((entry, key) => {
    payload[key] = entry;
  });
  chrome.storage.session.set({ [blockedInfoStoreKey]: payload }).catch((error) => {
    console.warn("Failed to persist blocked info.", error);
  });
};

const pruneExpiredAllows = async () => {
  const now = Date.now();
  let changed = false;
  allowUrls.forEach((expiresAt, url) => {
    if (expiresAt <= now) {
      allowUrls.delete(url);
      changed = true;
    }
  });
  if (changed) {
    persistAllowUrls();
    await syncDynamicRules();
  }
};

const scoreAndDecide = async ({ tabId, url }) => {
  if (!url) {
    return;
  }

  if (isRestrictedUrl(url)) {
    return;
  }

  if (isExtensionUrl(url)) {
    return;
  }

  await loadBlockedUrls();

  const normalizedUrl = normalizeUrl(url);

  if (blockedUrls.has(normalizedUrl)) {
    const cacheKey = buildCacheKey(scoreMode, normalizedUrl);
    const cachedScore = cachedScores.get(cacheKey);
    setBlockedInfo(tabId, url, cachedScore ?? blockThreshold);
    const redirectUrl = buildWarningUrl(url, blockThreshold);
    chrome.tabs.update(tabId, { url: redirectUrl }).catch((error) => {
      console.warn("Unable to redirect blocked URL.", error);
    });
    return;
  }

  if (allowUrls.has(normalizedUrl)) {
    return;
  }

  if (!shouldScore(tabId, url)) {
    return;
  }

  const cacheKey = buildCacheKey(scoreMode, normalizedUrl);
  let score = cachedScores.get(cacheKey);
  if (score == null) {
    const startTime = performance.now();
    score =
      scoreMode === "gti"
        ? await getGTIScore(url)
        : generateScoreDemo(url);
    const durationMs = performance.now() - startTime;
    const label = scoreMode === "gti" ? "getGTIScore" : "generateScoreDemo";
    console.log(`${label}() took ${durationMs.toFixed(2)} ms`);
    if (scoreMode === "gti") {
      recordGtiTiming(durationMs);
    }
    cachedScores.set(cacheKey, score);
    persistCachedScores();
  }

  if (score >= blockThreshold) {
    blockedUrls.add(normalizedUrl);
    persistBlockedUrls();
    await syncDynamicRules();
    setBlockedInfo(tabId, url, score);
    const redirectUrl = buildWarningUrl(url, score);
    chrome.tabs.update(tabId, { url: redirectUrl }).catch((error) => {
      console.warn("Unable to redirect blocked tab.", error);
    });
    return;
  }

  if (score >= 20) {
    const redirectUrl = buildWarningUrl(url, score);
    chrome.tabs.update(tabId, { url: redirectUrl }).catch((error) => {
      console.warn("Unable to redirect tab.", error);
    });
    return;
  }

  const expiresAt = Date.now() + allowDurationMs;
  allowUrls.set(normalizedUrl, expiresAt);
  persistAllowUrls();
  await syncDynamicRules();
  chrome.tabs.update(tabId, { url }).catch((error) => {
    console.warn("Unable to allow tab.", error);
  });
};

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) {
    return;
  }
  if (!details.url || !details.url.startsWith("http")) {
    return;
  }
  if (isExtensionUrl(details.url) || isRestrictedUrl(details.url)) {
    return;
  }
  updatePendingUrl(details.tabId, details.url);

  const normalizedUrl = normalizeUrl(details.url);
  if (blockedUrls.has(normalizedUrl)) {
    const cacheKey = buildCacheKey(scoreMode, normalizedUrl);
    const cachedScore = cachedScores.get(cacheKey);
    setBlockedInfo(details.tabId, details.url, cachedScore ?? blockThreshold);
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") {
    return;
  }
  if (changes[scoreModeKey]?.newValue) {
    scoreMode = changes[scoreModeKey].newValue;
  }
  if (changes[gtiApiKeyKey]?.newValue !== undefined) {
    gtiApiKey = changes[gtiApiKeyKey].newValue || "";
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "CHECK_URL" && Number.isInteger(message.tabId)) {
    const entry = pendingUrls.get(message.tabId);
    const targetUrl = entry?.url;
    if (!targetUrl) {
      sendResponse({ ok: false });
      return true;
    }
    scoreAndDecide({ tabId: message.tabId, url: targetUrl })
      .then(() => sendResponse({ ok: true }))
      .catch((error) => {
        console.warn("Failed to score URL.", error);
        sendResponse({ ok: false });
      });
    return true;
  }

  if (message?.type === "GET_BLOCK_INFO" && Number.isInteger(message.tabId)) {
    const entry = blockedInfoByTab.get(message.tabId);
    sendResponse(entry ? { ok: true, entry } : { ok: false });
    return true;
  }

  if (message?.type === "ALLOW_ONCE" && typeof message.url === "string") {
    const normalizedUrl = normalizeUrl(message.url);
    const expiresAt = Date.now() + allowDurationMs;
    allowUrls.set(normalizedUrl, expiresAt);
    persistAllowUrls();
    syncDynamicRules()
      .then(() => sendResponse({ ok: true }))
      .catch((error) => {
        console.warn("Failed to add allow rule.", error);
        sendResponse({ ok: false });
      });
    return true;
  }

  sendResponse({ ok: false });
  return false;
});

chrome.alarms.create("allow-cleanup", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "allow-cleanup") {
    pruneExpiredAllows().catch((error) => {
      console.warn("Failed to prune allow rules.", error);
    });
  }
});

chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
  if (info?.rule?.ruleId !== 1) {
    return;
  }
  const url = info?.request?.url;
  const tabId = info?.request?.tabId;
  if (!url || !Number.isInteger(tabId)) {
    return;
  }
  if (isExtensionUrl(url) || isRestrictedUrl(url)) {
    return;
  }
  updatePendingUrl(tabId, url);
  incrementDailyPageLoad();
});

loadBlockedUrls().catch((error) => {
  console.warn("Failed to initialize rules.", error);
});

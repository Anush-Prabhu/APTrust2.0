/**
 * AP Trust background service worker (MV3) — v2.0
 *
 * - Hydrates Protect Mode + selected boundary from chrome.storage (same keys
 *   as the popup).
 * - Calls the local server's POST /verify for tab URLs, hyperlinks, and
 *   redirect targets.
 * - Sets the toolbar badge (OK / ! / mail) and pushes APTRUST_PAGE_EVAL to
 *   the content script for the red in-page banner (APT 1.0 UX).
 */

import { CONFIG, SERVER_UNAVAILABLE_MESSAGE, STATUS } from './src/config.js';

let STATE = {
  protectMode: false,
  selectedBoundary: null, // { canonicalDomain, displayName, type?, status? }
};

/**
 * Cached metadata for the currently-selected boundary. We refresh these
 * whenever Protect Mode + boundary settings change so the in-page report
 * modal (APT 1.0) can show the right contact info, and the popup can show
 * the current boundary version + trust root.
 *
 * Reads tolerate both APT 1.0 JSON-LD (`aptrust:reportContact`,
 * `aptrust:aptrustVersion`) and the plain v2 keys.
 */
let CACHED_REPORT_CONTACT = null;
let CACHED_VERSION = null;
let CACHED_TRUST_ROOT = null;
/**
 * Targets the selected boundary CLAIMS a relationship to. Used by the popup
 * to render a dynamic "claims to be X" warning when the boundary itself is
 * a known impostor (jhuu.com today; any custom suspicious manifest later).
 * Each entry is `{ canonicalDomain, displayName }`.
 */
let CACHED_IMPERSONATION_TARGETS = [];

function extractHost(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function isEmailHost(host, list) {
  const h = (host || '').replace(/^www\./, '');
  for (const e of list) {
    if (h === e || h.endsWith('.' + e)) return true;
  }
  return false;
}

async function hydrateFromStorage() {
  const keys = CONFIG.storageKeys;
  const stored = await chrome.storage.local.get([
    keys.protectMode,
    keys.selectedBoundary,
  ]);
  STATE = {
    protectMode: !!stored[keys.protectMode],
    selectedBoundary: stored[keys.selectedBoundary] || null,
  };
  await refreshBoundaryManifestCache();
}

/**
 * Pulls reportContact + version for the active boundary from the local
 * server so the in-page report modal and the popup can render proper info.
 * The /manifest endpoint serves the JSON-LD on-disk file plus a `_normalized`
 * view; we accept either form.
 *
 * Failures are silent (server may be down) and clear the cache.
 */
async function refreshBoundaryManifestCache() {
  CACHED_REPORT_CONTACT = null;
  CACHED_VERSION = null;
  CACHED_TRUST_ROOT = null;
  CACHED_IMPERSONATION_TARGETS = [];
  const boundary = STATE.selectedBoundary?.canonicalDomain;
  if (!boundary) return;
  try {
    const r = await fetch(
      `${CONFIG.serverBase}/manifest/${encodeURIComponent(boundary)}`,
    );
    if (!r.ok) return;
    const m = await r.json();
    if (!m || typeof m !== 'object') return;
    const norm = (m._normalized && typeof m._normalized === 'object') ? m._normalized : null;
    const rc =
      m['aptrust:reportContact'] ||
      m.reportContact ||
      (norm && norm.reportContact);
    if (rc && typeof rc === 'object') CACHED_REPORT_CONTACT = rc;
    const ver =
      m['aptrust:aptrustVersion'] ||
      m.softwareVersion ||
      m.version ||
      (norm && norm.version);
    if (typeof ver === 'string') CACHED_VERSION = ver;
    if (m._policy && typeof m._policy.trustRootCanonical === 'string') {
      CACHED_TRUST_ROOT = m._policy.trustRootCanonical;
    }
    CACHED_IMPERSONATION_TARGETS = collectImpersonationTargets(m, norm);
  } catch {
    /* server unavailable; modal falls back to default copy */
  }
}

/**
 * Extract every organization the boundary's manifest CLAIMS a relationship
 * to. Reads parentOrganization, relatedOrganizations[], and
 * claimedExternalDomains[] from the JSON-LD top-level keys, the v2 plain
 * keys, or the `_normalized` view (whichever the server returned).
 *
 * The popup uses this to render a dynamic "claims to be X" warning when
 * the boundary itself is a known impostor; the message therefore follows
 * any custom malicious manifest verbatim.
 */
function collectImpersonationTargets(raw, normalized) {
  const out = [];
  const seen = new Set();
  const push = (canonicalDomain, displayName) => {
    if (!canonicalDomain) return;
    const key = String(canonicalDomain).toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push({
      canonicalDomain: String(canonicalDomain),
      displayName: displayName ? String(displayName) : '',
    });
  };

  const parent =
    raw['aptrust:parentOrganization'] ||
    raw.parentOrganization ||
    (normalized && normalized.parentOrganization);
  if (parent && typeof parent === 'object') {
    push(parent.canonicalDomain, parent.name);
  }

  const related =
    raw['aptrust:relatedOrganization'] ||
    raw.relatedOrganizations ||
    (normalized && normalized.relatedOrganizations) ||
    [];
  if (Array.isArray(related)) {
    for (const r of related) {
      if (r && typeof r === 'object') {
        push(r.canonicalDomain, r.name);
      }
    }
  }

  const claimed =
    raw['aptrust:claimedExternalDomain'] ||
    raw.claimedExternalDomains ||
    (normalized && normalized.claimedExternalDomains) ||
    [];
  if (Array.isArray(claimed)) {
    for (const url of claimed) {
      try {
        const u = new URL(String(url));
        push(u.hostname.replace(/^www\./, ''), '');
      } catch {
        /* skip malformed URLs */
      }
    }
  }
  return out;
}

async function verifyWithServer(url) {
  const boundary = STATE.selectedBoundary?.canonicalDomain;
  if (!boundary) throw new Error('no boundary selected');
  const res = await fetch(`${CONFIG.serverBase}/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ boundary, url }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(text || `verify HTTP ${res.status}`);
  }
  return res.json();
}

/** Map API status strings to legacy trusted / untrusted / excluded. */
function mapVerifyApiStatus(apiStatus) {
  if (
    apiStatus === 'OFFICIAL' ||
    apiStatus === 'RELATED' ||
    apiStatus === 'SOCIAL_VERIFIED' ||
    apiStatus === 'RELATED_CANDIDATE'
  ) {
    return STATUS.TRUSTED;
  }
  if (apiStatus === 'EXCLUDED') {
    return STATUS.EXCLUDED;
  }
  if (
    apiStatus === 'OUT_OF_BOUNDARY' ||
    apiStatus === 'SUSPICIOUS_LOOKALIKE' ||
    apiStatus === 'SUSPICIOUS_UNIDIRECTIONAL_CLAIM' ||
    apiStatus === 'UNKNOWN' ||
    apiStatus === 'DISABLED_BOUNDARY'
  ) {
    return STATUS.UNTRUSTED;
  }
  return STATUS.UNTRUSTED;
}

function humanHost(url) {
  const h = extractHost(url);
  return h.replace(/^www\./, '') || h;
}

/**
 * Page-level evaluation (tab URL). Applies mail-client softening like v1.0.
 */
async function evaluatePage(url) {
  if (!url.startsWith('http')) {
    return { status: STATUS.SKIPPED, reason: 'Not a web URL' };
  }
  if (!STATE.protectMode) {
    return { status: STATUS.SKIPPED, reason: 'Protect Mode is off' };
  }
  if (!STATE.selectedBoundary) {
    return { status: STATUS.SKIPPED, reason: 'No boundary selected' };
  }
  try {
    const v = await verifyWithServer(url);
    const mapped = mapVerifyApiStatus(v.status);
    const host = humanHost(url);
    if (mapped === STATUS.EXCLUDED) {
      return {
        status: STATUS.EXCLUDED,
        reason:
          (v.reasons && v.reasons[0]) ||
          `${host} is on the explicit excludedDomains list`,
        verify: v,
      };
    }
    if (mapped === STATUS.UNTRUSTED && isEmailHost(host, CONFIG.emailHosts)) {
      return {
        status: STATUS.MAIL_CLIENT,
        reason: `Recognized email client (${host}). Hyperlinks in messages are still checked against ${STATE.selectedBoundary.canonicalDomain}.`,
        verify: v,
      };
    }
    if (mapped === STATUS.UNTRUSTED) {
      return {
        status: STATUS.UNTRUSTED,
        reason: `${host} is outside the selected trust boundary`,
        verify: v,
      };
    }
    return {
      status: STATUS.TRUSTED,
      reason: (v.reasons && v.reasons[0]) || v.status || 'Inside trust boundary',
      verify: v,
    };
  } catch (_err) {
    return {
      status: STATUS.SKIPPED,
      reason: SERVER_UNAVAILABLE_MESSAGE,
    };
  }
}

/** Link / batch evaluation (no mail-client page special-case). */
async function evaluateLink(url) {
  if (!STATE.protectMode || !STATE.selectedBoundary) {
    return {
      status: STATUS.SKIPPED,
      reason: 'Protect Mode off or no boundary selected',
    };
  }
  try {
    const v = await verifyWithServer(url);
    const mapped = mapVerifyApiStatus(v.status);
    return {
      status: mapped,
      reason: (v.reasons && v.reasons[0]) || v.status,
      verify: v,
    };
  } catch (_e) {
    return {
      status: STATUS.SKIPPED,
      reason: 'Server unavailable',
    };
  }
}

function boundarySummary() {
  if (!STATE.selectedBoundary) return null;
  return {
    canonicalDomain: STATE.selectedBoundary.canonicalDomain,
    displayName: STATE.selectedBoundary.displayName,
    type: STATE.selectedBoundary.type,
    status: STATE.selectedBoundary.status,
    version: CACHED_VERSION,
    trustRootCanonical: CACHED_TRUST_ROOT,
    impersonationTargets: CACHED_IMPERSONATION_TARGETS,
    reportContact: CACHED_REPORT_CONTACT,
  };
}

function badgeFor(result) {
  switch (result.status) {
    case STATUS.TRUSTED:
      return { text: 'OK', color: '#2e7d32' };
    case STATUS.UNTRUSTED:
      return { text: '!', color: '#c62828' };
    case STATUS.EXCLUDED:
      return { text: 'X', color: '#ad1457' };
    case STATUS.MAIL_CLIENT:
      return { text: '\u2709', color: '#1976d2' };
    default:
      return { text: '', color: '#757575' };
  }
}

async function setBadge(tabId, result) {
  const b = badgeFor(result);
  try {
    await chrome.action.setBadgeText({ tabId, text: b.text });
    if (b.text) {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
    }
    await chrome.action.setTitle({
      tabId,
      title: `AP Trust — ${result.status}${
        result.reason ? `: ${result.reason}` : ''
      }`,
    });
  } catch {
    // tab may have closed
  }
}

async function evaluateAndBadgeTab(tab) {
  if (!tab?.id || !tab.url) return;
  const result = await evaluatePage(tab.url);
  await setBadge(tab.id, result);

  if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
    chrome.tabs.sendMessage(
      tab.id,
      { type: 'APTRUST_PAGE_EVAL', result, boundary: boundarySummary() },
      () => void chrome.runtime.lastError,
    );
  }
}

async function refreshBadgeForActiveTab() {
  const [tab] = await chrome.tabs.query({
    active: true,
    lastFocusedWindow: true,
  });
  if (tab) await evaluateAndBadgeTab(tab);
}

async function refreshAllHttpTabs() {
  const tabs = await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] });
  for (const tab of tabs) {
    await evaluateAndBadgeTab(tab);
  }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

async function boot() {
  await hydrateFromStorage();
  await refreshBadgeForActiveTab();
}

chrome.runtime.onInstalled.addListener(() => boot());
chrome.runtime.onStartup.addListener(() => boot());
boot();

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  const k = CONFIG.storageKeys;
  if (changes[k.protectMode] || changes[k.selectedBoundary]) {
    hydrateFromStorage().then(() => refreshAllHttpTabs());
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    await evaluateAndBadgeTab(tab);
  } catch {
    /* ignore */
  }
});

chrome.tabs.onUpdated.addListener(async (_tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' || changeInfo.url) {
    await evaluateAndBadgeTab(tab);
  }
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  chrome.tabs.get(details.tabId, (tab) => {
    if (!chrome.runtime.lastError && tab) evaluateAndBadgeTab(tab);
  });
});

/**
 * Observe redirects — warn (non-blocking) when the destination is outside the
 * boundary, matching v1.0 behavior.
 */
chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.type !== 'main_frame') return;
    if (!STATE.protectMode || !STATE.selectedBoundary) return;
    (async () => {
      try {
        const endV = await verifyWithServer(details.redirectUrl);
        if (mapVerifyApiStatus(endV.status) === STATUS.UNTRUSTED) {
          chrome.tabs.sendMessage(
            details.tabId,
            {
              type: 'APTRUST_REDIRECT_WARNING',
              from: details.url,
              to: details.redirectUrl,
              result: { status: STATUS.UNTRUSTED, verify: endV },
            },
            () => void chrome.runtime.lastError,
          );
        }
      } catch {
        /* ignore */
      }
    })();
  },
  { urls: ['http://*/*', 'https://*/*'] },
);

// ---------------------------------------------------------------------------
// Messages (popup + content script)
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      switch (msg && msg.type) {
        case 'GET_STATE':
          sendResponse({
            ok: true,
            state: {
              protectMode: STATE.protectMode,
              selectedEntry: STATE.selectedBoundary
                ? {
                    ...STATE.selectedBoundary,
                    version: CACHED_VERSION,
                    trustRootCanonical: CACHED_TRUST_ROOT,
                    impersonationTargets: CACHED_IMPERSONATION_TARGETS,
                  }
                : null,
              boundary: boundarySummary(),
            },
          });
          return;

        case 'EVALUATE_URL':
          sendResponse({ ok: true, result: await evaluatePage(msg.url) });
          return;

        case 'EVALUATE_URLS': {
          const urls = Array.isArray(msg.urls) ? msg.urls : [];
          const results = [];
          for (const u of urls) {
            results.push({ url: u, result: await evaluateLink(u) });
          }
          sendResponse({ ok: true, results });
          return;
        }

        case 'OPEN_REPORT_FOR_ACTIVE_TAB': {
          const [tab] = await chrome.tabs.query({
            active: true,
            lastFocusedWindow: true,
          });
          if (!tab || !tab.id) {
            sendResponse({ ok: false, error: 'no active tab' });
            return;
          }
          // Re-evaluate the tab so the modal carries fresh page context.
          const result = await evaluatePage(tab.url || '');
          chrome.tabs.sendMessage(
            tab.id,
            {
              type: 'APTRUST_OPEN_REPORT',
              result,
              boundary: boundarySummary(),
            },
            () => void chrome.runtime.lastError,
          );
          sendResponse({ ok: true });
          return;
        }

        case 'SUBMIT_REPORT': {
          const payload = {
            ...(msg.payload || {}),
            boundary: boundarySummary(),
            submittedAt: new Date().toISOString(),
          };
          try {
            const r = await fetch(`${CONFIG.serverBase}/report`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload),
            });
            const data = await r.json().catch(() => ({}));
            sendResponse({ ok: r.ok, status: r.status, data });
          } catch (err) {
            sendResponse({
              ok: false,
              error: err.message || String(err),
            });
          }
          return;
        }

        default:
          sendResponse({
            ok: false,
            error: `Unknown message type: ${msg && msg.type}`,
          });
      }
    } catch (err) {
      console.error('[aptrust/bg]', err);
      sendResponse({ ok: false, error: err.message || String(err) });
    }
  })();

  return true;
});

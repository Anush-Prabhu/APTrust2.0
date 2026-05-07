/**
 * APTrust popup controller.
 *
 * Layout matches APT 1.0 (selected boundary / find a boundary / current tab /
 * verify input / footer). All trust logic lives on the local server; this
 * file is pure UI and message glue.
 *
 * The Verify panel accepts three input shapes:
 *   - URL                   https://www.hopkinsmedicine.org/...
 *   - Email address         someone@jhu.edu        \u2192 verify https://jhu.edu/
 *   - Social handle         @johnshopkinsu         \u2192 match against the
 *                                                   selected boundary's
 *                                                   declared social profiles
 */

import { CONFIG, STATUS, SERVER_UNAVAILABLE_MESSAGE } from './src/config.js';

const $ = (id) => document.getElementById(id);

const els = {
  protect: $('protectMode'),
  search: $('searchInput'),
  results: $('searchResults'),
  selectedBody: $('selectedBody'),
  clearBtn: $('clearBtn'),
  tabUrl: $('tabUrl'),
  tabVerdict: $('tabVerdict'),
  reportBtn: $('reportBtn'),
  verifyInput: $('verifyInput'),
  verifyHint: $('verifyHint'),
  verifyVerdict: $('verifyVerdict'),
  status: $('status'),
  serverUrl: $('serverUrl'),
};

// Latest known active-tab URL + result so the Report button can re-trigger.
let activeTabUrl = null;
let activeTabResult = null;
let activeBoundary = null;

// ---------------------------------------------------------------------------
// IO helpers
// ---------------------------------------------------------------------------

function send(type, payload = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...payload }, (res) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message });
      } else {
        resolve(res || { ok: false, error: 'no response' });
      }
    });
  });
}

async function http(path) {
  const r = await fetch(`${CONFIG.serverBase}${path}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function httpPost(path, body) {
  const r = await fetch(`${CONFIG.serverBase}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const t = await r.text().catch(() => '');
    throw new Error(t || `HTTP ${r.status}`);
  }
  return r.json();
}

function setStatus(text, kind = '') {
  els.status.textContent = text || '';
  els.status.className = 'status' + (kind ? ` ${kind}` : '');
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/**
 * A record entry is "suspicious" for demo purposes if its registry type is
 * `SuspiciousExample` or its status is `test`. The Find-a-boundary list and
 * the selected-boundary card both surface this prominently so the user
 * cannot accidentally treat a known impersonator as a real boundary.
 */
function isSuspicious(entry) {
  if (!entry) return false;
  return entry.type === 'SuspiciousExample' || entry.status === 'test';
}

/**
 * Build the dynamic "Known impersonator" note for the selected-boundary
 * card. The list of orgs the boundary claims to be is derived from its
 * manifest at fetch time (background.js -> CACHED_IMPERSONATION_TARGETS),
 * so any custom suspicious manifest authored later is auto-described here
 * without a popup change.
 */
function buildSuspiciousNote(entry) {
  const canonical = escapeHtml(entry.canonicalDomain || '');
  const targets = Array.isArray(entry.impersonationTargets)
    ? entry.impersonationTargets
    : [];

  // Prefer named entries (parentOrganization / relatedOrganizations) over
  // bare claimedExternalDomain hosts so the message reads naturally. Fall
  // back to canonical-only only if no named targets exist.
  const named = targets.filter((t) => (t.displayName || '').trim());
  const chosen = (named.length ? named : targets).slice(0, 2);
  const labels = chosen.map((t) => {
    const name = (t.displayName || '').trim();
    const dom = (t.canonicalDomain || '').trim();
    if (name && dom) return `${name} (${dom})`;
    return name || dom;
  }).filter(Boolean);

  const totalNamed = (named.length ? named : targets).length;
  const trailing = totalNamed > chosen.length ? ' and others' : '';

  const claimsClause = labels.length
    ? `claims to be <strong>${escapeHtml(joinHumanList(labels) + trailing)}</strong>`
    : 'claims a relationship to other organizations';
  const reciprocateClause = labels.length
    ? labels.length === 1 && !trailing
      ? "but the real site's manifest does not reciprocate"
      : 'but those organizations\u2019 manifests do not reciprocate'
    : 'but the claimed organizations do not reciprocate';
  return `<div class="suspect-note">\u26a0 <strong>Known impersonator.</strong> This entry exists for demo only \u2014 ${canonical} ${claimsClause} ${reciprocateClause}. Pages on ${canonical} will resolve as <code>SUSPICIOUS_UNIDIRECTIONAL_CLAIM</code>; do not treat them as trusted.</div>`;
}

/** Join ["a","b","c"] as "a, b and c"; preserves single-item input as-is. */
function joinHumanList(parts) {
  if (parts.length <= 1) return parts.join('');
  if (parts.length === 2) return `${parts[0]} and ${parts[1]}`;
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}

function renderSelected(entry) {
  if (!entry) {
    els.selectedBody.textContent = 'None selected.';
    els.selectedBody.classList.add('muted');
    els.clearBtn.classList.add('hidden');
    return;
  }
  els.selectedBody.classList.remove('muted');
  const v = entry.version ? ` \u00b7 v${escapeHtml(entry.version)}` : '';
  const suspicious = isSuspicious(entry);
  const chips = [];
  if (suspicious) chips.push('<span class="chip warn">\u26a0 Suspicious</span>');
  if (entry.status && entry.status !== 'active') {
    chips.push(
      `<span class="chip test">${escapeHtml(String(entry.status).toUpperCase())}</span>`,
    );
  }
  const chipsHtml = chips.length
    ? `<div class="row" style="margin-top:4px;">${chips.join('')}</div>`
    : '';
  const note = suspicious
    ? buildSuspiciousNote(entry)
    : '';
  const root = entry.trustRootCanonical && entry.trustRootCanonical !== entry.canonicalDomain
    ? `<div class="small muted" style="margin-top:4px;">Trust root: <code>${escapeHtml(entry.trustRootCanonical)}</code></div>`
    : '';
  els.selectedBody.innerHTML = `
    <div><strong>${escapeHtml(entry.displayName || entry.canonicalDomain)}</strong></div>
    <div class="mono small muted">${escapeHtml(entry.canonicalDomain)}${v}</div>
    ${root}
    ${chipsHtml}
    ${note}
  `;
  els.clearBtn.classList.remove('hidden');
}

function statusToClass(status) {
  switch (status) {
    case STATUS.TRUSTED:     return 'ok';
    case STATUS.UNTRUSTED:   return 'warn';
    case STATUS.EXCLUDED:    return 'excl';
    case STATUS.MAIL_CLIENT: return 'mail';
    case STATUS.SKIPPED:     return 'skipped';
    default:                 return 'skipped';
  }
}

/** Headline used in the verdict box for the legacy STATUS values. */
function legacyHeadline(status) {
  switch (status) {
    case STATUS.TRUSTED:     return 'TRUSTED';
    case STATUS.UNTRUSTED:   return 'UNTRUSTED';
    case STATUS.EXCLUDED:    return 'EXCLUDED';
    case STATUS.MAIL_CLIENT: return 'EMAIL CLIENT';
    case STATUS.SKIPPED:     return 'SKIPPED';
    default:                 return String(status || 'UNKNOWN').toUpperCase();
  }
}

/**
 * Render an evaluatePage / evaluateLink result (used for the current tab).
 * `result` looks like `{ status, reason, verify? }` where `verify` is the
 * full /verify response when available.
 */
function renderTabVerdict(url, result) {
  els.tabUrl.textContent = url || '\u2014';
  if (!result) {
    els.tabVerdict.className = 'verdict skipped';
    els.tabVerdict.textContent = '\u2014';
    els.reportBtn.classList.add('hidden');
    return;
  }
  const cls = statusToClass(result.status);
  els.tabVerdict.className = `verdict ${cls}`;
  const headline = legacyHeadline(result.status);
  const detail = result.reason || '';
  const verifyStatus = result.verify && result.verify.status
    ? `<div class="verdict-detail small">Engine status: ${escapeHtml(result.verify.status)}</div>`
    : '';
  els.tabVerdict.innerHTML = `
    <div class="verdict-headline">${escapeHtml(headline)}</div>
    <div class="verdict-detail">${escapeHtml(detail)}</div>
    ${verifyStatus}
  `;
  // Show Report when the page is outside the boundary or excluded.
  const showReport =
    (result.status === STATUS.UNTRUSTED || result.status === STATUS.EXCLUDED) &&
    !!activeBoundary;
  els.reportBtn.classList.toggle('hidden', !showReport);
}

/**
 * Render a /verify result directly in the manual-verify panel.
 * `engine` is the full engine response (`status`, `relationship`, `reasons`).
 * `headline` is overridden when the popup synthesised the verdict (e.g. the
 * "no declared profile matches handle" case).
 */
function renderEngineVerdict(verifyEl, engine, opts = {}) {
  if (!engine) {
    verifyEl.className = 'verdict skipped';
    verifyEl.textContent = '\u2014';
    verifyEl.classList.remove('hidden');
    return;
  }
  const cls = (() => {
    switch (engine.status) {
      case 'OFFICIAL':
      case 'RELATED':
      case 'SOCIAL_VERIFIED':
      case 'RELATED_CANDIDATE':
        return 'ok';
      case 'EXCLUDED':
        return 'excl';
      case 'OUT_OF_BOUNDARY':
      case 'SUSPICIOUS_LOOKALIKE':
      case 'SUSPICIOUS_UNIDIRECTIONAL_CLAIM':
        return 'warn';
      default:
        return 'skipped';
    }
  })();
  verifyEl.className = `verdict ${cls}`;
  verifyEl.classList.remove('hidden');
  const reasons = Array.isArray(engine.reasons) ? engine.reasons : [];
  const reasonHtml = reasons.length
    ? `<ul class="verdict-reasons">${reasons
        .map((r) => `<li>${escapeHtml(r)}</li>`)
        .join('')}</ul>`
    : '';
  const sub = opts.subline || (engine.relationship ? `Relationship: ${engine.relationship}` : '');
  verifyEl.innerHTML = `
    <div class="verdict-headline">${escapeHtml(opts.headline || engine.status || 'UNKNOWN')}</div>
    <div class="verdict-detail">${escapeHtml(sub)}</div>
    ${reasonHtml}
  `;
}

function renderResults(list) {
  els.results.innerHTML = '';
  if (!list || list.length === 0) {
    const li = document.createElement('li');
    li.className = 'muted';
    li.textContent = 'No matches.';
    els.results.appendChild(li);
    return;
  }
  list.forEach((item) => {
    const li = document.createElement('li');
    const suspicious = isSuspicious(item);
    if (suspicious) li.classList.add('suspect');
    const chips = [];
    if (suspicious) chips.push('<span class="chip warn">\u26a0 Suspicious</span>');
    if (item.status && item.status !== 'active') {
      chips.push(
        `<span class="chip test">${escapeHtml(String(item.status).toUpperCase())}</span>`,
      );
    }
    const chipsHtml = chips.length ? chips.join(' ') : '';
    li.innerHTML = `
      <div class="row">
        <div class="name">${escapeHtml(item.displayName || item.canonicalDomain)}</div>
        ${chipsHtml}
      </div>
      <div class="domain">${escapeHtml(item.canonicalDomain)}</div>
    `;
    li.title = suspicious
      ? 'Suspicious lookalike \u2014 selecting is for demo purposes only.'
      : '';
    li.addEventListener('click', () => onPickBoundary(item));
    els.results.appendChild(li);
  });
}

// ---------------------------------------------------------------------------
// Manual-verify input parsing
// ---------------------------------------------------------------------------

const INPUT_KIND = {
  EMPTY: 'empty',
  HANDLE: 'handle',
  EMAIL: 'email',
  URL: 'url',
};

/**
 * Classify a user input from the Verify panel.
 *   "@johnshopkinsu"           \u2192 { kind: handle, handle: 'johnshopkinsu' }
 *   "someone@jhu.edu"          \u2192 { kind: email, domain: 'jhu.edu' }
 *   "instagram.com/handle"     \u2192 { kind: url, url: 'https://instagram.com/handle' }
 *   "https://example.com/x"    \u2192 { kind: url, url: 'https://example.com/x' }
 *   ""                         \u2192 { kind: empty }
 */
function classifyInput(raw) {
  const s = String(raw || '').trim();
  if (!s) return { kind: INPUT_KIND.EMPTY };

  if (s.startsWith('@')) {
    const handle = s.slice(1).replace(/[\s/]+$/, '');
    if (handle && /^[A-Za-z0-9_.\-]+$/.test(handle)) {
      return { kind: INPUT_KIND.HANDLE, handle: handle.toLowerCase() };
    }
  }

  // Email addresses must have exactly one '@' between two non-empty sides.
  const m = s.match(/^([^\s@]+)@([^\s@]+\.[^\s@]+)$/);
  if (m) {
    return {
      kind: INPUT_KIND.EMAIL,
      local: m[1],
      domain: m[2].toLowerCase(),
    };
  }

  // URL or bare host.
  let url = s;
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  try {
    const u = new URL(url);
    if (u.hostname && u.hostname.includes('.')) {
      return { kind: INPUT_KIND.URL, url };
    }
  } catch {
    /* fall through */
  }
  return { kind: INPUT_KIND.EMPTY };
}

/** Returns the lowercased trailing path segment of a URL (the social handle). */
function trailingPathHandle(url) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split('/').filter(Boolean);
    return parts[parts.length - 1]?.toLowerCase() || null;
  } catch {
    return null;
  }
}

/**
 * Search the selected boundary's declared social profiles for one whose
 * trailing path segment matches `handle` (case-insensitive). Returns
 * { profileUrl, platform } or null.
 */
async function findProfileForHandle(boundary, handle) {
  let manifest;
  try {
    manifest = await http(`/manifest/${encodeURIComponent(boundary)}`);
  } catch {
    return null;
  }
  const profiles =
    manifest['aptrust:sameAsSocialProfile'] ||
    manifest.socialProfiles ||
    (manifest._normalized && manifest._normalized.socialProfiles) ||
    [];
  const lowered = handle.toLowerCase();
  for (const profileUrl of profiles) {
    const tail = trailingPathHandle(profileUrl);
    if (tail && tail === lowered) {
      let platform = '';
      try {
        platform = new URL(profileUrl).hostname.replace(/^www\./, '');
      } catch {
        /* ignore */
      }
      return { profileUrl, platform };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async function refreshState() {
  const res = await send('GET_STATE');
  if (!res.ok) {
    setStatus(`Error: ${res.error}`, 'err');
    return;
  }
  const { protectMode, selectedEntry, boundary } = res.state;
  els.protect.checked = !!protectMode;
  activeBoundary = boundary || (selectedEntry
    ? { canonicalDomain: selectedEntry.canonicalDomain, displayName: selectedEntry.displayName }
    : null);
  renderSelected(selectedEntry);
  await refreshActiveTab();
}

async function refreshActiveTab() {
  let tabUrl = '\u2014';
  try {
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    const tab = tabs && tabs[0];
    tabUrl = tab && tab.url ? tab.url : '\u2014';
    activeTabUrl = tabUrl;
  } catch {
    activeTabUrl = null;
  }
  if (!activeTabUrl || !/^https?:\/\//i.test(activeTabUrl)) {
    renderTabVerdict(tabUrl, { status: STATUS.SKIPPED, reason: 'Not a web URL' });
    return;
  }
  const res = await send('EVALUATE_URL', { url: activeTabUrl });
  if (!res.ok) {
    renderTabVerdict(activeTabUrl, {
      status: STATUS.SKIPPED,
      reason: SERVER_UNAVAILABLE_MESSAGE,
    });
    return;
  }
  activeTabResult = res.result;
  renderTabVerdict(activeTabUrl, res.result);
}

async function onProtectToggle() {
  const wanted = els.protect.checked;
  await chrome.storage.local.set({ [CONFIG.storageKeys.protectMode]: wanted });
  setStatus(wanted ? 'Protect Mode ON' : 'Protect Mode OFF', 'ok');
  await refreshState();
}

let searchTimer = null;
function onSearchInput() {
  clearTimeout(searchTimer);
  const q = els.search.value.trim();
  if (!q) {
    els.results.innerHTML = '';
    return;
  }
  searchTimer = setTimeout(async () => {
    try {
      const list = await http(`/search?q=${encodeURIComponent(q)}`);
      setStatus('');
      renderResults(list);
    } catch (err) {
      setStatus(`Search failed: ${err.message}`, 'err');
    }
  }, 150);
}

async function onPickBoundary(item) {
  setStatus(`Loading ${item.canonicalDomain}\u2026`);
  if (isSuspicious(item)) {
    setStatus(
      `\u26a0 ${item.canonicalDomain} is flagged as a known impersonator (demo only).`,
      'err',
    );
  }
  await chrome.storage.local.set({
    [CONFIG.storageKeys.selectedBoundary]: {
      canonicalDomain: item.canonicalDomain,
      displayName: item.displayName,
      type: item.type,
      status: item.status,
    },
  });
  els.results.innerHTML = '';
  els.search.value = '';
  // Background hydrates the manifest cache asynchronously \u2014 wait briefly.
  await new Promise((r) => setTimeout(r, 150));
  await refreshState();
}

async function onClearBoundary() {
  await chrome.storage.local.remove(CONFIG.storageKeys.selectedBoundary);
  setStatus('Cleared.', 'ok');
  await refreshState();
}

async function onReportClick() {
  const res = await send('OPEN_REPORT_FOR_ACTIVE_TAB');
  if (!res.ok) {
    setStatus(`Could not open report: ${res.error || 'unknown error'}`, 'err');
    return;
  }
  // Closing the popup makes the in-page modal more visible.
  setTimeout(() => window.close(), 60);
}

let verifyTimer = null;
function onVerifyInput() {
  clearTimeout(verifyTimer);
  const raw = els.verifyInput.value;
  const cls = classifyInput(raw);
  els.verifyVerdict.classList.add('hidden');
  if (cls.kind === INPUT_KIND.EMPTY) {
    els.verifyHint.textContent = '';
    return;
  }
  if (cls.kind === INPUT_KIND.HANDLE) {
    els.verifyHint.textContent =
      `Will look up the handle "@${cls.handle}" in the selected boundary's declared social profiles.`;
  } else if (cls.kind === INPUT_KIND.EMAIL) {
    els.verifyHint.textContent =
      `Email detected. Will verify the domain "${cls.domain}" against the selected boundary.`;
  } else if (cls.kind === INPUT_KIND.URL) {
    els.verifyHint.textContent = '';
  }
  verifyTimer = setTimeout(() => runVerify(cls), 280);
}

async function runVerify(cls) {
  if (!activeBoundary || !activeBoundary.canonicalDomain) {
    renderEngineVerdict(els.verifyVerdict, {
      status: 'UNKNOWN',
      relationship: 'NO_RELATIONSHIP_FOUND',
      reasons: ['Select a trust boundary first.'],
    });
    return;
  }

  if (cls.kind === INPUT_KIND.HANDLE) {
    const found = await findProfileForHandle(activeBoundary.canonicalDomain, cls.handle);
    if (!found) {
      renderEngineVerdict(
        els.verifyVerdict,
        {
          status: 'OUT_OF_BOUNDARY',
          relationship: 'NO_RELATIONSHIP_FOUND',
          reasons: [
            `No declared social profile of ${activeBoundary.canonicalDomain} matches the handle "@${cls.handle}".`,
            'Add the handle to aptrust:sameAsSocialProfile to trust it.',
          ],
        },
        { headline: 'NOT FOUND', subline: `Handle: @${cls.handle}` },
      );
      return;
    }
    try {
      const engine = await httpPost('/verify', {
        boundary: activeBoundary.canonicalDomain,
        url: found.profileUrl,
      });
      renderEngineVerdict(els.verifyVerdict, engine, {
        subline: `Matched declared profile on ${found.platform || 'social platform'}`,
      });
    } catch (err) {
      setStatus(`Verify failed: ${err.message}`, 'err');
    }
    return;
  }

  if (cls.kind === INPUT_KIND.EMAIL) {
    try {
      const engine = await httpPost('/verify', {
        boundary: activeBoundary.canonicalDomain,
        url: `https://${cls.domain}/`,
      });
      renderEngineVerdict(els.verifyVerdict, engine, {
        subline: `Verified via the email's domain (${cls.domain}).`,
      });
    } catch (err) {
      setStatus(`Verify failed: ${err.message}`, 'err');
    }
    return;
  }

  if (cls.kind === INPUT_KIND.URL) {
    try {
      const engine = await httpPost('/verify', {
        boundary: activeBoundary.canonicalDomain,
        url: cls.url,
      });
      renderEngineVerdict(els.verifyVerdict, engine);
    } catch (err) {
      setStatus(`Verify failed: ${err.message}`, 'err');
    }
  }
}

// ---------------------------------------------------------------------------
// Wire up
// ---------------------------------------------------------------------------

els.serverUrl.textContent = CONFIG.serverBase;
els.protect.addEventListener('change', onProtectToggle);
els.search.addEventListener('input', onSearchInput);
els.clearBtn.addEventListener('click', onClearBoundary);
els.reportBtn.addEventListener('click', onReportClick);
els.verifyInput.addEventListener('input', onVerifyInput);

refreshState().catch((err) => setStatus(`Init error: ${err.message}`, 'err'));

/**
 * Local AP Trust admin UI.
 *
 * Pure browser JS (no build step). Loads data from /admin/data and posts edits
 * back to /admin/save-records, /admin/save-manifests, /admin/save-rules. The
 * verification tester reuses POST /verify so its results match the extension.
 */

const SERVER_BASE = '';

const els = {
  tabs: document.querySelectorAll('.tabs button'),
  panes: document.querySelectorAll('.tab-pane'),
  serverBadge: document.getElementById('serverBadge'),
  statServer: document.getElementById('statServer'),
  statRecords: document.getElementById('statRecords'),
  statManifests: document.getElementById('statManifests'),
  statRules: document.getElementById('statRules'),
  recordsEditor: document.getElementById('recordsEditor'),
  manifestsEditor: document.getElementById('manifestsEditor'),
  rulesEditor: document.getElementById('rulesEditor'),
  addRecordBtn: document.getElementById('addRecordBtn'),
  saveRecordsBtn: document.getElementById('saveRecordsBtn'),
  addManifestBtn: document.getElementById('addManifestBtn'),
  saveManifestsBtn: document.getElementById('saveManifestsBtn'),
  saveRulesBtn: document.getElementById('saveRulesBtn'),
  testerBoundary: document.getElementById('testerBoundary'),
  testerUrl: document.getElementById('testerUrl'),
  testerRun: document.getElementById('testerRun'),
  testerResult: document.getElementById('testerResult'),
  toastHost: document.getElementById('toastHost'),
};

const state = {
  records: [],
  manifests: {},
  rules: [],
};

initTabs();
init().catch((err) => {
  console.error(err);
  toast('Failed to initialize admin UI', 'bad');
});

function initTabs() {
  els.tabs.forEach((btn) =>
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-tab');
      els.tabs.forEach((b) => b.classList.toggle('active', b === btn));
      els.panes.forEach((p) =>
        p.classList.toggle('active', p.id === `tab-${id}`),
      );
    }),
  );
}

async function init() {
  await refreshHealth();
  await reloadAll();

  els.addRecordBtn.addEventListener('click', addEmptyRecord);
  els.saveRecordsBtn.addEventListener('click', saveRecords);
  els.addManifestBtn.addEventListener('click', addEmptyManifest);
  els.saveManifestsBtn.addEventListener('click', saveManifests);
  els.saveRulesBtn.addEventListener('click', saveRules);
  els.testerRun.addEventListener('click', runTester);
}

// ---------------- API ----------------

async function api(path, init) {
  const res = await fetch(`${SERVER_BASE}${path}`, init);
  const text = await res.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { raw: text };
    }
  }
  if (!res.ok) {
    const msg =
      (body && (body.message || body.error)) ||
      `HTTP ${res.status}`;
    const err = new Error(msg);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

async function refreshHealth() {
  try {
    const h = await api('/health');
    els.serverBadge.textContent = `${h.service} v${h.version}`;
    els.serverBadge.classList.add('ok');
    els.serverBadge.classList.remove('bad');
    els.statServer.textContent = 'OK';
  } catch (err) {
    els.serverBadge.textContent = 'unavailable';
    els.serverBadge.classList.add('bad');
    els.serverBadge.classList.remove('ok');
    els.statServer.textContent = 'Down';
    throw err;
  }
}

async function reloadAll() {
  const data = await api('/admin/data');
  state.records = Array.isArray(data.records) ? data.records : [];
  state.manifests = data.manifests && typeof data.manifests === 'object' ? data.manifests : {};
  state.rules = Array.isArray(data.rules) ? data.rules : [];
  els.statRecords.textContent = String(state.records.length);
  els.statManifests.textContent = String(Object.keys(state.manifests).length);
  els.statRules.textContent = String(state.rules.length);
  renderRecords();
  renderManifests();
  renderRules();
  renderTesterBoundaries();
}

// ---------------- Records (organizations) ----------------

function renderRecords() {
  els.recordsEditor.innerHTML = '';
  state.records.forEach((rec, idx) => {
    els.recordsEditor.appendChild(renderRecordItem(rec, idx));
  });
}

function renderRecordItem(rec, idx) {
  const item = document.createElement('div');
  item.className = 'item';
  item.innerHTML = `
    <div class="item-head">
      <div class="item-title">${esc(rec.displayName || rec.canonicalDomain || `Record ${idx + 1}`)}
        <span class="muted small">(${esc(rec.canonicalDomain || '\u2014')})</span>
      </div>
      <button class="danger" data-act="delete">Delete</button>
    </div>
    <div class="row-grid">
      <label><span>canonicalDomain</span><input type="text" data-key="canonicalDomain" value="${esc(rec.canonicalDomain || '')}" /></label>
      <label><span>displayName</span><input type="text" data-key="displayName" value="${esc(rec.displayName || '')}" /></label>
      <label><span>type</span><input type="text" data-key="type" value="${esc(rec.type || '')}" /></label>
      <label><span>status</span>
        <select data-key="status">
          ${['active', 'test', 'disabled']
            .map(
              (s) => `<option value="${s}" ${rec.status === s ? 'selected' : ''}>${s}</option>`,
            )
            .join('')}
        </select>
      </label>
      <label><span>manifestKey</span><input type="text" data-key="manifestKey" value="${esc(rec.manifestKey || '')}" /></label>
      <label><span>aliases (comma-separated)</span>
        <input type="text" data-key="aliases" value="${esc((rec.aliases || []).join(', '))}" />
      </label>
    </div>
    <div class="row-grid">
      <label><span>policy.defaultDecision</span>
        <select data-key="policy.defaultDecision">
          ${['deny', 'allow']
            .map(
              (s) =>
                `<option value="${s}" ${rec.policy?.defaultDecision === s ? 'selected' : ''}>${s}</option>`,
            )
            .join('')}
        </select>
      </label>
      <label><span>policy.allowNameserverExpansion</span>
        <input type="checkbox" data-key="policy.allowNameserverExpansion" ${rec.policy?.allowNameserverExpansion ? 'checked' : ''} />
      </label>
      <label><span>policy.requireBidirectionalVerification</span>
        <input type="checkbox" data-key="policy.requireBidirectionalVerification" ${rec.policy?.requireBidirectionalVerification ? 'checked' : ''} />
      </label>
    </div>
  `;
  bindFieldEvents(item, (key, val) => assignRecordField(idx, key, val));
  item.querySelector('[data-act="delete"]').addEventListener('click', () => {
    if (!confirm(`Delete record "${rec.canonicalDomain}"?`)) return;
    state.records.splice(idx, 1);
    renderRecords();
  });
  return item;
}

function assignRecordField(idx, key, val) {
  const rec = state.records[idx];
  if (!rec) return;
  if (key === 'aliases') {
    rec.aliases = String(val)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    return;
  }
  if (key.startsWith('policy.')) {
    rec.policy = rec.policy || {};
    rec.policy[key.slice('policy.'.length)] = val;
    return;
  }
  rec[key] = val;
}

function addEmptyRecord() {
  state.records.push({
    canonicalDomain: '',
    displayName: '',
    type: '',
    status: 'active',
    manifestKey: '',
    aliases: [],
    policy: {
      defaultDecision: 'deny',
      allowNameserverExpansion: false,
      requireBidirectionalVerification: true,
    },
  });
  renderRecords();
}

async function saveRecords() {
  try {
    await api('/admin/save-records', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(state.records),
    });
    toast('Records saved', 'ok');
    await reloadAll();
  } catch (err) {
    toast(formatError(err), 'bad');
  }
}

// ---------------- Manifests ----------------

function renderManifests() {
  els.manifestsEditor.innerHTML = '';
  Object.entries(state.manifests).forEach(([key, m]) => {
    els.manifestsEditor.appendChild(renderManifestItem(key, m));
  });
}

function renderManifestItem(key, m) {
  const item = document.createElement('div');
  item.className = 'item';
  item.innerHTML = `
    <div class="item-head">
      <div class="item-title">${esc(m.name || key)} <span class="muted small">(${esc(key)})</span></div>
      <button class="danger" data-act="delete">Delete</button>
    </div>
    <label><span>name</span><input type="text" data-key="name" value="${esc(m.name || '')}" /></label>
    <label><span>url</span><input type="text" data-key="url" value="${esc(m.url || '')}" /></label>
    <label><span>officialDomains (one per line)</span>
      <textarea data-key="officialDomains">${esc((m.officialDomains || []).join('\n'))}</textarea>
    </label>
    <label><span>socialProfiles (one per line)</span>
      <textarea data-key="socialProfiles">${esc((m.socialProfiles || []).join('\n'))}</textarea>
    </label>
    <label><span>relatedOrganizations (JSON array)</span>
      <textarea data-key="relatedOrganizations">${esc(
        JSON.stringify(m.relatedOrganizations || [], null, 2),
      )}</textarea>
    </label>
    <label><span>parentOrganization (JSON object or empty)</span>
      <textarea data-key="parentOrganization">${esc(
        m.parentOrganization ? JSON.stringify(m.parentOrganization, null, 2) : '',
      )}</textarea>
    </label>
    <label><span>claimedExternalDomains (one per line)</span>
      <textarea data-key="claimedExternalDomains">${esc((m.claimedExternalDomains || []).join('\n'))}</textarea>
    </label>
  `;
  bindFieldEvents(item, (k, val) => assignManifestField(key, k, val));
  item.querySelector('[data-act="delete"]').addEventListener('click', () => {
    if (!confirm(`Delete manifest "${key}"?`)) return;
    delete state.manifests[key];
    renderManifests();
  });
  return item;
}

function assignManifestField(manifestKey, key, val) {
  const m = state.manifests[manifestKey];
  if (!m) return;
  switch (key) {
    case 'officialDomains':
    case 'socialProfiles':
    case 'claimedExternalDomains':
      m[key] = String(val)
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (key === 'claimedExternalDomains' && m[key].length === 0) {
        delete m[key];
      }
      return;
    case 'relatedOrganizations': {
      try {
        const parsed = val ? JSON.parse(val) : [];
        if (!Array.isArray(parsed)) throw new Error('expected an array');
        m.relatedOrganizations = parsed;
      } catch (err) {
        toast(`relatedOrganizations: ${err.message}`, 'bad');
      }
      return;
    }
    case 'parentOrganization': {
      const trimmed = String(val).trim();
      if (!trimmed) {
        delete m.parentOrganization;
        return;
      }
      try {
        m.parentOrganization = JSON.parse(trimmed);
      } catch (err) {
        toast(`parentOrganization: ${err.message}`, 'bad');
      }
      return;
    }
    default:
      m[key] = val;
  }
}

function addEmptyManifest() {
  const key = prompt('Manifest key (canonical domain), e.g. example.edu');
  if (!key) return;
  if (state.manifests[key]) {
    toast(`Manifest "${key}" already exists`, 'bad');
    return;
  }
  state.manifests[key] = {
    name: '',
    url: '',
    officialDomains: [],
    relatedOrganizations: [],
    socialProfiles: [],
  };
  renderManifests();
}

async function saveManifests() {
  try {
    await api('/admin/save-manifests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(state.manifests),
    });
    toast('Manifests saved', 'ok');
    await reloadAll();
  } catch (err) {
    toast(formatError(err), 'bad');
  }
}

// ---------------- Rules ----------------

function renderRules() {
  els.rulesEditor.innerHTML = '';
  state.rules.forEach((rule, idx) => {
    els.rulesEditor.appendChild(renderRuleItem(rule, idx));
  });
}

function renderRuleItem(rule, idx) {
  const item = document.createElement('div');
  item.className = 'item';
  item.innerHTML = `
    <div class="item-head">
      <div class="item-title">${esc(rule.id)} <span class="muted small">(${esc(rule.type)})</span></div>
      <label class="muted small" style="display:flex;gap:6px;align-items:center;">
        <input type="checkbox" data-key="enabled" ${rule.enabled ? 'checked' : ''} /> enabled
      </label>
    </div>
    <div class="row-grid">
      <label><span>scope</span><input type="text" data-key="scope" value="${esc(rule.scope || '')}" /></label>
      <label><span>effect</span><input type="text" data-key="effect" value="${esc(rule.effect || '')}" /></label>
      <label><span>priority</span><input type="number" data-key="priority" value="${esc(String(rule.priority ?? 0))}" /></label>
      <label><span>requiresBidirectionalVerification</span>
        <input type="checkbox" data-key="requiresBidirectionalVerification" ${rule.requiresBidirectionalVerification ? 'checked' : ''} />
      </label>
    </div>
    <label><span>notes</span>
      <textarea data-key="notes">${esc(rule.notes || '')}</textarea>
    </label>
    ${rule.type === 'NAMESERVER_ALLOWLIST' ? `
      <label><span>nameservers (one per line)</span>
        <textarea data-key="nameservers">${esc((rule.nameservers || []).join('\n'))}</textarea>
      </label>
      <p class="muted small">
        Nameserver allowlist is metadata only. It can produce
        <code>RELATED_CANDIDATE</code>; it never marks a domain as
        <code>OFFICIAL</code> on its own.
      </p>
    ` : ''}
  `;
  bindFieldEvents(item, (key, val) => assignRuleField(idx, key, val));
  return item;
}

function assignRuleField(idx, key, val) {
  const rule = state.rules[idx];
  if (!rule) return;
  if (key === 'priority') {
    const n = Number(val);
    if (!Number.isFinite(n)) return;
    rule.priority = n;
    return;
  }
  if (key === 'nameservers') {
    rule.nameservers = String(val)
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    return;
  }
  rule[key] = val;
}

async function saveRules() {
  try {
    await api('/admin/save-rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(state.rules),
    });
    toast('Rules saved', 'ok');
    await reloadAll();
  } catch (err) {
    toast(formatError(err), 'bad');
  }
}

// ---------------- Tester ----------------

function renderTesterBoundaries() {
  els.testerBoundary.innerHTML = '';
  state.records.forEach((r) => {
    const opt = document.createElement('option');
    opt.value = r.canonicalDomain;
    opt.textContent = `${r.displayName} (${r.canonicalDomain})`;
    els.testerBoundary.appendChild(opt);
  });
}

async function runTester() {
  const boundary = els.testerBoundary.value;
  const url = els.testerUrl.value.trim();
  if (!boundary || !url) {
    toast('Pick a boundary and enter a URL.', 'bad');
    return;
  }
  els.testerResult.textContent = 'Running\u2026';
  try {
    const res = await api('/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ boundary, url }),
    });
    els.testerResult.innerHTML = `
      <div><span class="badge ${esc(res.status)}">${esc(res.status)}</span>
        <span class="muted">status code <strong>${esc(String(res.statusCode))}</strong> \u00b7 relationship <strong>${esc(res.relationship)}</strong></span>
      </div>
      <div class="muted small" style="margin:6px 0;">${esc(res.url)} \u2192 ${esc(res.normalizedDomain)}</div>
      <pre style="margin:0;white-space:pre-wrap;">${esc((res.reasons || []).map((r) => '\u2022 ' + r).join('\n'))}</pre>
    `;
  } catch (err) {
    els.testerResult.textContent = formatError(err);
  }
}

// ---------------- helpers ----------------

function bindFieldEvents(root, onChange) {
  root.querySelectorAll('[data-key]').forEach((input) => {
    const key = input.getAttribute('data-key');
    const handler = () => {
      const val = input.type === 'checkbox' ? input.checked : input.value;
      onChange(key, val);
    };
    input.addEventListener('change', handler);
    if (input.tagName === 'INPUT' && input.type !== 'checkbox') {
      input.addEventListener('blur', handler);
    }
    if (input.tagName === 'TEXTAREA') {
      input.addEventListener('blur', handler);
    }
  });
}

function toast(message, kind) {
  const div = document.createElement('div');
  div.className = `toast ${kind || ''}`;
  div.textContent = message;
  els.toastHost.appendChild(div);
  setTimeout(() => div.remove(), 3500);
}

function formatError(err) {
  if (!err) return 'Unknown error';
  if (err.body && Array.isArray(err.body.issues)) {
    return `Validation failed: ${err.body.issues.join('; ')}`;
  }
  return err.message || String(err);
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

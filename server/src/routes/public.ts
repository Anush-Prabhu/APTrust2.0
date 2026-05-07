import { Router } from 'express';
import {
  loadAll,
  loadManifests,
  loadRawManifest,
  loadRecords,
  loadRules,
} from '../data';
import { verifyUrl } from '../engine/engine';
import type { VerifyRequest } from '../types';

const SERVICE_NAME = 'aptrust-local-server';
const SERVICE_VERSION = '2.0.0';

export function publicRouter(): Router {
  const router = Router();

  // FR-SRV-001: health.
  router.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
    });
  });

  // FR-SRV-002: search trust boundaries.
  router.get('/search', (req, res) => {
    const q = String(req.query.q ?? '').trim().toLowerCase();
    let records;
    try {
      records = loadRecords();
    } catch (err: any) {
      return res.status(500).json({ error: 'data_error', message: err.message });
    }
    const visible = records.filter((r) => r.status !== 'disabled');
    const list = q
      ? visible.filter((r) => recordMatches(r, q))
      : visible;
    const results = list.map((r) => ({
      canonicalDomain: r.canonicalDomain,
      displayName: r.displayName,
      type: r.type,
      aliases: r.aliases,
      status: r.status,
    }));
    res.json(results);
  });

  // FR-SRV-003: get organization entry.
  router.get('/entry/:domain', (req, res) => {
    const domain = String(req.params.domain || '').trim().toLowerCase();
    let records;
    try {
      records = loadRecords();
    } catch (err: any) {
      return res.status(500).json({ error: 'data_error', message: err.message });
    }
    const entry = records.find(
      (r) => r.canonicalDomain.toLowerCase() === domain,
    );
    if (!entry) {
      return res.status(404).json({ error: 'not_found', domain });
    }
    res.json(entry);
  });

  // FR-SRV-004: get manifest. Returns the on-disk JSON (preserves the
  // JSON-LD @context / aptrust:* keys when authored that way), plus a
  // `_normalized` view for clients that want the plain v2 shape.
  router.get('/manifest/:domain', (req, res) => {
    const domain = String(req.params.domain || '').trim().toLowerCase();
    let records, manifests;
    try {
      records = loadRecords();
      manifests = loadManifests();
    } catch (err: any) {
      return res.status(500).json({ error: 'data_error', message: err.message });
    }
    const record = records.find(
      (r) => r.canonicalDomain.toLowerCase() === domain,
    );
    const key = record?.manifestKey || domain;
    const normalized = manifests[key];
    if (!normalized) {
      return res.status(404).json({ error: 'not_found', domain });
    }
    const raw = loadRawManifest(key) ?? {};
    // The on-disk JSON-LD body is preserved (clients can read
    // `aptrust:sameAsDomain` etc. directly), and `_normalized` provides the
    // engine-internal v2 shape for clients that don't grok the JSON-LD keys.
    // `_policy` exposes the optional `trustRootCanonical` and
    // `acceptWithinBoundary` fields the popup uses to label the boundary.
    res.json({
      ...raw,
      _normalized: normalized,
      _policy: record?.policy
        ? {
            trustRootCanonical: record.policy.trustRootCanonical || null,
            acceptWithinBoundary:
              record.policy.acceptWithinBoundary || 'bidirectional',
          }
        : null,
    });
  });

  // FR-SRV-005: get rules.
  router.get('/rules', (_req, res) => {
    let rules;
    try {
      rules = loadRules();
    } catch (err: any) {
      return res.status(500).json({ error: 'data_error', message: err.message });
    }
    res.json(rules);
  });

  /**
   * POST /report — mock impersonation-report sink (APT 1.0 extension parity).
   * Logs to stdout only; no remote delivery in the local POC.
   */
  router.post('/report', (req, res) => {
    const body = (req.body || {}) as Record<string, unknown>;
    const id = `mock-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const record = {
      id,
      receivedAt: new Date().toISOString(),
      url: body.url ?? null,
      reason: body.reason ?? null,
      boundary: body.boundary ?? null,
      pageResult: body.pageResult ?? null,
      userAgent: req.get('user-agent') || null,
      submittedAt: body.submittedAt ?? null,
    };
    // eslint-disable-next-line no-console
    console.log('[aptrust] /report (mock)', JSON.stringify(record, null, 2));
    res.status(201).json({
      ok: true,
      id,
      message: `Mock report filed for boundary ${(body.boundary as any)?.canonicalDomain ?? 'unknown'}.`,
    });
  });

  // FR-SRV-006: verify URL.
  router.post('/verify', (req, res) => {
    const body = (req.body || {}) as Partial<VerifyRequest>;
    if (typeof body.boundary !== 'string' || typeof body.url !== 'string') {
      return res.status(400).json({
        error: 'invalid_request',
        message: 'Body must include string fields "boundary" and "url".',
      });
    }
    let ctx;
    try {
      ctx = loadAll();
    } catch (err: any) {
      return res.status(500).json({ error: 'data_error', message: err.message });
    }
    const result = verifyUrl({ boundary: body.boundary, url: body.url }, ctx);
    res.json(result);
  });

  return router;
}

function recordMatches(record: any, q: string): boolean {
  if (!q) return false;
  const haystack: string[] = [];
  if (record.canonicalDomain) haystack.push(record.canonicalDomain);
  if (record.displayName) haystack.push(record.displayName);
  if (record.type) haystack.push(record.type);
  if (Array.isArray(record.aliases)) haystack.push(...record.aliases);
  return haystack.some(
    (h) => typeof h === 'string' && h.toLowerCase().includes(q),
  );
}

import express, { Router } from 'express';
import path from 'node:path';
import {
  ValidationError,
  loadAll,
  saveManifests,
  saveRecords,
  saveRules,
} from '../data';
import { findManifestDrift } from '../engine/explanations';

export function adminRouter(): Router {
  const router = Router();

  // FR-SRV-007: get all admin data.
  router.get('/data', (_req, res) => {
    try {
      res.json(loadAll());
    } catch (err: any) {
      res.status(500).json({ error: 'data_error', message: err.message });
    }
  });

  // FR-SRV-008: save records.
  router.post('/save-records', (req, res) => {
    const payload = req.body;
    try {
      saveRecords(payload);
      res.json({ ok: true });
    } catch (err: any) {
      if (err instanceof ValidationError) {
        return res
          .status(400)
          .json({ error: 'validation_error', issues: err.issues });
      }
      res.status(500).json({ error: 'save_failed', message: err.message });
    }
  });

  // FR-SRV-009: save manifests.
  router.post('/save-manifests', (req, res) => {
    const payload = req.body;
    try {
      saveManifests(payload);
      res.json({ ok: true });
    } catch (err: any) {
      if (err instanceof ValidationError) {
        return res
          .status(400)
          .json({ error: 'validation_error', issues: err.issues });
      }
      res.status(500).json({ error: 'save_failed', message: err.message });
    }
  });

  /**
   * Pairwise relationship-graph consistency. Lists every claim in a
   * manifest that is not reciprocated by the counterparty's manifest, plus
   * any claim that points at a record we cannot resolve. The verdict for a
   * single /verify call is unaffected; this endpoint is for operators
   * doing manifest-level lint.
   */
  router.get('/manifest-consistency', (_req, res) => {
    try {
      const { records, manifests } = loadAll();
      const findings = findManifestDrift(records, manifests);
      res.json({
        records: records.length,
        manifests: Object.keys(manifests).length,
        findings,
      });
    } catch (err: any) {
      res.status(500).json({ error: 'data_error', message: err.message });
    }
  });

  // FR-SRV-010: save rules.
  router.post('/save-rules', (req, res) => {
    const payload = req.body;
    try {
      saveRules(payload);
      res.json({ ok: true });
    } catch (err: any) {
      if (err instanceof ValidationError) {
        return res
          .status(400)
          .json({ error: 'validation_error', issues: err.issues });
      }
      res.status(500).json({ error: 'save_failed', message: err.message });
    }
  });

  return router;
}

/** Mounts the static admin UI at GET /admin. */
export function adminUiMiddleware(publicDir: string): express.RequestHandler {
  return express.static(path.resolve(publicDir), {
    fallthrough: true,
    index: 'index.html',
  });
}

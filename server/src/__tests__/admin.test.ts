import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../app';

const sourceDir = path.resolve(__dirname, '..', '..', '..', 'data');
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aptrust-admin-'));

function copyDirSync(src: string, dest: string) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDirSync(s, d);
    } else {
      fs.copyFileSync(s, d);
    }
  }
}

beforeAll(() => {
  for (const f of ['records.json', 'rules.json']) {
    fs.copyFileSync(path.join(sourceDir, f), path.join(tmpDir, f));
  }
  copyDirSync(path.join(sourceDir, 'manifests'), path.join(tmpDir, 'manifests'));
  process.env.APTRUST_DATA_DIR = tmpDir;
});

afterAll(() => {
  delete process.env.APTRUST_DATA_DIR;
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('admin save endpoints', () => {
  it('saves a valid records edit and reloads it', async () => {
    const app = createApp();
    const get = await request(app).get('/admin/data');
    expect(get.status).toBe(200);
    const records = get.body.records;
    records[0].displayName = 'Johns Hopkins University (renamed in test)';
    const save = await request(app).post('/admin/save-records').send(records);
    expect(save.status).toBe(200);
    expect(save.body.ok).toBe(true);

    const fresh = await request(app).get('/admin/data');
    expect(fresh.body.records[0].displayName).toBe(
      'Johns Hopkins University (renamed in test)',
    );
  });

  it('rejects records missing required fields', async () => {
    const app = createApp();
    const bad = [{ canonicalDomain: 'broken.test' }];
    const save = await request(app).post('/admin/save-records').send(bad);
    expect(save.status).toBe(400);
    expect(save.body.error).toBe('validation_error');
    expect(Array.isArray(save.body.issues)).toBe(true);
  });

  it('toggles the nameserver rule via save-rules', async () => {
    const app = createApp();
    const get = await request(app).get('/admin/data');
    const rules = get.body.rules;
    const ns = rules.find((r: any) => r.type === 'NAMESERVER_ALLOWLIST');
    expect(ns).toBeDefined();
    ns.enabled = true;
    const save = await request(app).post('/admin/save-rules').send(rules);
    expect(save.status).toBe(200);
    const fresh = await request(app).get('/rules');
    const after = fresh.body.find(
      (r: any) => r.type === 'NAMESERVER_ALLOWLIST',
    );
    expect(after.enabled).toBe(true);
  });
});

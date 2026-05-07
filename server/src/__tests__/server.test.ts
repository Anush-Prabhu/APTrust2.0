import path from 'node:path';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../app';

const dataDir = path.resolve(__dirname, '..', '..', '..', 'data');
process.env.APTRUST_DATA_DIR = dataDir;

let app: ReturnType<typeof createApp>;

beforeAll(() => {
  app = createApp();
});

afterAll(() => {
  delete process.env.APTRUST_DATA_DIR;
});

describe('public API', () => {
  it('T-SRV-001: GET /health returns ok', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.service).toBe('aptrust-local-server');
  });

  it('T-SRV-002: GET /search?q=jhu returns jhu.edu and jhuu.com', async () => {
    const res = await request(app).get('/search?q=jhu');
    expect(res.status).toBe(200);
    const domains = res.body.map((r: any) => r.canonicalDomain);
    expect(domains).toContain('jhu.edu');
    expect(domains).toContain('jhuu.com');
  });

  it('T-SRV-003: GET /search?q=medicine returns hopkinsmedicine.org', async () => {
    const res = await request(app).get('/search?q=medicine');
    expect(res.status).toBe(200);
    const domains = res.body.map((r: any) => r.canonicalDomain);
    expect(domains).toContain('hopkinsmedicine.org');
  });

  it('T-SRV-004: GET /entry/jhu.edu returns the JHU record', async () => {
    const res = await request(app).get('/entry/jhu.edu');
    expect(res.status).toBe(200);
    expect(res.body.canonicalDomain).toBe('jhu.edu');
    expect(res.body.policy.requireBidirectionalVerification).toBe(true);
  });

  it('T-SRV-005: GET /entry for unknown domain returns 404', async () => {
    const res = await request(app).get('/entry/no-such-domain.example');
    expect(res.status).toBe(404);
  });

  it('T-SRV-006: GET /manifest/jhu.edu returns the JHU manifest with JSON-LD context', async () => {
    const res = await request(app).get('/manifest/jhu.edu');
    expect(res.status).toBe(200);
    expect(res.body.name).toBe('Johns Hopkins University');
    expect(res.body['@type']).toBe('Organization');
    expect(res.body['@context']).toBeDefined();
    expect(Array.isArray(res.body['aptrust:sameAsDomain'])).toBe(true);
    expect(Array.isArray(res.body._normalized.officialDomains)).toBe(true);
    expect(res.body._normalized.officialDomains.length).toBeGreaterThan(0);
  });

  it('T-SRV-007: GET /rules includes a disabled NAMESERVER_ALLOWLIST rule', async () => {
    const res = await request(app).get('/rules');
    expect(res.status).toBe(200);
    const ns = res.body.find((r: any) => r.type === 'NAMESERVER_ALLOWLIST');
    expect(ns).toBeDefined();
    expect(ns.enabled).toBe(false);
  });

  it('T-SRV-008: GET /admin/data returns records, manifests, and rules', async () => {
    const res = await request(app).get('/admin/data');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.records)).toBe(true);
    expect(typeof res.body.manifests).toBe('object');
    expect(Array.isArray(res.body.rules)).toBe(true);
  });

  it('POST /verify returns the suspicious unidirectional claim shape', async () => {
    const res = await request(app)
      .post('/verify')
      .send({ boundary: 'jhuu.com', url: 'https://jhu.edu/' });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('SUSPICIOUS_UNIDIRECTIONAL_CLAIM');
    expect(res.body.relationship).toBe('UNIDIRECTIONAL_CLAIM');
    expect(res.body.statusCode).toBe(10);
  });

  it('POST /verify rejects malformed bodies', async () => {
    const res = await request(app).post('/verify').send({ url: 'https://x' });
    expect(res.status).toBe(400);
  });

  it('POST /report returns mock id (extension parity)', async () => {
    const res = await request(app)
      .post('/report')
      .send({
        url: 'https://example.com/',
        reason: 'test',
        boundary: { canonicalDomain: 'jhu.edu' },
      });
    expect(res.status).toBe(201);
    expect(res.body.ok).toBe(true);
    expect(res.body.id).toBeDefined();
    expect(res.body.message).toMatch(/Mock report/i);
  });
});

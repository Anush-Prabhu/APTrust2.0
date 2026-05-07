/**
 * Tests for dynamic unidirectional-claim reasons + cross-manifest drift.
 *
 * The dynamic-reasons tests use a temp data directory with a freshly
 * authored malicious manifest. They prove that the verdict messages follow
 * the manifest's actual contents \u2014 if an operator hand-writes a new
 * impostor manifest, the engine still produces field-by-field explanations
 * without any code change.
 *
 * The drift tests exercise the cross-manifest lint independently of the
 * verify path, so a single API call can return findings for every loaded
 * pair.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from 'vitest';
import request from 'supertest';

const sourceDir = path.resolve(__dirname, '..', '..', '..', 'data');
let tmpDir: string;

function copyDirSync(src: string, dest: string) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) copyDirSync(s, d);
    else fs.copyFileSync(s, d);
  }
}

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aptrust-explanations-'));
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

// Each test installs its own scratch records/manifest where needed.
let originalRecords: string;
let installedManifests: string[] = [];
beforeEach(() => {
  originalRecords = fs.readFileSync(path.join(tmpDir, 'records.json'), 'utf8');
  installedManifests = [];
});
afterEach(() => {
  fs.writeFileSync(path.join(tmpDir, 'records.json'), originalRecords);
  for (const p of installedManifests) {
    try { fs.unlinkSync(p); } catch { /* ignore */ }
  }
});

function installRecord(rec: any) {
  const recordsPath = path.join(tmpDir, 'records.json');
  const arr = JSON.parse(fs.readFileSync(recordsPath, 'utf8'));
  arr.push(rec);
  fs.writeFileSync(recordsPath, JSON.stringify(arr, null, 2));
}

function installManifest(canonical: string, body: any) {
  const p = path.join(tmpDir, 'manifests', `${canonical}.json`);
  fs.writeFileSync(p, JSON.stringify(body, null, 2));
  installedManifests.push(p);
}

describe('explanations: dynamic unidirectional claim reasons', () => {
  it('seed jhuu.com manifest produces field-by-field reasons against jhu.edu', async () => {
    const { loadAll } = await import('../data');
    const { verifyUrl } = await import('../engine/engine');
    const ctx = loadAll();
    const r = verifyUrl({ boundary: 'jhuu.com', url: 'https://jhu.edu/' }, ctx);
    expect(r.status).toBe('SUSPICIOUS_UNIDIRECTIONAL_CLAIM');
    const joined = r.reasons.join('\n');
    // Headline + claim path + reciprocation scan + policy line.
    expect(joined).toMatch(/jhuu\.com claims a relationship to jhu\.edu/);
    expect(joined).toMatch(/relatedOrganizations on jhuu\.com contains/i);
    expect(joined).toMatch(/Searched jhu\.edu's manifest/);
    expect(joined).toMatch(/parentOrganization/);
    expect(joined).toMatch(/relatedOrganizations/);
    expect(joined).toMatch(/officialDomains/);
    expect(joined).toMatch(/Self-attestation alone is not sufficient/);
  });

  it('custom malicious manifest is explained from its actual fields', async () => {
    // Author three single-path malicious boundaries so each claim type
    // (relatedOrganizations, claimedExternalDomains, parentOrganization) is
    // exercised in isolation. The verdict reasons must echo each authored
    // field literally; this is what makes the engine's messages dynamic
    // rather than templated.

    installRecord({
      canonicalDomain: 'evil-rel.test',
      displayName: 'Evil Rel',
      type: 'SuspiciousExample',
      status: 'test',
      manifestKey: 'evil-rel.test',
      aliases: [],
      policy: {
        defaultDecision: 'deny',
        allowNameserverExpansion: false,
        requireBidirectionalVerification: true,
      },
    });
    installManifest('evil-rel.test', {
      name: 'Evil Rel',
      url: 'https://evil-rel.test/',
      officialDomains: ['https://evil-rel.test/'],
      socialProfiles: [],
      relatedOrganizations: [
        {
          name: 'Johns Hopkins University',
          canonicalDomain: 'jhu.edu',
          url: 'https://jhu.edu/',
          domains: ['https://jhu.edu/', 'https://www.jhu.edu/'],
          relationshipType: 'claimed-affiliation',
        },
      ],
    });

    installRecord({
      canonicalDomain: 'evil-claim.test',
      displayName: 'Evil Claim',
      type: 'SuspiciousExample',
      status: 'test',
      manifestKey: 'evil-claim.test',
      aliases: [],
      policy: {
        defaultDecision: 'deny',
        allowNameserverExpansion: false,
        requireBidirectionalVerification: true,
      },
    });
    installManifest('evil-claim.test', {
      name: 'Evil Claim',
      url: 'https://evil-claim.test/',
      officialDomains: ['https://evil-claim.test/'],
      socialProfiles: [],
      claimedExternalDomains: ['https://www.hopkinsmedicine.org/'],
    });

    installRecord({
      canonicalDomain: 'evil-parent.test',
      displayName: 'Evil Parent',
      type: 'SuspiciousExample',
      status: 'test',
      manifestKey: 'evil-parent.test',
      aliases: [],
      policy: {
        defaultDecision: 'deny',
        allowNameserverExpansion: false,
        requireBidirectionalVerification: true,
      },
    });
    installManifest('evil-parent.test', {
      name: 'Evil Parent',
      url: 'https://evil-parent.test/',
      officialDomains: ['https://evil-parent.test/'],
      socialProfiles: [],
      parentOrganization: {
        name: 'Johns Hopkins Medical Institutions',
        canonicalDomain: 'jhmi.edu',
        url: 'https://www.jhmi.edu/',
      },
    });

    const { loadAll } = await import('../data');
    const { verifyUrl } = await import('../engine/engine');
    const ctx = loadAll();

    const r1 = verifyUrl(
      { boundary: 'evil-rel.test', url: 'https://jhu.edu/' },
      ctx,
    );
    expect(r1.status).toBe('SUSPICIOUS_UNIDIRECTIONAL_CLAIM');
    expect(r1.reasons.join('\n')).toMatch(
      /relatedOrganizations on evil-rel\.test contains "Johns Hopkins University" \(jhu\.edu\)/,
    );

    const r2 = verifyUrl(
      { boundary: 'evil-claim.test', url: 'https://www.hopkinsmedicine.org/' },
      ctx,
    );
    expect(r2.status).toBe('SUSPICIOUS_UNIDIRECTIONAL_CLAIM');
    expect(r2.reasons.join('\n')).toMatch(
      /claimedExternalDomains on evil-claim\.test contains "https:\/\/www\.hopkinsmedicine\.org\/"/,
    );

    const r3 = verifyUrl(
      { boundary: 'evil-parent.test', url: 'https://www.jhmi.edu/' },
      ctx,
    );
    expect(r3.status).toBe('SUSPICIOUS_UNIDIRECTIONAL_CLAIM');
    expect(r3.reasons.join('\n')).toMatch(
      /parentOrganization on evil-parent\.test = "Johns Hopkins Medical Institutions" \(jhmi\.edu\)/,
    );
  });

  it('reasons cite scanned counterparty fields when the claim is asymmetric', async () => {
    // Plant a victim manifest that has a parentOrganization, related, and
    // officialDomains, but none of them point at evilcorp.test. The scan
    // section of the reasons must list each entry that was checked.
    installRecord({
      canonicalDomain: 'victim.test',
      displayName: 'Victim Org',
      type: 'CollegeOrUniversity',
      status: 'active',
      manifestKey: 'victim.test',
      aliases: [],
      policy: {
        defaultDecision: 'deny',
        allowNameserverExpansion: false,
        requireBidirectionalVerification: true,
      },
    });
    installManifest('victim.test', {
      name: 'Victim Org',
      url: 'https://victim.test/',
      officialDomains: ['https://victim.test/', 'https://alt.victim.test/'],
      socialProfiles: [],
      relatedOrganizations: [
        {
          name: 'Some Friend',
          canonicalDomain: 'friend.test',
          url: 'https://friend.test/',
          domains: ['https://friend.test/'],
        },
      ],
      parentOrganization: {
        name: 'Parent Org',
        canonicalDomain: 'parent.test',
        url: 'https://parent.test/',
      },
    });
    installRecord({
      canonicalDomain: 'liar.test',
      displayName: 'Liar Org',
      type: 'SuspiciousExample',
      status: 'test',
      manifestKey: 'liar.test',
      aliases: [],
      policy: {
        defaultDecision: 'deny',
        allowNameserverExpansion: false,
        requireBidirectionalVerification: true,
      },
    });
    installManifest('liar.test', {
      name: 'Liar Org',
      url: 'https://liar.test/',
      officialDomains: ['https://liar.test/'],
      socialProfiles: [],
      relatedOrganizations: [
        {
          name: 'Victim Org',
          canonicalDomain: 'victim.test',
          url: 'https://victim.test/',
          domains: ['https://victim.test/'],
        },
      ],
    });

    const { loadAll } = await import('../data');
    const { verifyUrl } = await import('../engine/engine');
    const ctx = loadAll();
    const r = verifyUrl(
      { boundary: 'liar.test', url: 'https://victim.test/' },
      ctx,
    );
    expect(r.status).toBe('SUSPICIOUS_UNIDIRECTIONAL_CLAIM');
    const joined = r.reasons.join('\n');
    expect(joined).toMatch(/parentOrganization: present \("parent\.test"\)/);
    expect(joined).toMatch(/relatedOrganizations: 1 entry scanned \(friend\.test\)/);
    expect(joined).toMatch(/officialDomains: 2 entries scanned/);
  });
});

describe('explanations: cross-manifest relationship drift', () => {
  it('seed corpus is internally consistent for the JHU family', async () => {
    const { loadAll } = await import('../data');
    const { findManifestDrift } = await import('../engine/explanations');
    const { records, manifests } = loadAll();
    const findings = findManifestDrift(records, manifests);
    // The seed JHU family is fully reciprocated. The only legitimate
    // findings come from jhuu.com (the malicious example).
    for (const f of findings) {
      expect(f.from).toBe('jhuu.com');
    }
  });

  it('detects drift when an authored manifest drops a reciprocal edge', async () => {
    // Replace jhmi.edu with a copy that no longer declares jhu.edu in any
    // reciprocal field. jhu.edu still claims jhmi.edu as a related org, so
    // the drift detector must flag the (jhu.edu -> jhmi.edu) edge.
    const jhmiBackup = fs.readFileSync(
      path.join(tmpDir, 'manifests', 'jhmi.edu.json'),
      'utf8',
    );
    try {
      installManifest('jhmi.edu', {
        name: 'Johns Hopkins Medical Institutions',
        url: 'https://www.jhmi.edu/',
        officialDomains: ['https://jhmi.edu/', 'https://www.jhmi.edu/'],
        socialProfiles: [],
      });
      const { loadAll } = await import('../data');
      const { findManifestDrift, findingsForPair } = await import(
        '../engine/explanations'
      );
      const { records, manifests } = loadAll();
      const findings = findManifestDrift(records, manifests);
      const pair = findingsForPair(findings, 'jhu.edu', 'jhmi.edu');
      expect(pair.length).toBeGreaterThan(0);
      // jhu.edu's manifest declares jhmi.edu via relatedOrganizations.
      expect(pair[0].kind).toBe('unreciprocated_related');
      expect(pair[0].from).toBe('jhu.edu');
      expect(pair[0].to).toBe('jhmi.edu');
    } finally {
      fs.writeFileSync(
        path.join(tmpDir, 'manifests', 'jhmi.edu.json'),
        jhmiBackup,
      );
    }
  });

  it('reports unknown_record when a manifest references a missing org', async () => {
    installRecord({
      canonicalDomain: 'orphan.test',
      displayName: 'Orphan Org',
      type: 'CollegeOrUniversity',
      status: 'active',
      manifestKey: 'orphan.test',
      aliases: [],
      policy: {
        defaultDecision: 'deny',
        allowNameserverExpansion: false,
        requireBidirectionalVerification: true,
      },
    });
    installManifest('orphan.test', {
      name: 'Orphan Org',
      url: 'https://orphan.test/',
      officialDomains: ['https://orphan.test/'],
      socialProfiles: [],
      relatedOrganizations: [
        {
          name: 'Ghost',
          canonicalDomain: 'ghost.invalid',
          url: 'https://ghost.invalid/',
          domains: ['https://ghost.invalid/'],
        },
      ],
    });
    const { loadAll } = await import('../data');
    const { findManifestDrift } = await import('../engine/explanations');
    const { records, manifests } = loadAll();
    const findings = findManifestDrift(records, manifests);
    const orphan = findings.filter((f) => f.from === 'orphan.test');
    // The orphan can produce an unknown_record OR (if no record is found) an
    // unreciprocated finding; we just assert it is surfaced at all.
    expect(orphan.length).toBeGreaterThan(0);
  });
});

describe('explanations: GET /admin/manifest-consistency', () => {
  it('returns findings via the admin endpoint', async () => {
    const { createApp } = await import('../app');
    const app = createApp();
    const res = await request(app).get('/admin/manifest-consistency');
    expect(res.status).toBe(200);
    expect(typeof res.body.records).toBe('number');
    expect(typeof res.body.manifests).toBe('number');
    expect(Array.isArray(res.body.findings)).toBe(true);
    // jhuu.com unreciprocated claims should be visible.
    const jhuuFindings = res.body.findings.filter(
      (f: any) => f.from === 'jhuu.com',
    );
    expect(jhuuFindings.length).toBeGreaterThan(0);
  });
});

describe('verify: drift warnings are attached when a pair is asymmetric', () => {
  it('jhuu.com -> jhu.edu carries manifest_drift warnings', async () => {
    const { loadAll } = await import('../data');
    const { verifyUrl } = await import('../engine/engine');
    const ctx = loadAll();
    const r = verifyUrl({ boundary: 'jhuu.com', url: 'https://jhu.edu/' }, ctx);
    expect(r.warnings).toBeDefined();
    expect((r.warnings || []).some((w) => w.kind === 'manifest_drift')).toBe(
      true,
    );
  });

  it('jhu.edu -> hopkinsmedicine.org has NO drift warnings (reciprocal)', async () => {
    const { loadAll } = await import('../data');
    const { verifyUrl } = await import('../engine/engine');
    const ctx = loadAll();
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://www.hopkinsmedicine.org/' },
      ctx,
    );
    expect(r.warnings === undefined || r.warnings.length === 0).toBe(true);
  });
});

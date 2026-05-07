/**
 * Local JSON data store for the AP Trust POC.
 *
 * Files live under `<repoRoot>/data/`:
 *   - records.json
 *   - manifests/<canonicalDomain>.json   (one file per organization)
 *   - rules.json
 *
 * The per-domain manifest layout mirrors APT 1.0 (`aptrust-records/domains/
 * <domain>/manifest.jsonld`), so each org's manifest is editable in
 * isolation and can later be served from a GitHub raw URL.
 *
 * All reads happen lazily on each request to keep the demo predictable when
 * the admin UI saves changes. Writes use a temp-file + rename to avoid
 * corrupting an existing JSON file on a failed save.
 */

import fs from 'node:fs';
import path from 'node:path';
import type {
  AdminDataPayload,
  Manifest,
  ManifestMap,
  RecordEntry,
  Rule,
} from './types';

const DEFAULT_DATA_DIR = path.resolve(__dirname, '..', '..', 'data');

/**
 * Resolves the data directory at call time so that tests (and operators) can
 * point the server at an alternate location via the `APTRUST_DATA_DIR`
 * environment variable.
 */
export function dataDir(): string {
  const env = process.env.APTRUST_DATA_DIR;
  return env ? path.resolve(env) : DEFAULT_DATA_DIR;
}

export function recordsPath(): string {
  return path.join(dataDir(), 'records.json');
}
/**
 * Directory holding one JSON file per canonical domain.
 *
 * @example
 *   data/manifests/jhu.edu.json
 *   data/manifests/hopkinsmedicine.org.json
 */
export function manifestsDir(): string {
  return path.join(dataDir(), 'manifests');
}
export function manifestPath(canonicalDomain: string): string {
  return path.join(manifestsDir(), `${canonicalDomain}.json`);
}
export function rulesPath(): string {
  return path.join(dataDir(), 'rules.json');
}

function readJsonSafe<T>(p: string, fallback: T): T {
  try {
    const raw = fs.readFileSync(p, 'utf8');
    return JSON.parse(raw) as T;
  } catch (err: any) {
    if (err && err.code === 'ENOENT') return fallback;
    throw new Error(
      `Failed to read JSON file ${path.relative(process.cwd(), p)}: ${err?.message || err}`,
    );
  }
}

function writeJsonAtomic(p: string, value: unknown): void {
  const dir = path.dirname(p);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = `${p}.tmp-${process.pid}-${Date.now()}`;
  const json = JSON.stringify(value, null, 2) + '\n';
  fs.writeFileSync(tmp, json, 'utf8');
  fs.renameSync(tmp, p);
}

export function loadRecords(): RecordEntry[] {
  const value = readJsonSafe<RecordEntry[]>(recordsPath(), []);
  if (!Array.isArray(value)) {
    throw new Error('records.json must be an array of record objects.');
  }
  return value;
}

/**
 * Loads every `data/manifests/*.json` file and returns them keyed by file
 * basename (which must be the canonical domain).
 *
 * Each file's content must be a single Manifest object \u2014 NOT a map. This
 * mirrors the v1 layout `aptrust-records/domains/<domain>/manifest.jsonld`.
 *
 * Files may be in either of two forms:
 *
 *   1. Plain v2 keys (officialDomains, socialProfiles, ...).
 *   2. JSON-LD with a schema.org `@context` and `aptrust:` namespace
 *      (preferred form, matches APT 1.0). Keys are mapped via
 *      `coerceManifest` below.
 *
 * The loader always returns the internal v2 shape; callers do not need to
 * know which form the file used.
 */
export function loadManifests(): ManifestMap {
  const dir = manifestsDir();
  const map: ManifestMap = {};
  let files: string[] = [];
  try {
    files = fs.readdirSync(dir);
  } catch (err: any) {
    if (err && err.code === 'ENOENT') return map;
    throw err;
  }
  for (const name of files) {
    if (!name.toLowerCase().endsWith('.json')) continue;
    const canonical = name.replace(/\.json$/i, '');
    const raw = readJsonSafe<Record<string, unknown> | null>(
      path.join(dir, name),
      null,
    );
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error(`Manifest file "${name}" must contain a JSON object.`);
    }
    map[canonical] = coerceManifest(raw, canonical);
  }
  return map;
}

/**
 * Returns the on-disk manifest JSON for `canonicalDomain` exactly as
 * authored \u2014 including any JSON-LD `@context`, `@type`, `aptrust:*` keys.
 * The `/manifest/:domain` HTTP route serves this so clients see the rich
 * schema.org representation.
 */
export function loadRawManifest(
  canonicalDomain: string,
): Record<string, unknown> | null {
  const p = manifestPath(canonicalDomain);
  return readJsonSafe<Record<string, unknown> | null>(p, null);
}

/**
 * Translate a raw on-disk manifest object (JSON-LD or plain v2) into the
 * internal `Manifest` shape used by the engine.
 *
 * Maximum schema.org / APT 1.0 keyword recognition:
 *   - schema.org `name`, `url`                        \u2192 Manifest.name / .url
 *   - `aptrust:sameAsDomain` | `officialDomains`      \u2192 .officialDomains
 *   - `aptrust:sameAsSocialProfile` | `socialProfiles`\u2192 .socialProfiles
 *   - `aptrust:sameAsAdditionalProfile` | `additionalProfiles`
 *                                                     \u2192 .additionalProfiles
 *   - `aptrust:relatedOrganization` | `relatedOrganizations`
 *     | schema.org `subOrganization`                  \u2192 .relatedOrganizations
 *   - `aptrust:parentOrganization` | `parentOrganization` (schema.org)
 *                                                     \u2192 .parentOrganization
 *   - `aptrust:claimedExternalDomain` | `claimedExternalDomains`
 *                                                     \u2192 .claimedExternalDomains
 *   - `aptrust:exclusion` | `excludedDomains`         \u2192 .excludedDomains
 *   - `aptrust:reportContact` | `reportContact`       \u2192 .reportContact
 *   - `aptrust:officialMail` | `officialMail`         \u2192 .officialMail
 *   - `aptrust:trustRule` | `trustRule`               \u2192 .trustRule
 *   - `aptrust:verificationMethod` | `verificationMethod`
 *                                                     \u2192 .verificationMethod
 *   - `aptrust:aptrustVersion` | schema.org `softwareVersion` | `version`
 *                                                     \u2192 .version
 *   - `aptrust:lastUpdated` | schema.org `dateModified` | `lastUpdated`
 *                                                     \u2192 .lastUpdated
 */
export function coerceManifest(
  raw: Record<string, any>,
  _canonicalDomain?: string,
): Manifest {
  const pick = <T = unknown>(...keys: string[]): T | undefined => {
    for (const k of keys) {
      if (raw[k] !== undefined && raw[k] !== null) return raw[k] as T;
    }
    return undefined;
  };

  const officialDomains =
    pick<string[]>('aptrust:sameAsDomain', 'officialDomains') ?? [];
  const socialProfiles =
    pick<string[]>('aptrust:sameAsSocialProfile', 'socialProfiles') ?? [];

  return {
    name: String(raw.name ?? ''),
    url: String(raw.url ?? ''),
    officialDomains,
    socialProfiles,
    additionalProfiles: pick(
      'aptrust:sameAsAdditionalProfile',
      'additionalProfiles',
    ),
    relatedOrganizations: pick(
      'aptrust:relatedOrganization',
      'relatedOrganizations',
      'subOrganization',
    ),
    parentOrganization: pick('aptrust:parentOrganization', 'parentOrganization'),
    claimedExternalDomains: pick(
      'aptrust:claimedExternalDomain',
      'claimedExternalDomains',
    ),
    excludedDomains: pick('aptrust:exclusion', 'excludedDomains'),
    reportContact: pick('aptrust:reportContact', 'reportContact'),
    officialMail: pick('aptrust:officialMail', 'officialMail'),
    trustRule: pick('aptrust:trustRule', 'trustRule'),
    verificationMethod: pick(
      'aptrust:verificationMethod',
      'verificationMethod',
    ),
    version: pick('aptrust:aptrustVersion', 'softwareVersion', 'version'),
    lastUpdated: pick('aptrust:lastUpdated', 'dateModified', 'lastUpdated'),
  };
}

export function loadRules(): Rule[] {
  const value = readJsonSafe<Rule[]>(rulesPath(), []);
  if (!Array.isArray(value)) {
    throw new Error('rules.json must be an array of rule objects.');
  }
  return value;
}

export function loadAll(): AdminDataPayload {
  return {
    records: loadRecords(),
    manifests: loadManifests(),
    rules: loadRules(),
  };
}

export function saveRecords(records: RecordEntry[]): void {
  validateRecords(records);
  writeJsonAtomic(recordsPath(), records);
}

/**
 * Writes one JSON file per manifest entry, then deletes any orphaned files
 * for keys that are no longer in the map.
 */
export function saveManifests(manifests: ManifestMap): void {
  validateManifests(manifests);
  const dir = manifestsDir();
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const wantKeys = new Set(Object.keys(manifests));
  for (const [key, value] of Object.entries(manifests)) {
    writeJsonAtomic(manifestPath(key), value);
  }
  for (const name of fs.readdirSync(dir)) {
    if (!name.toLowerCase().endsWith('.json')) continue;
    const key = name.replace(/\.json$/i, '');
    if (!wantKeys.has(key)) {
      try {
        fs.unlinkSync(path.join(dir, name));
      } catch {
        /* best-effort */
      }
    }
  }
}

export function saveRules(rules: Rule[]): void {
  validateRules(rules);
  writeJsonAtomic(rulesPath(), rules);
}

export class ValidationError extends Error {
  constructor(public readonly issues: string[]) {
    super(`Validation failed: ${issues.join('; ')}`);
    this.name = 'ValidationError';
  }
}

function validateRecords(records: unknown): asserts records is RecordEntry[] {
  const issues: string[] = [];
  if (!Array.isArray(records)) {
    throw new ValidationError(['Records payload must be an array.']);
  }
  const seen = new Set<string>();
  records.forEach((r, i) => {
    if (!r || typeof r !== 'object') {
      issues.push(`records[${i}]: must be an object`);
      return;
    }
    const rec = r as Partial<RecordEntry>;
    if (!isNonEmptyString(rec.canonicalDomain)) issues.push(`records[${i}]: canonicalDomain required`);
    if (!isNonEmptyString(rec.displayName)) issues.push(`records[${i}]: displayName required`);
    if (!isNonEmptyString(rec.type)) issues.push(`records[${i}]: type required`);
    if (!isNonEmptyString(rec.manifestKey)) issues.push(`records[${i}]: manifestKey required`);
    if (rec.status !== 'active' && rec.status !== 'test' && rec.status !== 'disabled') {
      issues.push(`records[${i}]: status must be one of active|test|disabled`);
    }
    if (!Array.isArray(rec.aliases)) issues.push(`records[${i}]: aliases must be an array`);
    if (!rec.policy || typeof rec.policy !== 'object') {
      issues.push(`records[${i}]: policy required`);
    }
    if (rec.canonicalDomain) {
      const key = rec.canonicalDomain.toLowerCase();
      if (seen.has(key)) issues.push(`records[${i}]: duplicate canonicalDomain "${key}"`);
      seen.add(key);
    }
  });
  if (issues.length) throw new ValidationError(issues);
}

function validateManifests(manifests: unknown): asserts manifests is ManifestMap {
  const issues: string[] = [];
  if (!manifests || typeof manifests !== 'object' || Array.isArray(manifests)) {
    throw new ValidationError(['Manifests payload must be a JSON object.']);
  }
  for (const [key, m] of Object.entries(manifests as Record<string, unknown>)) {
    if (!m || typeof m !== 'object') {
      issues.push(`manifests["${key}"]: must be an object`);
      continue;
    }
    const man = m as Partial<Manifest>;
    if (!isNonEmptyString(man.name)) issues.push(`manifests["${key}"]: name required`);
    if (!isNonEmptyString(man.url)) issues.push(`manifests["${key}"]: url required`);
    if (!Array.isArray(man.officialDomains)) issues.push(`manifests["${key}"]: officialDomains must be an array`);
    if (!Array.isArray(man.socialProfiles)) issues.push(`manifests["${key}"]: socialProfiles must be an array`);
  }
  if (issues.length) throw new ValidationError(issues);
}

function validateRules(rules: unknown): asserts rules is Rule[] {
  const issues: string[] = [];
  if (!Array.isArray(rules)) {
    throw new ValidationError(['Rules payload must be an array.']);
  }
  const seen = new Set<string>();
  rules.forEach((r, i) => {
    if (!r || typeof r !== 'object') {
      issues.push(`rules[${i}]: must be an object`);
      return;
    }
    const rule = r as Partial<Rule>;
    if (!isNonEmptyString(rule.id)) issues.push(`rules[${i}]: id required`);
    if (!isNonEmptyString(rule.type)) issues.push(`rules[${i}]: type required`);
    if (typeof rule.enabled !== 'boolean') issues.push(`rules[${i}]: enabled must be boolean`);
    if (!isNonEmptyString(rule.scope)) issues.push(`rules[${i}]: scope required`);
    if (!isNonEmptyString(rule.effect)) issues.push(`rules[${i}]: effect required`);
    if (typeof rule.priority !== 'number') issues.push(`rules[${i}]: priority must be a number`);
    if (typeof rule.requiresBidirectionalVerification !== 'boolean') {
      issues.push(`rules[${i}]: requiresBidirectionalVerification must be boolean`);
    }
    if (rule.id) {
      if (seen.has(rule.id)) issues.push(`rules[${i}]: duplicate id "${rule.id}"`);
      seen.add(rule.id);
    }
  });
  if (issues.length) throw new ValidationError(issues);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.trim().length > 0;
}

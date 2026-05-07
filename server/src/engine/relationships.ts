/**
 * Relationship helpers used by the rule engine to evaluate bidirectional and
 * unidirectional declarations between AP Trust records.
 */

import {
  getHostFromUrl,
  hostMatches,
  isSocialHost,
  stripWww,
} from '../normalize';
import type { Manifest, ManifestMap, RecordEntry } from '../types';

export function findRecordByDomain(
  records: RecordEntry[],
  domain: string,
): RecordEntry | undefined {
  if (!domain) return undefined;
  const target = stripWww(domain.toLowerCase());
  return records.find(
    (r) => stripWww(r.canonicalDomain.toLowerCase()) === target,
  );
}

export function manifestHostsSet(manifest: Manifest | undefined): Set<string> {
  const set = new Set<string>();
  if (!manifest) return set;
  for (const u of manifest.officialDomains || []) {
    const h = getHostFromUrl(u);
    if (h) {
      set.add(h);
      set.add(stripWww(h));
    }
  }
  return set;
}

/**
 * The hosts an organization controls strongly enough that subdomain expansion
 * is appropriate \u2014 i.e. canonical + officialDomain hosts, but EXCLUDING any
 * multi-tenant social platform listed inside officialDomains. Subdomain
 * matching against an "owned" host is what makes `news.jhu.edu` resolve to
 * OFFICIAL when only `jhu.edu` is declared.
 */
export function ownedHostScope(
  canonicalDomain: string | undefined,
  manifest: Manifest | undefined,
): Set<string> {
  const set = new Set<string>();
  if (canonicalDomain) {
    const c = stripWww(canonicalDomain.toLowerCase());
    if (!isSocialHost(c)) {
      set.add(c);
    }
  }
  for (const u of manifest?.officialDomains || []) {
    const h = getHostFromUrl(u);
    if (!h) continue;
    if (isSocialHost(h)) continue;
    set.add(stripWww(h));
  }
  return set;
}

/**
 * True if `subject` (a manifest belonging to organization X) somewhere
 * declares `boundary` as a parent, related organization, or official domain.
 *
 * Used to verify that organization X reciprocally acknowledges the AP Trust
 * record whose canonicalDomain is `boundary`.
 */
export function manifestDeclaresBoundary(
  subject: Manifest | undefined,
  boundary: string,
): boolean {
  if (!subject || !boundary) return false;
  const target = stripWww(boundary.toLowerCase());

  if (subject.parentOrganization) {
    if (
      stripWww(subject.parentOrganization.canonicalDomain.toLowerCase()) ===
      target
    ) {
      return true;
    }
  }

  for (const ro of subject.relatedOrganizations || []) {
    if (stripWww(ro.canonicalDomain.toLowerCase()) === target) return true;
    for (const d of ro.domains || []) {
      const h = getHostFromUrl(d);
      if (h && hostMatches(h, boundary)) return true;
    }
  }

  for (const d of subject.officialDomains || []) {
    const h = getHostFromUrl(d);
    if (h && hostMatches(h, boundary)) return true;
  }

  return false;
}

/**
 * The full set of hosts owned by `claimed` (canonical + officialDomain hosts),
 * with social-platform hosts removed so we don't accidentally claim that the
 * boundary "owns" something like `instagram.com`.
 */
export function claimedRecordOwnedHosts(
  claimed: RecordEntry,
  claimedManifest: Manifest | undefined,
): Set<string> {
  return ownedHostScope(claimed.canonicalDomain, claimedManifest);
}

export interface UnidirectionalClaim {
  /** The org claimed by the boundary that does not reciprocate. */
  claimedRecord: RecordEntry;
  /** A representative reason string explaining the asymmetry. */
  reason: string;
  /** Hosts the claimed record actually owns (boundary, officialDomains). */
  claimedRecordHosts: Set<string>;
}

/**
 * Detect unreciprocated claims declared by `boundary`. For each known org
 * referenced by the boundary's manifest (relatedOrganizations or
 * claimedExternalDomains) that does NOT declare `boundary` back, we return a
 * claim record. Callers use this to flag suspicious URLs that point at the
 * unreciprocated org.
 */
export function findUnidirectionalClaims(
  boundary: RecordEntry,
  boundaryManifest: Manifest,
  records: RecordEntry[],
  manifests: ManifestMap,
): UnidirectionalClaim[] {
  const claims: UnidirectionalClaim[] = [];
  const seen = new Set<string>();

  const considerCandidate = (canonicalDomain: string | undefined): void => {
    if (!canonicalDomain) return;
    const key = stripWww(canonicalDomain.toLowerCase());
    if (!key || seen.has(key)) return;
    if (key === stripWww(boundary.canonicalDomain.toLowerCase())) return;
    const claimed = findRecordByDomain(records, key);
    if (!claimed) return;
    seen.add(key);
    const claimedManifest = manifests[claimed.manifestKey];
    if (manifestDeclaresBoundary(claimedManifest, boundary.canonicalDomain)) {
      return; // reciprocal \u2014 not suspicious
    }
    claims.push({
      claimedRecord: claimed,
      reason: `${boundary.canonicalDomain} claims a relationship to ${claimed.canonicalDomain}, but ${claimed.canonicalDomain} does not reciprocally declare ${boundary.canonicalDomain}.`,
      claimedRecordHosts: claimedRecordOwnedHosts(claimed, claimedManifest),
    });
  };

  for (const ro of boundaryManifest.relatedOrganizations || []) {
    considerCandidate(ro.canonicalDomain);
  }
  for (const d of boundaryManifest.claimedExternalDomains || []) {
    const h = getHostFromUrl(d);
    if (!h) continue;
    const claimed = findRecordByDomain(records, h);
    if (claimed) considerCandidate(claimed.canonicalDomain);
  }
  if (boundaryManifest.parentOrganization) {
    considerCandidate(boundaryManifest.parentOrganization.canonicalDomain);
  }

  return claims;
}

/**
 * Returns every host in the universe of the boundary's manifest that should
 * be considered "the boundary itself or one of its declared own assets".
 * This is the set we compare *against* when looking for lookalikes \u2014 we
 * never use it to admit a host as trusted on its own.
 */
export function boundaryProtectedHosts(
  boundary: RecordEntry,
  manifest: Manifest,
): string[] {
  const set = new Set<string>();
  set.add(boundary.canonicalDomain.toLowerCase());
  set.add(`www.${boundary.canonicalDomain.toLowerCase()}`);
  for (const u of manifest.officialDomains || []) {
    const h = getHostFromUrl(u);
    if (h) set.add(h);
  }
  for (const a of boundary.aliases || []) {
    if (typeof a === 'string' && a.includes('.')) {
      set.add(a.toLowerCase());
    }
  }
  return Array.from(set);
}

/**
 * Returns the union of every host declared by the boundary OR any of its
 * declared related/parent organizations. The lookalike step uses this set as
 * an allow-list so we don't misflag legitimately-related hosts (e.g. a
 * boundary's parent organization's officialDomain hosts).
 */
export function boundaryDeclaredScope(
  boundary: RecordEntry,
  manifest: Manifest,
  manifests: ManifestMap,
): Set<string> {
  const set = new Set<string>();
  for (const h of boundaryProtectedHosts(boundary, manifest)) set.add(h);

  const addCanonical = (canonical: string | undefined) => {
    if (!canonical) return;
    const c = canonical.toLowerCase();
    set.add(c);
    set.add(`www.${c}`);
    const m = manifests[canonical];
    for (const h of manifestHostsSet(m)) set.add(h);
  };

  for (const ro of manifest.relatedOrganizations || []) {
    addCanonical(ro.canonicalDomain);
    for (const d of ro.domains || []) {
      const h = getHostFromUrl(d);
      if (h) {
        set.add(h);
        set.add(stripWww(h));
      }
    }
  }
  if (manifest.parentOrganization) {
    addCanonical(manifest.parentOrganization.canonicalDomain);
  }
  return set;
}

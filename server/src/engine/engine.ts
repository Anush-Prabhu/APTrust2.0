/**
 * AP Trust Local Verification rule engine.
 *
 * Implements the priority order defined by the SRS section 5.3:
 *
 *   1.  Normalize URL and selected boundary.
 *   2.  Verify selected boundary exists in records.json.
 *   3.  Load selected boundary manifest.
 *   4.  Check whether selected boundary is disabled.
 *   4b. (APT 1.0 restored) Check the manifest's `excludedDomains` deny-list,
 *       carrying the per-entry reason into the response.
 *   5.  Check suspicious unidirectional claims (subdomain-aware).
 *   6.  Check suspicious lookalike detection (literal host AND eTLD+1).
 *   7.  Check exact boundary match (literal canonical only).
 *   8.  Check officialDomains match (with subdomain expansion).
 *   9.  Check relatedOrganizations match (with subdomain expansion).
 *   9b. (APT 1.0 restored) Check `additionalProfiles` (third-party-hosted
 *       official assets) by exact URL.
 *  10.  Check socialProfiles match (sub-path-aware, APT 1.0 parity).
 *  10b. (APT 1.0 restored) Check `officialMail` host + realmHint.
 *  11.  Check nameserver allowlist metadata if enabled.
 *  12.  Apply default deny / OUT_OF_BOUNDARY.
 *
 * Subdomain handling: most real organizations expose hundreds of subdomains
 * (`news.jhu.edu`, `apply.jhu.edu`, ...) without enumerating each in their
 * AP Trust manifest. The engine therefore treats `host` as belonging to a
 * declared owned host `parent` whenever `host === parent` OR `host` is a
 * subdomain of `parent`. Subdomain expansion is intentionally suppressed for
 * known multi-tenant social-platform hosts; on those, only an exact path
 * match against `socialProfiles` ever counts as trusted.
 *
 * Bidirectional acceptance: when a record declares
 * `policy.acceptWithinBoundary = 'bidirectional'` (the default), a host
 * that resolves to a related/parent organization is admitted as RELATED
 * only if the counterparty's manifest reciprocally declares this boundary.
 * The engine has always done this via `manifestDeclaresBoundary`; the
 * policy field exists so the data carries the semantics explicitly. A
 * record may also declare `policy.trustRootCanonical` (e.g. `jhu.edu` for
 * `jhmi.edu` and `hopkinsmedicine.org`); this is documentation only and
 * does NOT change the verdict, but is surfaced in `/manifest/:domain` so
 * the popup can label the relationship for the operator.
 *
 * Drift advisories: every verdict is post-processed by
 * `attachDriftWarnings` which appends non-blocking `warnings[]` whenever
 * the (boundary, counterparty) pair has an unreciprocated edge in the
 * cross-manifest relationship graph (see `engine/explanations.ts`).
 */

import {
  additionalProfileEquals,
  findHostScopeMatch,
  getHostFromUrl,
  hostMatches,
  isSocialHost,
  isSubdomainOf,
  normalizeUrl,
  registeredDomain,
  socialProfileEquals,
  socialProfileMatchesPath,
  stripWww,
} from '../normalize';
import type {
  Manifest,
  ManifestMap,
  RecordEntry,
  Relationship,
  Rule,
  Status,
  VerifyRequest,
  VerifyResult,
} from '../types';
import { detectLookalike } from './lookalike';
import {
  explainUnidirectionalClaim,
  findManifestDrift,
  findingsForPair,
} from './explanations';
import {
  boundaryDeclaredScope,
  boundaryProtectedHosts,
  findRecordByDomain,
  findUnidirectionalClaims,
  manifestDeclaresBoundary,
  manifestHostsSet,
  ownedHostScope,
} from './relationships';

export interface EngineContext {
  records: RecordEntry[];
  manifests: ManifestMap;
  rules: Rule[];
}

export const STATUS_CODE = {
  EXACT_BOUNDARY: 95,
  OFFICIAL_DOMAIN: 90,
  BIDIRECTIONAL_RELATED: 85,
  SOCIAL_PROFILE: 80,
  RELATED_UNIDIRECTIONAL: 65,
  RELATED_CANDIDATE: 55,
  OUT_OF_BOUNDARY: 35,
  SUSPICIOUS_LOOKALIKE: 15,
  SUSPICIOUS_UNIDIRECTIONAL_CLAIM: 10,
  EXCLUDED: 5,
  INVALID_OR_DISABLED: 0,
} as const;

function ruleEnabled(rules: Rule[], type: string): boolean {
  const r = rules.find((rule) => rule.type === type);
  return !!r && r.enabled !== false;
}

function nameserverRulesForBoundary(rules: Rule[], boundary: string): Rule[] {
  return rules.filter(
    (r) =>
      r.type === 'NAMESERVER_ALLOWLIST' &&
      r.enabled === true &&
      (r.scope === 'global' || r.scope === boundary),
  );
}

/**
 * Normalize a manifest's `excludedDomains` array into a list of
 * `{ host, reason }` records. Accepts both the v1 shape `{domain, reason}`
 * and bare URL/host strings.
 */
function excludedEntries(
  manifest: Manifest | undefined,
): Array<{ host: string; reason: string }> {
  const out: Array<{ host: string; reason: string }> = [];
  for (const entry of manifest?.excludedDomains || []) {
    if (typeof entry === 'string') {
      const h =
        getHostFromUrl(entry) || stripWww(String(entry).toLowerCase());
      if (h && h.includes('.')) out.push({ host: h, reason: '' });
      continue;
    }
    if (entry && typeof entry === 'object' && entry.domain) {
      const h =
        getHostFromUrl(entry.domain) ||
        stripWww(String(entry.domain).toLowerCase());
      if (h && h.includes('.')) {
        out.push({ host: h, reason: entry.reason || '' });
      }
    }
  }
  return out;
}

/** Materialize the additional-profile URL list (handles both string and {url} shapes). */
function additionalProfileUrls(manifest: Manifest | undefined): string[] {
  const out: string[] = [];
  for (const entry of manifest?.additionalProfiles || []) {
    if (typeof entry === 'string') {
      out.push(entry);
    } else if (entry && typeof entry === 'object' && entry.url) {
      out.push(entry.url);
    }
  }
  return out;
}

export function verifyUrl(
  req: VerifyRequest,
  ctx: EngineContext,
): VerifyResult {
  const result = verifyUrlInner(req, ctx);
  return attachDriftWarnings(result, ctx);
}

function verifyUrlInner(
  req: VerifyRequest,
  ctx: EngineContext,
): VerifyResult {
  const boundaryInput = String(req?.boundary ?? '').trim();
  const urlInput = String(req?.url ?? '').trim();

  // Step 1: normalize.
  const norm = normalizeUrl(urlInput);
  if (!norm.ok) {
    return {
      boundary: boundaryInput,
      url: urlInput,
      normalizedDomain: '',
      status: 'UNKNOWN',
      statusCode: STATUS_CODE.INVALID_OR_DISABLED,
      relationship: 'NO_RELATIONSHIP_FOUND',
      reasons: [`The URL could not be parsed (${norm.reason || 'invalid URL'}).`],
    };
  }
  const targetHost = norm.host!;
  const targetCompareHost = stripWww(targetHost);

  // Step 2: boundary record exists?
  const boundary = findRecordByDomain(ctx.records, boundaryInput);
  if (!boundary) {
    return {
      boundary: boundaryInput,
      url: urlInput,
      normalizedDomain: targetHost,
      status: 'UNKNOWN',
      statusCode: STATUS_CODE.INVALID_OR_DISABLED,
      relationship: 'NO_RELATIONSHIP_FOUND',
      reasons: [
        `The selected trust boundary "${boundaryInput}" was not found in the local AP Trust records.`,
      ],
    };
  }

  // Step 3: load manifest.
  const boundaryManifest = ctx.manifests[boundary.manifestKey];
  if (!boundaryManifest) {
    return {
      boundary: boundary.canonicalDomain,
      url: urlInput,
      normalizedDomain: targetHost,
      status: 'UNKNOWN',
      statusCode: STATUS_CODE.INVALID_OR_DISABLED,
      relationship: 'NO_RELATIONSHIP_FOUND',
      reasons: [
        `The local AP Trust manifest for "${boundary.canonicalDomain}" is missing.`,
      ],
    };
  }

  // Step 4: disabled boundary.
  if (boundary.status === 'disabled') {
    return {
      boundary: boundary.canonicalDomain,
      url: urlInput,
      normalizedDomain: targetHost,
      status: 'DISABLED_BOUNDARY',
      statusCode: STATUS_CODE.INVALID_OR_DISABLED,
      relationship: 'NO_RELATIONSHIP_FOUND',
      reasons: [
        `The trust boundary "${boundary.canonicalDomain}" is disabled and cannot be used for verification.`,
      ],
    };
  }

  // Step 4b: explicit deny-list (APT 1.0 excludedDomains, restored).
  const excluded = excludedEntries(boundaryManifest);
  if (excluded.length > 0) {
    const hostsToReason = new Map<string, string>();
    for (const e of excluded) hostsToReason.set(e.host, e.reason);
    const match = findHostScopeMatch(targetHost, hostsToReason.keys());
    if (match) {
      const reason = hostsToReason.get(match.matched) || '';
      const reasons: string[] = [
        match.subdomain
          ? `Host "${targetHost}" is a subdomain of "${match.matched}", which is on the explicit excludedDomains list of ${boundary.canonicalDomain}.`
          : `Host "${targetHost}" is on the explicit excludedDomains list of ${boundary.canonicalDomain}.`,
      ];
      if (reason) reasons.push(`Reason: ${reason}`);
      reasons.push('Explicit deny-list entries always override allow-list rules.');
      return {
        boundary: boundary.canonicalDomain,
        url: urlInput,
        normalizedDomain: targetHost,
        status: 'EXCLUDED',
        statusCode: STATUS_CODE.EXCLUDED,
        relationship: 'NO_RELATIONSHIP_FOUND',
        reasons,
      };
    }
  }

  // Step 5: suspicious unidirectional claim detection.
  if (ruleEnabled(ctx.rules, 'UNIDIRECTIONAL_CLAIM_DETECTION')) {
    const claims = findUnidirectionalClaims(
      boundary,
      boundaryManifest,
      ctx.records,
      ctx.manifests,
    );
    for (const claim of claims) {
      const matchesClaimedRecord =
        hostMatches(targetHost, claim.claimedRecord.canonicalDomain) ||
        isSubdomainOf(targetHost, claim.claimedRecord.canonicalDomain) ||
        !!findHostScopeMatch(targetHost, claim.claimedRecordHosts);
      if (matchesClaimedRecord) {
        const claimedManifest = ctx.manifests[claim.claimedRecord.manifestKey];
        return {
          boundary: boundary.canonicalDomain,
          url: urlInput,
          normalizedDomain: targetHost,
          status: 'SUSPICIOUS_UNIDIRECTIONAL_CLAIM',
          statusCode: STATUS_CODE.SUSPICIOUS_UNIDIRECTIONAL_CLAIM,
          relationship: 'UNIDIRECTIONAL_CLAIM',
          reasons: explainUnidirectionalClaim({
            boundary,
            boundaryManifest,
            claimedRecord: claim.claimedRecord,
            claimedManifest,
            records: ctx.records,
          }),
        };
      }
    }
  }

  // Step 6: suspicious lookalike detection.
  if (ruleEnabled(ctx.rules, 'LOOKALIKE_DETECTION')) {
    const protectedHosts = boundaryProtectedHosts(boundary, boundaryManifest);
    const declaredScope = boundaryDeclaredScope(
      boundary,
      boundaryManifest,
      ctx.manifests,
    );
    const declaredScopeMatch = findHostScopeMatch(targetHost, declaredScope);
    const isDeclared =
      declaredScope.has(targetHost) ||
      declaredScope.has(targetCompareHost) ||
      hostMatches(targetHost, boundary.canonicalDomain) ||
      // A subdomain of any declared owned host is, by construction, NOT a
      // lookalike of the boundary.
      (declaredScopeMatch !== null);
    if (!isDeclared) {
      // The lookalike heuristic compares both the literal host AND the
      // best-effort registered domain (eTLD+1). This catches `news.jhuu.edu`
      // (registered `jhuu.edu`, distance 1 from `jhu.edu`) which the literal
      // host check would otherwise miss.
      const finding = detectLookalike(targetHost, {
        protectedHosts,
        registeredDomain: registeredDomain(targetHost),
      });
      if (finding.isLookalike) {
        return {
          boundary: boundary.canonicalDomain,
          url: urlInput,
          normalizedDomain: targetHost,
          status: 'SUSPICIOUS_LOOKALIKE',
          statusCode: STATUS_CODE.SUSPICIOUS_LOOKALIKE,
          relationship: 'LOOKALIKE_DETECTED',
          reasons: [
            ...finding.reasons,
            `Lookalike domains are not declared by ${boundary.canonicalDomain} and may be used for impersonation.`,
          ],
        };
      }
    }
  }

  // Step 7: exact boundary match.
  //
  // Only the literal canonical host counts as SELF_VERIFIED. www-variants and
  // alternate-spelling boundaries (e.g. `johnshopkins.edu`) flow through to
  // Step 8 (OFFICIAL_DOMAIN). Subdomain expansion is also handled in Step 8
  // via `ownedHostScope`, which seeds the canonical host.
  if (
    ruleEnabled(ctx.rules, 'DOMAIN_EXACT') &&
    targetHost === boundary.canonicalDomain.toLowerCase()
  ) {
    return {
      boundary: boundary.canonicalDomain,
      url: urlInput,
      normalizedDomain: targetHost,
      status: 'OFFICIAL',
      statusCode: STATUS_CODE.EXACT_BOUNDARY,
      relationship: 'SELF_VERIFIED',
      reasons: [
        `The URL host "${targetHost}" exactly matches the selected trust boundary.`,
      ],
    };
  }

  // Step 8: officialDomains match (with subdomain expansion).
  if (ruleEnabled(ctx.rules, 'OFFICIAL_DOMAIN')) {
    const ownedHosts = ownedHostScope(boundary.canonicalDomain, boundaryManifest);
    const exactOfficialHostSet = manifestHostsSet(boundaryManifest);
    const match = findHostScopeMatch(targetHost, ownedHosts);
    if (match) {
      return {
        boundary: boundary.canonicalDomain,
        url: urlInput,
        normalizedDomain: targetHost,
        status: 'OFFICIAL',
        statusCode: STATUS_CODE.OFFICIAL_DOMAIN,
        relationship: 'OFFICIAL_DOMAIN_DECLARED',
        reasons: [
          match.subdomain
            ? `The URL host "${targetHost}" is a subdomain of "${match.matched}", an officialDomain of ${boundary.canonicalDomain}.`
            : `The URL host "${targetHost}" is listed in the officialDomains of ${boundary.canonicalDomain}.`,
        ],
      };
    }
    // Defensive: if a social host happens to be in officialDomains, allow the
    // exact-host match through (rule SOCIAL_PROFILE_EXACT will refine path).
    if (
      exactOfficialHostSet.has(targetHost) ||
      exactOfficialHostSet.has(targetCompareHost)
    ) {
      // Intentionally let step 10 handle the path-level decision instead of
      // claiming the whole multi-tenant host as official.
    }
  }

  // Step 9: relatedOrganizations match (and parentOrganization treated similarly).
  if (ruleEnabled(ctx.rules, 'RELATED_ORGANIZATION')) {
    const related = matchRelatedOrganization(
      boundary,
      boundaryManifest,
      targetHost,
      urlInput,
      ctx,
    );
    if (related) return related;
  }

  // Step 9b: additionalProfiles (third-party-hosted official assets).
  // Restored from APT 1.0. Exact-URL match (query/fragment dropped).
  for (const declared of additionalProfileUrls(boundaryManifest)) {
    if (additionalProfileEquals(declared, urlInput)) {
      return {
        boundary: boundary.canonicalDomain,
        url: urlInput,
        normalizedDomain: targetHost,
        status: 'OFFICIAL',
        statusCode: STATUS_CODE.OFFICIAL_DOMAIN,
        relationship: 'ADDITIONAL_PROFILE_DECLARED',
        reasons: [
          `The URL exactly matches "${declared}", an additionalProfile declared by ${boundary.canonicalDomain}.`,
          'additionalProfiles cover official assets the org hosts on third-party platforms (employment vendors, donation/giving platforms, learning systems, ...).',
        ],
      };
    }
  }

  // Step 10: socialProfiles match.
  // Sub-path-aware (APT 1.0): a declared profile URL also matches any
  // sub-path under it (e.g. /tagged, /status/<id>) at a path-segment
  // boundary. socialProfileEquals stays as a fast pre-check.
  if (ruleEnabled(ctx.rules, 'SOCIAL_PROFILE_EXACT')) {
    for (const profile of boundaryManifest.socialProfiles || []) {
      const exact = socialProfileEquals(profile, urlInput);
      const subpath = !exact && socialProfileMatchesPath(urlInput, profile);
      if (exact || subpath) {
        return {
          boundary: boundary.canonicalDomain,
          url: urlInput,
          normalizedDomain: targetHost,
          status: 'SOCIAL_VERIFIED',
          statusCode: STATUS_CODE.SOCIAL_PROFILE,
          relationship: 'SOCIAL_PROFILE_DECLARED',
          reasons: [
            exact
              ? `The URL exactly matches a social profile declared by ${boundary.canonicalDomain}.`
              : `The URL is a sub-path of a social profile declared by ${boundary.canonicalDomain} ("${profile}").`,
          ],
        };
      }
    }
  }

  // Step 10b: officialMail. APT 1.0 declared an org's webmail tenant so the
  // engine can confirm a tenant URL with the right `realmHint` (e.g. shared
  // Outlook with `realm=jh.edu`). Host alone is not enough \u2014 if the manifest
  // declares a `realmHint` we require the URL to contain it.
  const om = boundaryManifest.officialMail;
  if (om && om.host && hostMatches(targetHost, om.host)) {
    const lowered = urlInput.toLowerCase();
    const hint = (om.realmHint || '').toLowerCase();
    if (!hint || lowered.includes(hint)) {
      return {
        boundary: boundary.canonicalDomain,
        url: urlInput,
        normalizedDomain: targetHost,
        status: 'OFFICIAL',
        statusCode: STATUS_CODE.OFFICIAL_DOMAIN,
        relationship: 'OFFICIAL_MAIL_DECLARED',
        reasons: [
          `Host "${targetHost}" matches the officialMail tenant declared by ${boundary.canonicalDomain} (provider: ${om.provider}).`,
          hint ? `Realm fragment "${om.realmHint}" was found in the URL.` : '',
        ].filter(Boolean),
      };
    }
    // Host matched but the realm hint did not \u2014 fall through so the page
    // either resolves OUT_OF_BOUNDARY (and the extension softens it to
    // MAIL_CLIENT for the page-level case) or matches some other rule.
  }

  // Step 11: nameserver allowlist (metadata only, never OFFICIAL).
  const nsRules = nameserverRulesForBoundary(ctx.rules, boundary.canonicalDomain);
  if (nsRules.length > 0) {
    // No live NS lookup. The POC keeps this purely as metadata; any match
    // would have to be wired up through additional local data. We surface
    // RELATED_CANDIDATE only if a future implementation adds that wiring.
    // Today this branch never activates against the seed data, which is the
    // intended SRS behavior (FR-RULE-009).
  }

  // Step 12: default deny.
  return {
    boundary: boundary.canonicalDomain,
    url: urlInput,
    normalizedDomain: targetHost,
    status: 'OUT_OF_BOUNDARY',
    statusCode: STATUS_CODE.OUT_OF_BOUNDARY,
    relationship: 'NO_RELATIONSHIP_FOUND',
    reasons: [
      `${targetHost} is not declared inside the trust boundary of ${boundary.canonicalDomain}.`,
      `Default policy is DENY for unknown domains.`,
    ],
  };
}

function matchRelatedOrganization(
  boundary: RecordEntry,
  boundaryManifest: Manifest,
  targetHost: string,
  urlInput: string,
  ctx: EngineContext,
): VerifyResult | null {
  // 9a) parentOrganization linkage.
  if (boundaryManifest.parentOrganization) {
    const parent = boundaryManifest.parentOrganization;
    const parentManifest = ctx.manifests[parent.canonicalDomain];
    const parentScope = ownedHostScope(parent.canonicalDomain, parentManifest);
    const match = findHostScopeMatch(targetHost, parentScope);
    if (match) {
      const reciprocal = manifestDeclaresBoundary(
        parentManifest,
        boundary.canonicalDomain,
      );
      const relationship: Relationship = reciprocal
        ? 'BIDIRECTIONAL_VERIFIED'
        : 'PARENT_CHILD_DECLARED';
      const status: Status = 'RELATED';
      const statusCode = reciprocal
        ? STATUS_CODE.BIDIRECTIONAL_RELATED
        : STATUS_CODE.RELATED_UNIDIRECTIONAL;
      return {
        boundary: boundary.canonicalDomain,
        url: urlInput,
        normalizedDomain: targetHost,
        status,
        statusCode,
        relationship,
        reasons: buildRelatedReasons({
          boundary: boundary.canonicalDomain,
          relatedDomain: parent.canonicalDomain,
          relatedName: parent.name,
          mode: 'parent',
          reciprocal,
          subdomainMatch: match.subdomain ? match.matched : null,
          targetHost,
        }),
      };
    }
  }

  // 9b) declared related organizations.
  for (const ro of boundaryManifest.relatedOrganizations || []) {
    const candidateHosts = new Set<string>();
    candidateHosts.add(stripWww(ro.canonicalDomain.toLowerCase()));
    for (const d of ro.domains || []) {
      const h = getHostFromUrl(d);
      if (h && !isSocialHost(h)) candidateHosts.add(stripWww(h));
    }
    // Also pull in the related org's own officialDomains (when known).
    const relatedManifest = ctx.manifests[ro.canonicalDomain];
    for (const h of ownedHostScope(ro.canonicalDomain, relatedManifest)) {
      candidateHosts.add(h);
    }

    const match = findHostScopeMatch(targetHost, candidateHosts);
    if (match) {
      const reciprocal = manifestDeclaresBoundary(
        relatedManifest,
        boundary.canonicalDomain,
      );
      const relationship: Relationship = reciprocal
        ? 'BIDIRECTIONAL_VERIFIED'
        : 'UNIDIRECTIONAL_CLAIM';
      const statusCode = reciprocal
        ? STATUS_CODE.BIDIRECTIONAL_RELATED
        : STATUS_CODE.RELATED_UNIDIRECTIONAL;
      return {
        boundary: boundary.canonicalDomain,
        url: urlInput,
        normalizedDomain: targetHost,
        status: 'RELATED',
        statusCode,
        relationship,
        reasons: buildRelatedReasons({
          boundary: boundary.canonicalDomain,
          relatedDomain: ro.canonicalDomain,
          relatedName: ro.name,
          mode: 'related',
          reciprocal,
          subdomainMatch: match.subdomain ? match.matched : null,
          targetHost,
        }),
      };
    }
  }

  return null;
}

function buildRelatedReasons(args: {
  boundary: string;
  relatedDomain: string;
  relatedName: string;
  mode: 'related' | 'parent';
  reciprocal: boolean;
  subdomainMatch: string | null;
  targetHost: string;
}): string[] {
  const reasons: string[] = [];
  if (args.mode === 'related') {
    reasons.push(
      `${args.boundary} declares ${args.relatedName} (${args.relatedDomain}) as a related organization.`,
    );
  } else {
    reasons.push(
      `${args.boundary} declares ${args.relatedName} (${args.relatedDomain}) as its parent organization.`,
    );
  }
  if (args.subdomainMatch) {
    reasons.push(
      `Host "${args.targetHost}" is a subdomain of "${args.subdomainMatch}", which is owned by ${args.relatedDomain}.`,
    );
  }
  if (args.reciprocal) {
    reasons.push(
      `${args.relatedDomain} reciprocally declares ${args.boundary} in its AP Trust manifest.`,
    );
    reasons.push('The relationship is bidirectionally verified.');
  } else {
    reasons.push(
      `${args.relatedDomain} does not reciprocally declare ${args.boundary}; the relationship is one-directional.`,
    );
  }
  return reasons;
}

/**
 * Attach pairwise relationship-graph drift advisories to the verdict.
 *
 * Drift findings are computed across ALL loaded manifests once, then
 * filtered to the (boundary, counterparty) pair for the verified URL. The
 * counterparty is resolved by mapping the URL's host or its registered
 * domain back to a known record. Drift never changes the verdict's status
 * \u2014 it only adds informational `warnings[]`.
 */
function attachDriftWarnings(
  result: VerifyResult,
  ctx: EngineContext,
): VerifyResult {
  if (!result.normalizedDomain || !result.boundary) return result;
  const counterparty = resolveCounterpartyRecord(
    result.normalizedDomain,
    ctx.records,
  );
  if (!counterparty) return result;
  if (
    stripWww(counterparty.canonicalDomain.toLowerCase()) ===
    stripWww(result.boundary.toLowerCase())
  ) {
    return result;
  }
  const findings = findManifestDrift(ctx.records, ctx.manifests);
  const pair = findingsForPair(
    findings,
    result.boundary,
    counterparty.canonicalDomain,
  );
  if (pair.length === 0) return result;
  const warnings = pair.map((f) => ({
    kind: 'manifest_drift' as const,
    detail: f.detail,
    data: f,
  }));
  return { ...result, warnings };
}

function resolveCounterpartyRecord(
  host: string,
  records: RecordEntry[],
): RecordEntry | undefined {
  const direct = findRecordByDomain(records, host);
  if (direct) return direct;
  // Walk parent labels; e.g. news.hopkinsmedicine.org \u2192 hopkinsmedicine.org.
  const labels = stripWww(host).split('.');
  for (let i = 1; i < labels.length - 1; i++) {
    const parent = labels.slice(i).join('.');
    const r = findRecordByDomain(records, parent);
    if (r) return r;
  }
  return undefined;
}

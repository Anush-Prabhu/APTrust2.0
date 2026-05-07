/**
 * Dynamic explanations and cross-manifest consistency checks.
 *
 * The functions in this module build human-readable, manifest-derived
 * reasons rather than emitting hard-coded strings. That is what makes the
 * engine's verdicts dynamic when an operator authors a new (possibly
 * malicious) manifest: the messages always reflect what the manifest
 * actually says and what was searched on the counterparty's manifest, not
 * a frozen template.
 *
 * Two related capabilities live here:
 *
 *   1. {@link explainUnidirectionalClaim} \u2014 used by the rule engine when
 *      Step 5 (`SUSPICIOUS_UNIDIRECTIONAL_CLAIM`) fires. It walks the
 *      boundary's manifest to find which field claimed the relationship
 *      (parentOrganization / relatedOrganizations / claimedExternalDomains)
 *      and walks the counterparty's manifest to enumerate the fields that
 *      were checked for reciprocation. The returned `reasons[]` therefore
 *      explain the EXACT claim path and the EXACT scan that found nothing.
 *
 *   2. {@link findManifestDrift} + {@link explainPairwiseConsistency} \u2014
 *      pairwise relationship-graph drift. For each `relatedOrganizations`
 *      edge from manifest A to record B, we require B's manifest to declare
 *      A back. Findings are surfaced via `GET /admin/manifest-consistency`
 *      and (optionally) appended to /verify when the verified URL's org
 *      pair matches a finding.
 *
 * Phase 2 (asset-inventory drift) is intentionally NOT implemented here;
 * see the plan for the gating policy when it lands.
 */

import {
  getHostFromUrl,
  hostMatches,
  stripWww,
} from '../normalize';
import type {
  Manifest,
  ManifestMap,
  ParentOrganization,
  RecordEntry,
  RelatedOrganization,
} from '../types';
import { findRecordByDomain, manifestDeclaresBoundary } from './relationships';

// ---------------------------------------------------------------------------
// Claim paths \u2014 where in a manifest a relationship was declared.
// ---------------------------------------------------------------------------

/**
 * A pointer to the exact field/value in a manifest that asserts a
 * relationship to another organization.
 */
export type ClaimPath =
  | {
      kind: 'parentOrganization';
      claimedCanonical: string;
      claimedName?: string;
    }
  | {
      kind: 'relatedOrganizations';
      claimedCanonical: string;
      claimedName?: string;
      domains: string[];
    }
  | {
      kind: 'claimedExternalDomains';
      url: string;
      resolvedCanonical: string;
    };

/**
 * Enumerate every manifest field on `subjectManifest` that asserts a
 * relationship to a known AP Trust record. Used both for unidirectional
 * claim explanation and for pairwise drift detection.
 */
export function collectClaimPaths(
  subjectManifest: Manifest,
  records: RecordEntry[],
): ClaimPath[] {
  const out: ClaimPath[] = [];
  if (subjectManifest.parentOrganization) {
    const p: ParentOrganization = subjectManifest.parentOrganization;
    out.push({
      kind: 'parentOrganization',
      claimedCanonical: p.canonicalDomain,
      claimedName: p.name,
    });
  }
  for (const ro of subjectManifest.relatedOrganizations || []) {
    const r: RelatedOrganization = ro;
    out.push({
      kind: 'relatedOrganizations',
      claimedCanonical: r.canonicalDomain,
      claimedName: r.name,
      domains: Array.isArray(r.domains) ? [...r.domains] : [],
    });
  }
  for (const url of subjectManifest.claimedExternalDomains || []) {
    const h = getHostFromUrl(url) || stripWww(String(url || '').toLowerCase());
    if (!h) continue;
    const rec = findRecordByDomain(records, h);
    if (!rec) continue;
    out.push({
      kind: 'claimedExternalDomains',
      url,
      resolvedCanonical: rec.canonicalDomain,
    });
  }
  return out;
}

/**
 * The fields that {@link manifestDeclaresBoundary} checks on the
 * counterparty's manifest. Returning these as concrete labels lets the
 * engine explain WHAT was searched even when the result is "nothing
 * matched" \u2014 so adding a custom malicious manifest still produces a
 * descriptive verdict.
 */
export interface ReciprocationSearch {
  parentChecked: boolean;
  parentCanonical?: string;
  parentMatched: boolean;
  relatedOrganizationsChecked: number;
  relatedOrganizationCandidates: string[];
  relatedOrganizationMatched: boolean;
  officialDomainsChecked: number;
  officialDomainsCandidates: string[];
  officialDomainsMatched: boolean;
  /** True if any of the three sub-checks above resolved positively. */
  reciprocated: boolean;
}

export function searchReciprocation(
  counterpartyManifest: Manifest | undefined,
  boundaryCanonical: string,
): ReciprocationSearch {
  const out: ReciprocationSearch = {
    parentChecked: false,
    parentMatched: false,
    relatedOrganizationsChecked: 0,
    relatedOrganizationCandidates: [],
    relatedOrganizationMatched: false,
    officialDomainsChecked: 0,
    officialDomainsCandidates: [],
    officialDomainsMatched: false,
    reciprocated: false,
  };
  if (!counterpartyManifest) return out;
  const target = stripWww(boundaryCanonical.toLowerCase());

  if (counterpartyManifest.parentOrganization) {
    out.parentChecked = true;
    out.parentCanonical = counterpartyManifest.parentOrganization.canonicalDomain;
    if (
      stripWww(out.parentCanonical.toLowerCase()) === target
    ) {
      out.parentMatched = true;
    }
  }

  for (const ro of counterpartyManifest.relatedOrganizations || []) {
    out.relatedOrganizationsChecked += 1;
    out.relatedOrganizationCandidates.push(ro.canonicalDomain);
    if (stripWww(ro.canonicalDomain.toLowerCase()) === target) {
      out.relatedOrganizationMatched = true;
    } else {
      for (const d of ro.domains || []) {
        const h = getHostFromUrl(d);
        if (h && hostMatches(h, boundaryCanonical)) {
          out.relatedOrganizationMatched = true;
          break;
        }
      }
    }
  }

  for (const d of counterpartyManifest.officialDomains || []) {
    out.officialDomainsChecked += 1;
    const h = getHostFromUrl(d);
    if (h) {
      out.officialDomainsCandidates.push(h);
      if (hostMatches(h, boundaryCanonical)) {
        out.officialDomainsMatched = true;
      }
    }
  }

  out.reciprocated =
    out.parentMatched ||
    out.relatedOrganizationMatched ||
    out.officialDomainsMatched;
  return out;
}

// ---------------------------------------------------------------------------
// Unidirectional-claim explanations.
// ---------------------------------------------------------------------------

/**
 * Build dynamic `reasons[]` for a `SUSPICIOUS_UNIDIRECTIONAL_CLAIM` verdict.
 *
 * The output is derived from the actual manifests at evaluation time:
 *
 *   - Lists every manifest field on the BOUNDARY where it claims a
 *     relationship to the counterparty (parentOrganization,
 *     relatedOrganizations, claimedExternalDomains). Each field is
 *     enumerated literally so a custom malicious manifest is fully
 *     explained.
 *   - Lists what was searched on the COUNTERPARTY's manifest
 *     (parentOrganization, relatedOrganizations[], officialDomains[]) and
 *     reports that none of those entries pointed back at the boundary.
 *   - Closes with the policy statement that self-attestation alone is not
 *     sufficient.
 *
 * Falls back to a short generic message when the boundary's manifest is
 * missing or empty (defensive only \u2014 the engine never calls this with a
 * missing manifest).
 */
export function explainUnidirectionalClaim(args: {
  boundary: RecordEntry;
  boundaryManifest: Manifest;
  claimedRecord: RecordEntry;
  claimedManifest: Manifest | undefined;
  records: RecordEntry[];
}): string[] {
  const {
    boundary,
    boundaryManifest,
    claimedRecord,
    claimedManifest,
  } = args;

  const claimPaths = collectClaimPaths(boundaryManifest, args.records).filter(
    (cp) => {
      const c =
        cp.kind === 'claimedExternalDomains'
          ? cp.resolvedCanonical
          : cp.claimedCanonical;
      return (
        stripWww((c || '').toLowerCase()) ===
        stripWww(claimedRecord.canonicalDomain.toLowerCase())
      );
    },
  );

  const reasons: string[] = [];
  reasons.push(
    `${boundary.canonicalDomain} claims a relationship to ${claimedRecord.canonicalDomain}.`,
  );

  if (claimPaths.length === 0) {
    // Defensive: the engine only invokes us when a claim was found, but if
    // an operator called this directly with a manifest that no longer
    // declares the claim we still produce a coherent message.
    reasons.push(
      `No declared field on ${boundary.canonicalDomain}'s manifest was found pointing at ${claimedRecord.canonicalDomain}.`,
    );
  } else {
    for (const cp of claimPaths) {
      reasons.push(claimPathToReason(cp, boundary.canonicalDomain));
    }
  }

  const search = searchReciprocation(
    claimedManifest,
    boundary.canonicalDomain,
  );

  if (!claimedManifest) {
    reasons.push(
      `${claimedRecord.canonicalDomain} does NOT have a local AP Trust manifest at all, so the claim cannot be reciprocated.`,
    );
  } else {
    reasons.push(
      `Searched ${claimedRecord.canonicalDomain}'s manifest for a reciprocal declaration of ${boundary.canonicalDomain}:`,
    );
    reasons.push(
      `  \u2022 parentOrganization: ${
        search.parentChecked
          ? `present (\"${search.parentCanonical}\") \u2014 does NOT point at ${boundary.canonicalDomain}.`
          : 'not declared.'
      }`,
    );
    reasons.push(
      `  \u2022 relatedOrganizations: ${
        search.relatedOrganizationsChecked === 0
          ? 'no entries declared.'
          : `${search.relatedOrganizationsChecked} entr${
              search.relatedOrganizationsChecked === 1 ? 'y' : 'ies'
            } scanned (${search.relatedOrganizationCandidates.join(', ')}); none points at ${boundary.canonicalDomain}.`
      }`,
    );
    reasons.push(
      `  \u2022 officialDomains: ${
        search.officialDomainsChecked === 0
          ? 'no entries declared.'
          : `${search.officialDomainsChecked} entr${
              search.officialDomainsChecked === 1 ? 'y' : 'ies'
            } scanned; none equals or contains ${boundary.canonicalDomain}.`
      }`,
    );
  }

  reasons.push(
    `Self-attestation alone is not sufficient \u2014 the claim is treated as suspicious until ${claimedRecord.canonicalDomain} reciprocally declares ${boundary.canonicalDomain}.`,
  );

  return reasons;
}

function claimPathToReason(cp: ClaimPath, boundary: string): string {
  switch (cp.kind) {
    case 'parentOrganization':
      return `  \u2022 parentOrganization on ${boundary} = ${
        cp.claimedName ? `"${cp.claimedName}" (${cp.claimedCanonical})` : cp.claimedCanonical
      }.`;
    case 'relatedOrganizations': {
      const tail = cp.domains.length
        ? `; domains: ${cp.domains.slice(0, 4).join(', ')}${
            cp.domains.length > 4 ? ', ...' : ''
          }`
        : '';
      return `  \u2022 relatedOrganizations on ${boundary} contains ${
        cp.claimedName ? `"${cp.claimedName}" (${cp.claimedCanonical})` : cp.claimedCanonical
      }${tail}.`;
    }
    case 'claimedExternalDomains':
      return `  \u2022 claimedExternalDomains on ${boundary} contains "${cp.url}" (resolves to record ${cp.resolvedCanonical}).`;
  }
}

// ---------------------------------------------------------------------------
// Pairwise relationship-graph drift.
// ---------------------------------------------------------------------------

export type DriftKind =
  | 'unreciprocated_related'
  | 'unreciprocated_parent'
  | 'unreciprocated_claimed_external'
  | 'unknown_record';

export interface DriftFinding {
  kind: DriftKind;
  /** Manifest making the assertion. */
  from: string;
  /** Counterparty (canonical) the assertion targets. */
  to: string;
  /** Manifest field where the assertion was authored. */
  field: 'parentOrganization' | 'relatedOrganizations' | 'claimedExternalDomains';
  /** Short, human-readable detail describing the drift. */
  detail: string;
}

/**
 * Detect every relationship-graph drift between every pair of loaded
 * manifests. A "drift" today means: A asserts a relationship to B, but B's
 * manifest does not declare A back through any of the recognised fields.
 *
 * `unknown_record` is reported when A asserts a relationship to a canonical
 * domain that does not exist in records.json at all (we cannot enforce
 * reciprocation on something we cannot resolve).
 */
export function findManifestDrift(
  records: RecordEntry[],
  manifests: ManifestMap,
): DriftFinding[] {
  const findings: DriftFinding[] = [];

  for (const fromRecord of records) {
    const fromManifest = manifests[fromRecord.manifestKey];
    if (!fromManifest) continue;

    const claims = collectClaimPaths(fromManifest, records);
    for (const cp of claims) {
      const targetCanonical =
        cp.kind === 'claimedExternalDomains'
          ? cp.resolvedCanonical
          : cp.claimedCanonical;
      if (!targetCanonical) continue;
      if (
        stripWww(targetCanonical.toLowerCase()) ===
        stripWww(fromRecord.canonicalDomain.toLowerCase())
      ) {
        continue; // self-reference; ignore
      }
      const counterparty = findRecordByDomain(records, targetCanonical);
      const field = claimPathField(cp);

      if (!counterparty) {
        findings.push({
          kind: 'unknown_record',
          from: fromRecord.canonicalDomain,
          to: targetCanonical,
          field,
          detail: `${fromRecord.canonicalDomain}.${field} references ${targetCanonical}, which has no record in records.json.`,
        });
        continue;
      }
      const counterpartyManifest = manifests[counterparty.manifestKey];
      if (
        manifestDeclaresBoundary(
          counterpartyManifest,
          fromRecord.canonicalDomain,
        )
      ) {
        continue;
      }

      findings.push({
        kind: driftKindForField(cp.kind),
        from: fromRecord.canonicalDomain,
        to: counterparty.canonicalDomain,
        field,
        detail: driftDetail(cp, fromRecord.canonicalDomain, counterparty.canonicalDomain),
      });
    }
  }
  return findings;
}

function claimPathField(cp: ClaimPath): DriftFinding['field'] {
  if (cp.kind === 'parentOrganization') return 'parentOrganization';
  if (cp.kind === 'relatedOrganizations') return 'relatedOrganizations';
  return 'claimedExternalDomains';
}

function driftKindForField(kind: ClaimPath['kind']): DriftKind {
  switch (kind) {
    case 'parentOrganization':
      return 'unreciprocated_parent';
    case 'relatedOrganizations':
      return 'unreciprocated_related';
    case 'claimedExternalDomains':
      return 'unreciprocated_claimed_external';
  }
}

function driftDetail(cp: ClaimPath, from: string, to: string): string {
  switch (cp.kind) {
    case 'parentOrganization':
      return `${from} declares ${to} as parentOrganization, but ${to}'s manifest does not list ${from} in any reciprocal field.`;
    case 'relatedOrganizations':
      return `${from} declares ${to} in relatedOrganizations, but ${to}'s manifest does not list ${from} back.`;
    case 'claimedExternalDomains':
      return `${from} lists "${cp.url}" in claimedExternalDomains (resolves to ${to}); ${to} does not declare ${from} back.`;
  }
}

/**
 * Filter findings to only the pair (a -> b) and (b -> a). Used by /verify
 * to attach drift warnings only when the verified URL's org pair is part
 * of a finding.
 */
export function findingsForPair(
  findings: DriftFinding[],
  a: string,
  b: string,
): DriftFinding[] {
  const A = stripWww(a.toLowerCase());
  const B = stripWww(b.toLowerCase());
  return findings.filter((f) => {
    const from = stripWww(f.from.toLowerCase());
    const to = stripWww(f.to.toLowerCase());
    return (from === A && to === B) || (from === B && to === A);
  });
}

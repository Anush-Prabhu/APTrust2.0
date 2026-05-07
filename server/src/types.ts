export type RecordStatus = 'active' | 'test' | 'disabled';

/**
 * How the engine interprets a manifest graph rooted at this record.
 *
 * - `bidirectional` (default): a host owned by a related/parent org is only
 *   admitted as RELATED when the counterparty's manifest reciprocates. This
 *   is what the engine has always done; declaring it explicitly makes the
 *   policy visible to operators.
 * - `unidirectional-warn`: same admit decision as `bidirectional`, but the
 *   policy is documented to accept a one-way claim with a warning. The
 *   engine still emits drift warnings via `attachDriftWarnings`; this value
 *   is reserved for future tuning.
 */
export type AcceptWithinBoundary = 'bidirectional' | 'unidirectional-warn';

export interface RecordPolicy {
  defaultDecision: 'deny' | 'allow';
  allowNameserverExpansion: boolean;
  requireBidirectionalVerification: boolean;
  /**
   * Optional canonical domain that this record considers its "trust root"
   * (e.g. `jhu.edu` for `jh.edu`, `jhmi.edu`, and `hopkinsmedicine.org`).
   * Documentation only \u2014 the engine never blocks selection. Surfaced to
   * the popup via the `_normalized` view and to admin tooling.
   */
  trustRootCanonical?: string;
  /**
   * Documentation hook for the bidirectional-acceptance semantics. Defaults
   * to `bidirectional`. Today the engine does not branch on this value; the
   * field exists so the policy is authored alongside the data and can be
   * surfaced to operators.
   */
  acceptWithinBoundary?: AcceptWithinBoundary;
}

export interface RecordEntry {
  canonicalDomain: string;
  displayName: string;
  type: string;
  status: RecordStatus;
  manifestKey: string;
  aliases: string[];
  policy: RecordPolicy;
}

export interface RelatedOrganization {
  name: string;
  canonicalDomain: string;
  url: string;
  domains: string[];
  relationshipType?: string;
}

export interface ParentOrganization {
  name: string;
  canonicalDomain: string;
  url: string;
}

/**
 * Optional contact details that the extension's "Report" button surfaces.
 * Restored from APT 1.0.
 */
export interface ReportContact {
  team?: string;
  email?: string;
  url?: string;
  note?: string;
}

/**
 * Restored from APT 1.0. Each entry can be a bare host string OR an object
 * with a human-readable reason. The engine emits the reason in `reasons[]`
 * when a host matches.
 */
export type ExclusionEntry = string | { domain: string; reason?: string };

/**
 * Restored from APT 1.0. Some organizations contract a third party to host
 * an official asset on a domain they don't own (employment vendors, alumni
 * giving platforms, learning-management providers, conference bookers,
 * webmail tenants, ...). Listed entries are matched as exact URLs (query
 * stripped) and resolve to status `OFFICIAL` with relationship
 * `ADDITIONAL_PROFILE_DECLARED`.
 */
export type AdditionalProfileEntry =
  | string
  | { url: string; provider?: string; note?: string };

/**
 * Restored from APT 1.0. Declares the org's official webmail provider so the
 * engine can confirm a tenant URL (e.g. shared Outlook / GSuite) and the
 * extension can avoid mis-flagging the inbox itself.
 */
export interface OfficialMail {
  provider: string;
  /** Full webmail URL the org sends users to (canonical entry point). */
  webUrl: string;
  /** Hostname of the webmail tenant. */
  host: string;
  /**
   * Optional fragment of the full URL (path or query) that confirms the
   * tenant belongs to this org. e.g. `realm=jh.edu`. When omitted the engine
   * trusts any path on the listed host.
   */
  realmHint?: string;
  note?: string;
}

/**
 * Restored from APT 1.0. Declarative metadata describing which match modes
 * the org expects the engine to use. The engine reads this for documentation
 * and admin display only \u2014 the actual matching is hard-wired.
 */
export interface TrustRuleDeclaration {
  type: 'domain' | 'socialProfile' | 'additionalProfile' | string;
  match: 'exact' | 'exact-or-subdomain' | 'exact-url' | string;
}

/**
 * Restored from APT 1.0. Pure metadata; the POC never enforces hash or NS
 * verification, but the manifest declares the intended algorithm so the
 * surface area matches v1.
 */
export interface VerificationMethodMetadata {
  hashAlgorithm?: string;
  hashVerificationEnabled?: boolean;
  nameserverMetadata?: {
    note?: string;
    nameservers?: string[];
  };
}

export interface Manifest {
  name: string;
  url: string;
  officialDomains: string[];
  relatedOrganizations?: RelatedOrganization[];
  parentOrganization?: ParentOrganization;
  socialProfiles: string[];
  /**
   * Restored from APT 1.0. Third-party-hosted official assets (employment
   * portals, donation platforms, etc.) matched as exact URLs.
   */
  additionalProfiles?: AdditionalProfileEntry[];
  /**
   * Domains the boundary CLAIMS belong to it, even when they are owned by
   * another organization. Used to detect suspicious unidirectional claims
   * (see FR-RULE-003).
   */
  claimedExternalDomains?: string[];
  /**
   * Optional explicit deny-list. Hosts that match (or are subdomains of) any
   * URL/host listed here resolve to status `EXCLUDED` regardless of any
   * other rule. Restored from APT 1.0; v1 entries may include a `reason`.
   */
  excludedDomains?: ExclusionEntry[];
  reportContact?: ReportContact;
  officialMail?: OfficialMail;
  trustRule?: TrustRuleDeclaration[];
  verificationMethod?: VerificationMethodMetadata;
  /** Free-form metadata. */
  version?: string;
  lastUpdated?: string;
}

export type ManifestMap = Record<string, Manifest>;

export type RuleType =
  | 'DOMAIN_EXACT'
  | 'OFFICIAL_DOMAIN'
  | 'RELATED_ORGANIZATION'
  | 'SOCIAL_PROFILE_EXACT'
  | 'BIDIRECTIONAL_REQUIRED'
  | 'UNIDIRECTIONAL_CLAIM_DETECTION'
  | 'LOOKALIKE_DETECTION'
  | 'NAMESERVER_ALLOWLIST'
  | 'DENY_PATTERN';

export interface Rule {
  id: string;
  type: RuleType;
  enabled: boolean;
  scope: string;
  effect: string;
  priority: number;
  requiresBidirectionalVerification: boolean;
  notes?: string;
  nameservers?: string[];
}

export type Status =
  | 'OFFICIAL'
  | 'RELATED'
  | 'SOCIAL_VERIFIED'
  | 'RELATED_CANDIDATE'
  | 'OUT_OF_BOUNDARY'
  | 'SUSPICIOUS_LOOKALIKE'
  | 'SUSPICIOUS_UNIDIRECTIONAL_CLAIM'
  | 'EXCLUDED'
  | 'UNKNOWN'
  | 'DISABLED_BOUNDARY';

export type Relationship =
  | 'SELF_VERIFIED'
  | 'OFFICIAL_DOMAIN_DECLARED'
  | 'PARENT_CHILD_DECLARED'
  | 'BIDIRECTIONAL_VERIFIED'
  | 'UNIDIRECTIONAL_CLAIM'
  | 'SOCIAL_PROFILE_DECLARED'
  | 'ADDITIONAL_PROFILE_DECLARED'
  | 'OFFICIAL_MAIL_DECLARED'
  | 'LOOKALIKE_DETECTED'
  | 'NO_RELATIONSHIP_FOUND';

export interface VerifyRequest {
  boundary: string;
  url: string;
}

export interface VerifyResult {
  boundary: string;
  url: string;
  normalizedDomain: string;
  status: Status;
  statusCode: number;
  relationship: Relationship;
  reasons: string[];
  /**
   * Non-blocking advisories surfaced alongside the verdict. Today this is
   * populated when a drift finding (see {@link DriftFinding}) involves the
   * boundary and the resolved counterparty for the verified URL. The
   * verdict itself is still computed from rule order; warnings are
   * informational and never change `status`.
   */
  warnings?: VerifyWarning[];
}

export interface VerifyWarning {
  /** Stable machine-readable identifier (e.g. 'manifest_drift'). */
  kind: string;
  /** Human-readable one-line explanation. */
  detail: string;
  /** Optional structured payload for clients that want to render details. */
  data?: unknown;
}

export interface AdminDataPayload {
  records: RecordEntry[];
  manifests: ManifestMap;
  rules: Rule[];
}

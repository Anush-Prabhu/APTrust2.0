/**
 * Suspicious lookalike detection for the AP Trust POC.
 *
 * Local heuristics only. No remote calls, no real WHOIS, no live registrar
 * checks. The point is to flag obvious typo, repeat-character, punycode, and
 * brand-keyword squats so the demo can show "this is suspicious" instead of
 * letting a fake site slip through as `OUT_OF_BOUNDARY`.
 */

import { isPunycode, stripWww } from '../normalize';

export const SUSPICIOUS_KEYWORDS = [
  'login',
  'verify',
  'security',
  'account',
  'support',
  'auth',
  'portal',
] as const;

/** Standard iterative Levenshtein implementation. */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  const prev = new Array<number>(n + 1);
  const curr = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1, // deletion
        curr[j - 1] + 1, // insertion
        prev[j - 1] + cost, // substitution
      );
    }
    for (let j = 0; j <= n; j++) prev[j] = curr[j];
  }
  return prev[n];
}

/** Domain stem = labels before the public TLD (rough approximation: all but last). */
export function domainStem(host: string): string {
  const h = stripWww(host);
  const parts = h.split('.');
  if (parts.length <= 1) return h;
  return parts.slice(0, -1).join('.');
}

export interface LookalikeFinding {
  isLookalike: boolean;
  reasons: string[];
  matchedAgainst?: string;
  method?:
    | 'PUNYCODE'
    | 'LEVENSHTEIN'
    | 'REPEATED_CHARACTER'
    | 'BRAND_KEYWORD';
}

export interface LookalikeOptions {
  /**
   * The domains we want to protect against (boundary canonical + officialDomain
   * hosts). We will compare the candidate against each of these.
   */
  protectedHosts: string[];
  /** Maximum Levenshtein distance to count as a typo lookalike. */
  maxDistance?: number;
  /**
   * Optional best-effort registered domain (eTLD+1) of the candidate host.
   * When supplied, the heuristics also evaluate it. This catches cases where
   * the literal host has subdomain noise that hides a typo, e.g.
   *   candidate `news.jhuu.edu`, registeredDomain `jhuu.edu`, vs `jhu.edu`.
   */
  registeredDomain?: string;
}

/**
 * Check whether `candidateHost` looks like a deceptive variant of any host in
 * `protectedHosts`. The candidate must NOT exactly equal a protected host
 * (callers should test that case before invoking lookalike detection).
 */
export function detectLookalike(
  candidateHost: string,
  options: LookalikeOptions,
): LookalikeFinding {
  const max = options.maxDistance ?? 2;
  const candidate = stripWww(candidateHost.toLowerCase());
  const reg = options.registeredDomain
    ? stripWww(options.registeredDomain.toLowerCase())
    : '';
  // Evaluate both the literal host and (if different) the registered domain.
  const candidates: string[] = [candidate];
  if (reg && reg !== candidate) candidates.push(reg);

  for (const c of candidates) {
    if (isPunycode(c)) {
      return {
        isLookalike: true,
        reasons: [
          `Domain "${candidateHost}" uses an internationalized "xn--" (punycode) label, which is a common impersonation vector.`,
        ],
        method: 'PUNYCODE',
        matchedAgainst: c,
      };
    }
  }

  let bestDistance = Infinity;
  let bestTarget: string | undefined;
  let bestCandidate: string | undefined;
  for (const c of candidates) {
    for (const raw of options.protectedHosts) {
      const target = stripWww(raw.toLowerCase());
      if (!target || target === c) continue;
      const d = levenshtein(c, target);
      if (d < bestDistance) {
        bestDistance = d;
        bestTarget = target;
        bestCandidate = c;
      }
    }
  }

  if (bestTarget && bestDistance > 0 && bestDistance <= max) {
    const using = bestCandidate && bestCandidate !== candidate
      ? ` (registered domain "${bestCandidate}")`
      : '';
    return {
      isLookalike: true,
      reasons: [
        `Domain "${candidateHost}"${using} is only ${bestDistance} character${bestDistance === 1 ? '' : 's'} away from the trusted domain "${bestTarget}".`,
      ],
      method: 'LEVENSHTEIN',
      matchedAgainst: bestTarget,
    };
  }

  // Repeated-character pattern such as `jhuu.edu` (extra "u").
  for (const c of candidates) {
    if (!bestTarget) break;
    if (hasRepeatedCharacterInsertion(c, bestTarget)) {
      const using = c !== candidate ? ` (registered domain "${c}")` : '';
      return {
        isLookalike: true,
        reasons: [
          `Domain "${candidateHost}"${using} appears to repeat a character compared to the trusted domain "${bestTarget}".`,
        ],
        method: 'REPEATED_CHARACTER',
        matchedAgainst: bestTarget,
      };
    }
  }

  // Brand keyword squat: candidate contains the trusted stem AND a suspicious keyword.
  for (const raw of options.protectedHosts) {
    const target = stripWww(raw.toLowerCase());
    const stem = domainStem(target);
    if (!stem) continue;
    for (const c of candidates) {
      if (c.includes(stem) && c !== target) {
        const found = SUSPICIOUS_KEYWORDS.find((k) => c.includes(k));
        if (found) {
          return {
            isLookalike: true,
            reasons: [
              `Domain "${candidateHost}" combines the trusted stem "${stem}" with the suspicious keyword "${found}".`,
            ],
            method: 'BRAND_KEYWORD',
            matchedAgainst: target,
          };
        }
      }
    }
  }

  return { isLookalike: false, reasons: [] };
}

function hasRepeatedCharacterInsertion(candidate: string, target: string): boolean {
  if (candidate.length !== target.length + 1) return false;
  for (let i = 0; i < target.length; i++) {
    if (candidate[i] === target[i] && candidate[i + 1] === target[i]) {
      // Removing one of the doubled chars yields target.
      const rebuilt = candidate.slice(0, i) + candidate.slice(i + 1);
      if (rebuilt === target) return true;
    }
  }
  return false;
}

/**
 * URL and host normalization helpers used across the rule engine and routes.
 *
 * Local POC only \u2014 does NOT perform real DNS, NS, or remote lookups.
 */

export interface NormalizedUrl {
  ok: boolean;
  /** Lowercase hostname, no port. */
  host?: string;
  /** Pathname including a leading slash; never has a trailing slash unless the path is "/". */
  path?: string;
  /** Lowercased `<scheme>://<host><path>` with no trailing slash. */
  canonical?: string;
  reason?: string;
}

export function normalizeUrl(input: string): NormalizedUrl {
  const raw = String(input ?? '').trim();
  if (!raw) return { ok: false, reason: 'Empty URL' };

  // Primary path: the WHATWG URL parser. Some inputs we still need to verify
  // (e.g. invalid-IDN punycode lookalikes from FR-RULE-004) make this throw,
  // so we keep a regex-based fallback for those cases below.
  try {
    const parsed = new URL(raw.includes('://') ? raw : `http://${raw}`);
    const host = parsed.hostname.toLowerCase();
    if (host) {
      let path = parsed.pathname || '/';
      if (path.length > 1 && path.endsWith('/')) {
        path = path.replace(/\/+$/, '');
      }
      const canonical = `${parsed.protocol.toLowerCase()}//${host}${
        path === '/' ? '' : path
      }`;
      return { ok: true, host, path, canonical };
    }
  } catch {
    // fall through to regex parser
  }

  const fallback = parseFallback(raw);
  if (fallback) return fallback;
  return { ok: false, reason: 'Invalid URL' };
}

function parseFallback(raw: string): NormalizedUrl | null {
  const m = raw.match(/^(?:[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/)?([^/?#\s]+)([/?#].*)?$/);
  if (!m) return null;
  let hostPart = m[1].toLowerCase().replace(/^[^@]*@/, '').replace(/:\d+$/, '');
  if (!hostPart || !hostPart.includes('.')) return null;
  let path = '/';
  const rest = m[2];
  if (rest) {
    const noQuery = rest.split(/[?#]/)[0] || '/';
    path = noQuery.length > 1 && noQuery.endsWith('/')
      ? noQuery.replace(/\/+$/, '')
      : noQuery;
  }
  const canonical = `http://${hostPart}${path === '/' ? '' : path}`;
  return { ok: true, host: hostPart, path, canonical };
}

/** Strip a leading `www.` from a host if present. */
export function stripWww(host: string): string {
  return host.replace(/^www\./i, '');
}

export function isPunycode(host: string): boolean {
  return host.split('.').some((label) => label.toLowerCase().startsWith('xn--'));
}

/**
 * Compare two URLs for "exact" social profile equivalence:
 *   - hostnames are compared lowercased
 *   - paths are compared lowercased and without trailing slash
 *
 * Strict scheme is ignored (http vs https are considered equivalent for the POC).
 */
export function socialProfileEquals(a: string, b: string): boolean {
  const na = normalizeUrl(a);
  const nb = normalizeUrl(b);
  if (!na.ok || !nb.ok) return false;
  return (
    na.host === nb.host &&
    (na.path || '/').toLowerCase() === (nb.path || '/').toLowerCase()
  );
}

/**
 * APT 1.0 "sub-path" social profile match.
 *
 * Returns true when `visited` is the declared profile URL OR any sub-path of
 * it at a path-segment boundary. Same-host required.
 *
 *   declared = https://www.instagram.com/johnshopkinsu
 *   visited  = https://www.instagram.com/johnshopkinsu              -> true (exact)
 *   visited  = https://www.instagram.com/johnshopkinsu/tagged       -> true (sub-path)
 *   visited  = https://www.instagram.com/johnshopkinsuhelp          -> false (segment-aware)
 *   visited  = https://www.instagram.com/OtherAccount               -> false
 */
export function socialProfileMatchesPath(visited: string, declared: string): boolean {
  const v = normalizeUrl(visited);
  const d = normalizeUrl(declared);
  if (!v.ok || !d.ok) return false;
  if (v.host !== d.host) return false;
  const vp = (v.path || '/').toLowerCase();
  const dp = (d.path || '/').toLowerCase();
  if (vp === dp) return true;
  return vp.startsWith(dp + '/');
}

/**
 * Canonicalize a URL for `additionalProfiles` exact-URL matching:
 *   - lowercase host
 *   - drop www when stripWww=true (default false; preserves the URL the org wrote)
 *   - drop query string and fragment
 *   - normalize trailing slash on path (path === '/' kept; otherwise trailing
 *     slash removed)
 *   - lowercase scheme but keep both http/https as separate canonicals so we
 *     can detect a deliberate downgrade (we still treat http vs https as
 *     equivalent at compare time below)
 *
 * Returns null if the URL cannot be parsed.
 */
export function canonicalUrl(input: string): string | null {
  const r = normalizeUrl(input);
  if (!r.ok) return null;
  return r.canonical || `http://${r.host}${r.path === '/' ? '' : r.path}`;
}

/**
 * Exact-URL match used by `additionalProfiles`. Ignores scheme http vs https
 * and ignores query / fragment.
 */
export function additionalProfileEquals(a: string, b: string): boolean {
  const ca = canonicalUrl(a);
  const cb = canonicalUrl(b);
  if (!ca || !cb) return false;
  const stripScheme = (s: string) => s.replace(/^https?:\/\//, '');
  return stripScheme(ca).toLowerCase() === stripScheme(cb).toLowerCase();
}

export function getHostFromUrl(url: string): string | null {
  const r = normalizeUrl(url);
  return r.ok ? r.host! : null;
}

/**
 * Returns true if `host` is "the same" as `target` for boundary comparison
 * purposes, allowing for an optional leading `www.` on either side.
 */
export function hostMatches(host: string, target: string): boolean {
  if (!host || !target) return false;
  const h = host.toLowerCase();
  const t = target.toLowerCase();
  return h === t || stripWww(h) === stripWww(t);
}

/**
 * Returns true if `host` equals `parent` OR is a subdomain of `parent`.
 *
 * Examples:
 *   isSubdomainOf('news.jhu.edu', 'jhu.edu')            \u2192 true
 *   isSubdomainOf('apply.it.jhu.edu', 'jhu.edu')        \u2192 true
 *   isSubdomainOf('jhu.edu', 'jhu.edu')                 \u2192 true
 *   isSubdomainOf('jhuu.edu', 'jhu.edu')                \u2192 false (sibling, not subdomain)
 *   isSubdomainOf('evil-jhu.edu', 'jhu.edu')            \u2192 false (label-aware)
 *
 * Comparison is label-aware (checks `endsWith('.' + parent)`), so
 * `evil-jhu.edu` does NOT match `jhu.edu`.
 */
export function isSubdomainOf(host: string, parent: string): boolean {
  if (!host || !parent) return false;
  const h = stripWww(host.toLowerCase());
  const p = stripWww(parent.toLowerCase());
  if (!h || !p) return false;
  if (h === p) return true;
  return h.endsWith('.' + p);
}

/**
 * Finds the longest host in `scope` such that `host` equals it or is a
 * subdomain of it. Returns null if no match.
 *
 * "Longest" matters when the scope contains both `jhu.edu` and `it.jhu.edu`
 * \u2014 a target of `apply.it.jhu.edu` should attribute to the more specific
 * declared host.
 */
export function findHostScopeMatch(
  host: string,
  scope: Iterable<string>,
): { matched: string; subdomain: boolean } | null {
  if (!host) return null;
  const h = stripWww(host.toLowerCase());
  let best: { matched: string; subdomain: boolean } | null = null;
  for (const raw of scope) {
    const p = stripWww((raw || '').toLowerCase());
    if (!p) continue;
    if (h === p) {
      // Exact match always wins.
      return { matched: p, subdomain: false };
    }
    if (h.endsWith('.' + p)) {
      if (!best || p.length > best.matched.length) {
        best = { matched: p, subdomain: true };
      }
    }
  }
  return best;
}

/**
 * Best-effort "registered domain" approximation (eTLD+1) for the POC.
 *
 * Returns the last two labels of the host. This is intentionally simplistic:
 * it does NOT consult the Public Suffix List, so multi-segment TLDs like
 * `co.uk` are not handled correctly. The seed data targets `.edu`, `.org`,
 * and `.com`, where this approximation is correct.
 */
export function registeredDomain(host: string): string {
  if (!host) return '';
  const h = stripWww(host.toLowerCase());
  const parts = h.split('.').filter(Boolean);
  if (parts.length <= 2) return h;
  return parts.slice(-2).join('.');
}

/**
 * Hosts that should NEVER be treated as official just because they are listed
 * (or a subdomain of a listed host) inside an officialDomains array. These
 * are multi-tenant platforms where individual paths/handles \u2014 not the host
 * \u2014 represent identity.
 *
 * Engine code that performs subdomain expansion must skip hosts in this set.
 */
export const SOCIAL_HOSTS: ReadonlySet<string> = new Set([
  'x.com',
  'twitter.com',
  'facebook.com',
  'm.facebook.com',
  'linkedin.com',
  'youtube.com',
  'm.youtube.com',
  'instagram.com',
  'tiktok.com',
  'threads.net',
  'reddit.com',
]);

export function isSocialHost(host: string): boolean {
  if (!host) return false;
  const h = stripWww(host.toLowerCase());
  if (SOCIAL_HOSTS.has(h)) return true;
  for (const s of SOCIAL_HOSTS) {
    if (h.endsWith('.' + s)) return true;
  }
  return false;
}

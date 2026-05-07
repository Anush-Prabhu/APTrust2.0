# AP Trust \u2014 Local Verification POC (v2.0)

Trust-boundary verification POC. An organization declares its official
digital assets in a structured local manifest, and a Chrome extension verifies
whether a visited URL or social profile is inside or outside that declared
trust boundary.

Everything runs **locally**:

- No real DNS or NS lookups.
- No remote manifest fetching.
- No hash verification, no signatures, no remote APIs.

The complete normative spec lives in
[`aptrust_local_verification_poc_srs.md`](aptrust_local_verification_poc_srs.md).

**Full developer documentation** (architecture, bidirectional logic with code references, unique features, extension contract, testing):  
[**docs/APTrust2.0-developer-guide.md**](docs/APTrust2.0-developer-guide.md)

**Upstream repository:** [github.com/Anush-Prabhu/APTrust2.0](https://github.com/Anush-Prabhu/APTrust2.0)

## Layout

```
aptrust2.0/
\u251c\u2500\u2500 server/                 Local Express + TypeScript server, rule engine, admin UI host
\u2502   \u251c\u2500\u2500 src/                Server source (TypeScript)
\u2502   \u2514\u2500\u2500 public/admin/       Static admin UI files (vanilla JS)
\u251c\u2500\u2500 extension/              Chrome MV3 extension (popup + content scripts for banners / badges)
\u251c\u2500\u2500 data/
\u2502   \u251c\u2500\u2500 records.json        Index of canonical trust boundaries
\u2502   \u251c\u2500\u2500 manifests/          ONE JSON file per organization (mirrors APT 1.0)
\u2502   \u2502   \u251c\u2500\u2500 jhu.edu.json
\u2502   \u2502   \u251c\u2500\u2500 jh.edu.json
\u2502   \u2502   \u251c\u2500\u2500 jhmi.edu.json
\u2502   \u2502   \u251c\u2500\u2500 hopkinsmedicine.org.json
\u2502   \u2502   \u2514\u2500\u2500 jhuu.com.json   (intentionally suspicious lookalike example)
\u2502   \u2514\u2500\u2500 rules.json          Engine rule registry
\u251c\u2500\u2500 docs/                   Architecture, demo script, production roadmap
\u2514\u2500\u2500 README.md
```

## Requirements

- Node.js 18 or newer
- Google Chrome (or any Chromium browser that supports unpacked MV3 extensions)

## Install and run

```bash
# from repo root
npm install
npm run dev
```

Expected output:

```
AP Trust local server running at http://localhost:3000
```

The admin UI is available at <http://localhost:3000/admin>.

To run the test suite (rule engine + server endpoints):

```bash
npm test
```

## Load the extension

1. Open `chrome://extensions`.
2. Enable Developer mode.
3. **Load unpacked** \u2192 choose the `extension/` folder.

The popup talks only to `http://localhost:3000`; if the local server is not
running, the popup says so explicitly.

**Popup (APT 1.0 layout, single-screen, color-coded verdicts):**

- **Header** with Protect Mode toggle.
- **Selected boundary** card: display name, canonical domain, manifest version, Clear button.
- **Find a boundary** search (results live-filter from `GET /search`).
- **Current tab**: tab URL plus a color-coded verdict box (green TRUSTED / red UNTRUSTED / purple EXCLUDED / blue EMAIL CLIENT). When the verdict is UNTRUSTED or EXCLUDED, a **Report this page** button opens the v1 in-page report modal (with the selected boundary's `reportContact`).
- **Verify a URL, email, or social handle**: a single input that auto-detects what you typed and shows a verdict box with reasons:
  - `https://example.com/path` &rarr; verified directly.
  - `someone@jhu.edu` &rarr; verifies the email's domain (`https://jhu.edu/`).
  - `@johnshopkinsu` &rarr; matched against the selected boundary's declared `aptrust:sameAsSocialProfile` entries; resolves to SOCIAL_VERIFIED on a trailing-segment match, or "NOT FOUND" otherwise.

**APT 1.0-style browsing features (preserved on top of v2.0 `/verify`):**

- Toolbar **badge**: **OK** (green) when the active tab is inside the selected boundary; **!** (red) when it is outside; **X** (purple) when the host is on the boundary's `excludedDomains` deny-list; **\u2709** on recognized webmail hosts (message links are still evaluated).
- **Red in-page banner** with **APTrust** branding, **Report to &lt;boundary&gt;**, and **Dismiss** when the page is outside the boundary (Protect Mode on).
- **Untrusted link outlines**, **paste** warnings for untrusted URLs, and a banner when a **redirect** lands outside the boundary.
- **POST `/report`** on the local server accepts mock impersonation reports from the extension (logged to the server console only). The report modal pulls the selected boundary's optional `reportContact` (team / email / URL / note) from `GET /manifest/:domain`.

**Per-organization manifests in JSON-LD.** Each canonical domain has its own file under `data/manifests/<canonical>.json` (mirrors APT 1.0's `aptrust-records/domains/<domain>/manifest.jsonld`). Files are JSON-LD with the schema.org `@context` and an `aptrust:` namespace, so they speak as much native schema.org vocabulary as possible:

```json
{
  "@context": { "@vocab": "https://schema.org/", "aptrust": "https://aptrust.org/vocab#" },
  "@type": "Organization",
  "@id": "https://jhu.edu/",
  "name": "Johns Hopkins University",
  "alternateName": ["JHU", "Johns Hopkins"],
  "address": { "@type": "PostalAddress", "..." },
  "sameAs": ["https://en.wikipedia.org/wiki/Johns_Hopkins_University", "..."],
  "identifier": [{ "@type": "PropertyValue", "propertyID": "ROR", "value": "00za53h95" }, "..."],
  "softwareVersion": "1.0.0",
  "dateModified": "2026-05-07T00:00:00Z",
  "aptrust:sameAsDomain": ["..."],
  "aptrust:sameAsSocialProfile": ["..."],
  "aptrust:sameAsAdditionalProfile": ["..."],
  "aptrust:trustBoundary": { "..." },
  "aptrust:trustRule": ["..."],
  "aptrust:relatedOrganization": ["..."],
  "aptrust:exclusion": [{ "domain": "...", "reason": "..." }],
  "aptrust:officialMail": { "..." },
  "aptrust:reportContact": { "..." }
}
```

The loader (`server/src/data.ts`) accepts either form (JSON-LD or plain v2 keys) and normalizes to the engine's internal `Manifest`. The `GET /manifest/:domain` endpoint preserves the JSON-LD shape on the wire and adds a `_normalized` field for clients that want plain v2 keys. The seed set ships with `jhu.edu`, `jh.edu`, `jhmi.edu`, `hopkinsmedicine.org`, and a deliberately-suspicious `jhuu.com`.

**Subdomain matching.** Hosts are matched label-aware: when the selected boundary is `jhu.edu`, `news.jhu.edu` and `apply.it.jhu.edu` resolve as `OFFICIAL` without needing every subdomain enumerated in the manifest. The same expansion applies to declared `officialDomains`, `relatedOrganizations`, and `parentOrganization` hosts; `evil-jhu.edu` is correctly rejected because it is a sibling, not a subdomain. Subdomain expansion is intentionally suppressed for known multi-tenant social hosts (`x.com`, `instagram.com`, ...) so that only a `socialProfiles` match counts.

**Third-party-hosted official assets (`additionalProfiles`).** Restored from APT 1.0. Each manifest can declare exact URLs for vendor-hosted official pages \u2014 e.g. JHU's student-employment portal at `johnshopkins.employment.ngwebsolutions.com`, the Qualtrics survey tenant `jhu.qualtrics.com`, or Hopkins Medicine's Epic MyChart instance. Matched as exact URLs (query/fragment ignored) and surfaced as `OFFICIAL` with relationship `ADDITIONAL_PROFILE_DECLARED`. Different hosts on the same vendor platform (`otheruniversity.qualtrics.com`) are correctly rejected.

**Sub-path social profiles.** A declared social profile URL like `https://www.instagram.com/johnshopkinsu` now also matches `/johnshopkinsu/tagged`, `/johnshopkinsu/reels/...`, etc., at a path-segment boundary. Prefix-but-not-segment hosts like `/johnshopkinsuhelp` are still rejected.

**Official webmail (`officialMail`).** A manifest declares its webmail provider, host, and an optional `realmHint` (e.g. `realm=jh.edu`). When the user visits `outlook.cloud.microsoft/mail/?realm=jh.edu` under the JHU boundary, the engine returns `OFFICIAL` with relationship `OFFICIAL_MAIL_DECLARED`. The same host with a different `realm=` value is NOT auto-trusted (the page-level extension still softens to the mail-client banner so the inbox isn't painted as an impersonation target).

**Explicit deny-list (`excludedDomains`).** A manifest may include `Array<string | { domain, reason }>`. Any host that equals or is a subdomain of an entry resolves to status `EXCLUDED`, overriding every allow-list rule. The per-entry reason flows back into the response and is shown in the popup / banner. Restored from APT 1.0.

**Optional metadata.** Each manifest can also declare `trustRule` (declarative match modes), `verificationMethod` (hash + nameserver metadata), `version`, and `lastUpdated`. The engine treats these as documentation surface; admin UI displays them as-is.

Network use is still limited to your machine: the extension may fetch any `http(s)` page's URL string only to evaluate it via `POST /verify` on localhost; it does not exfiltrate history to a remote service.

## Demo

A step-by-step walkthrough with expected statuses and status codes lives in
[`docs/demo-script.md`](docs/demo-script.md). It mirrors SRS section 12 and
covers:

- Official domain detection.
- Bidirectionally verified related organizations.
- Social profile verification.
- Suspicious lookalike detection (`jhuu.edu` under `jhu.edu`).
- Suspicious unidirectional-claim detection (`jhu.edu` under boundary
  `jhuu.edu`).
- The nameserver-allowlist rule, which is disabled by default and can never
  produce `OFFICIAL` on its own.

## Endpoints

| Method | Path                       | Purpose                                       |
| ------ | -------------------------- | --------------------------------------------- |
| GET    | `/health`                  | Liveness check                                |
| GET    | `/search?q=<keyword>`      | Search trust boundaries                       |
| GET    | `/entry/:domain`           | Get one organization record                   |
| GET    | `/manifest/:domain`        | Get one local manifest                        |
| GET    | `/rules`                   | Get all rules                                 |
| POST   | `/verify`                  | Verify a URL against a selected boundary      |
| POST   | `/report`                  | Mock report sink (extension "Report" button)   |
| GET    | `/admin`                   | Admin UI                                      |
| GET    | `/admin/data`              | Records + manifests + rules in one payload    |
| POST   | `/admin/save-records`      | Save records.json                             |
| POST   | `/admin/save-manifests`    | Save manifests.json                           |
| POST   | `/admin/save-rules`        | Save rules.json                               |
| GET    | `/admin/manifest-consistency` | Pairwise relationship-graph drift findings |

## Verification statuses

`OFFICIAL`, `RELATED`, `SOCIAL_VERIFIED`, `RELATED_CANDIDATE`,
`OUT_OF_BOUNDARY`, `SUSPICIOUS_LOOKALIKE`,
`SUSPICIOUS_UNIDIRECTIONAL_CLAIM`, `EXCLUDED`, `UNKNOWN`,
`DISABLED_BOUNDARY`.

Relationships include the APT 1.0-restored `ADDITIONAL_PROFILE_DECLARED`
(third-party portal) and `OFFICIAL_MAIL_DECLARED` (webmail tenant) in
addition to the v2.0 set.

### Dynamic fraud explanations

When a verdict resolves to `SUSPICIOUS_UNIDIRECTIONAL_CLAIM`, the engine
no longer emits a fixed three-line message. Reasons are built from the
actual manifests at evaluation time:

1. The exact field on the boundary's manifest where the relationship was
   declared (`parentOrganization`, `relatedOrganizations[]`, or
   `claimedExternalDomains`), including names and domain lists.
2. The fields scanned on the counterparty's manifest
   (`parentOrganization`, `relatedOrganizations[]` candidates,
   `officialDomains[]` count) and what each one resolved to.
3. The closing policy line: self-attestation alone is not sufficient.

This means hand-authoring a new malicious manifest in
`data/manifests/<your-impostor>.json` produces a fully descriptive
verdict with no engine code change \u2014 the message follows the data.

### Cross-manifest drift

The engine computes pairwise relationship-graph drift across all loaded
manifests: if A asserts a relationship to B, B's manifest must declare A
back through `parentOrganization`, `relatedOrganizations`, or
`officialDomains`. Findings are exposed in two places:

- `GET /admin/manifest-consistency` lists every unreciprocated edge plus
  any claim that points at an unknown record.
- `POST /verify` attaches a non-blocking `warnings[]` array to the
  verdict whenever the verified URL's resolved counterparty is part of a
  drift finding involving the boundary. The verdict's `status` is
  unaffected by warnings.

### Trust root + acceptance policy

Records may declare an optional `policy.trustRootCanonical` (e.g.
`jhu.edu` for the JHU family). It is documentation only \u2014 the engine
never blocks selection of a non-root boundary \u2014 but the field is
surfaced via `GET /manifest/:domain` (in `_policy`) so the popup can show
the relationship under the boundary card. The companion
`policy.acceptWithinBoundary` field documents that subdomains owned by a
related/parent organization are admitted as `RELATED` only when the
counterparty's manifest reciprocates (`bidirectional`, the default).

See [`docs/architecture.md`](docs/architecture.md) for the rule priority
order and module map.

## Disclaimer

Proof of concept only. The admin UI is local-only and unauthenticated; a
production system would add authentication, authorization, signed updates,
change approvals, and audit logs. See
[`docs/future-production-roadmap.md`](docs/future-production-roadmap.md).

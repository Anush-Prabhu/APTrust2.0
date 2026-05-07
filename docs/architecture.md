# AP Trust Local Verification POC \u2014 Architecture

This document describes the v2.0 local POC. Everything runs locally; there are
no remote DNS, NS, manifest, or hash lookups in this version. See the SRS
(`aptrust_local_verification_poc_srs.md`) for the normative spec.

## Components

```
+-------------------+       +-----------------------+       +-------------------+
| Browser Extension | ----> | Local AP Trust Server | ----> | Local JSON Files  |
| Chrome MV3        |       | http://localhost:3000 |       | data/*.json       |
+-------------------+       +-----------------------+       +-------------------+
        |                            |
        |                            v
        |                   +----------------+
        |                   | Rule Engine    |
        |                   +----------------+
```

### Local server (`server/`)

- Node.js 18+, Express, TypeScript.
- Run via `tsx` (no build step required during dev).
- Loads/saves data lazily on each request so admin edits become visible
  without a server restart.

### Browser extension (`extension/`)

- Chrome Manifest V3.
- Calls only `http://localhost:3000/*`.
- No content scripts, no history collection (FR-EXT-009).

### Local data (`data/`)

- `records.json` \u2014 organization records and policy flags.
- `manifests.json` \u2014 local AP Trust manifests keyed by canonical domain.
- `rules.json` \u2014 rule definitions for the engine.

### Admin UI (`server/public/admin/`)

- Vanilla HTML/CSS/JS (no build step).
- Talks to the same server via `/admin/data` and the SRS save endpoints.

## Module map (server)

| File | Responsibility |
| ---- | -------------- |
| `src/index.ts` | Boots Express, listens on the configured port. |
| `src/app.ts` | Wires routers and the static admin UI. |
| `src/routes/public.ts` | `/health`, `/search`, `/entry/:domain`, `/manifest/:domain`, `/rules`, `/verify`. |
| `src/routes/admin.ts` | `/admin/data`, `/admin/save-records`, `/admin/save-manifests`, `/admin/save-rules`. |
| `src/data.ts` | Reads/writes JSON files atomically and validates payloads. |
| `src/normalize.ts` | URL/host normalization helpers. |
| `src/engine/engine.ts` | Rule engine entry point with the SRS priority order. |
| `src/engine/lookalike.ts` | Levenshtein, repeated-character, brand-keyword, and punycode detection. |
| `src/engine/relationships.ts` | Bidirectional and unidirectional verification helpers. |

## Verification flow

The rule engine implements the priority order from SRS section 5.3:

1. Normalize URL and selected boundary.
2. Verify the selected boundary exists in `records.json`.
3. Load the boundary manifest from `manifests.json`.
4. Reject if the boundary is `disabled`.
5. **Suspicious unidirectional claim detection** (runs before everything else
   to prevent fake boundaries from self-validating).
6. Suspicious lookalike detection.
7. Exact boundary match.
8. `officialDomains` match.
9. `relatedOrganizations` / `parentOrganization` match (with reciprocity).
10. `socialProfiles` exact match.
11. `NAMESERVER_ALLOWLIST` metadata (disabled by default; never produces
    `OFFICIAL`).
12. Default deny \u2192 `OUT_OF_BOUNDARY`.

## Trust philosophy

- **Default deny.** Unknown domains are not trusted (SEC-001).
- **No blind self-trust.** A boundary cannot trust itself just because it
  claims another organization\u2019s assets (SEC-002).
- **Bidirectional verification.** Important relationships should be declared
  by both sides (SEC-003).
- **Suspicious unidirectional claims are flagged**, not silently allowed
  (SEC-004).
- **Lookalikes are flagged.** Typo, repeated-character, punycode, and
  brand-keyword squats are surfaced as suspicious (SEC-005).
- **Nameserver metadata is cautious.** It can never produce `OFFICIAL`
  by itself (SEC-006).

## Future production roadmap

See `docs/future-production-roadmap.md` for items that are explicitly out of
scope for this POC.

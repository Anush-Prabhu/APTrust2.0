# AP Trust \u2014 Future Production Roadmap

The local POC deliberately avoids real-world infrastructure so Cursor AI can
build it phase by phase. The items below are documented but **must not be
implemented** in this version.

## Trust pipeline

1. Real DNS TXT record lookup for `_aptrust.<domain>`.
2. Real nameserver lookup for ownership signals.
3. Hosted JSON-LD manifests on the canonical domain.
4. Manifest hash verification (sha256, signed manifests).
5. Public AP Trust registry of canonical records.
6. Organization-controlled publishing workflow with change approvals.

## Operations and security

7. Admin authentication and authorization.
8. Role-based access control.
9. Comprehensive audit logging for every change.
10. Cloud deployment with multi-tenant management.
11. Threat-intelligence feeds and certificate-transparency integration.
12. SIEM/SOAR webhooks and platform takedown integrations.

## Browser-side enrichment

13. Redirect-chain verification (catch suspicious redirects between trusted
    and untrusted domains).
14. Page-link scanning when a page is on a webmail host or composer.
15. Reporting flow that talks to the manifest's declared `reportContact`.

## Out of scope (POC)

The current local POC explicitly does not perform any of the items above.
The seed data, rule engine, and extension all assume the local server is the
single source of truth.

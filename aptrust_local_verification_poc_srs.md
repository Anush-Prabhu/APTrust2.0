# Software Requirements Specification

# AP Trust Local Verification POC

**Version:** 2.0  
**Status:** Final local POC specification for Cursor AI implementation  
**Project Type:** Production-grade local proof of concept  
**Primary Goal:** Demonstrate machine-readable trust-boundary verification using local records, local manifests, local rules, browser extension verification, editable admin data, bidirectional relationship checks, and suspicious impersonation detection.

---

## 1. Introduction

### 1.1 Purpose

This Software Requirements Specification defines the complete requirements for the AP Trust Local Verification POC.

The purpose of the system is to demonstrate how an organization can declare its official digital assets in a structured local manifest, and how a browser extension can verify whether a visited website, social profile, or related organizational domain is inside or outside that declared trust boundary.

The system shall run fully locally. It shall not use real DNS lookup, hosted manifests, hash verification, remote API calls, or cloud services in this version.

This SRS is written so that Cursor AI can implement the system in controlled phases without overbuilding or mixing future production features into the local POC.

---

### 1.2 Product Vision

AP Trust is a trust-boundary verification framework.

Organizations publish structured declarations of their official digital assets, including:

- Primary domains
- Alias domains
- Related organizations
- Related domains
- Social media profiles
- Rule-based trust policies
- Optional weak signals such as nameserver allowlist metadata

A browser extension, security tool, AI agent, platform, or defender can use those declarations to verify whether a visited asset is official, related, social-verified, suspicious, or outside the declared boundary.

The POC demonstrates this core idea:

> Instead of asking only whether a site is known to be malicious, AP Trust asks whether the site is officially declared as legitimate within a selected trust boundary.

The POC also demonstrates that self-attestation alone is not enough. A fake or copied record must not automatically become trusted. Important relationships must be checked using bidirectional verification where possible.

---

### 1.3 Intended Audience

This document is intended for:

- Cursor AI or coding agents implementing the POC
- Developers maintaining the AP Trust prototype
- Professors, judges, reviewers, or investors evaluating the project
- Cybersecurity stakeholders reviewing the verification logic
- Product stakeholders reviewing demo readiness

---

### 1.4 Scope

The system shall include:

1. A local Node.js/Express/TypeScript server
2. Local JSON records, manifests, and rules
3. A local rule engine
4. A Chrome Manifest V3 browser extension
5. A local admin interface for editing records, manifests, and rules
6. A local verification tester
7. Bidirectional verification logic
8. Suspicious lookalike detection
9. Suspicious unidirectional claim detection
10. Nameserver allowlist metadata that is disabled by default
11. Demo records for JHU, Johns Hopkins Medicine, and a suspicious fake `jhuu.edu` example

---

### 1.5 Out of Scope

The following features shall not be implemented in this local POC:

- Real DNS TXT lookup
- Real nameserver lookup
- Hosted GitHub manifests
- Remote manifest fetching
- Hash verification
- Digital signatures
- Public registry
- Database integration
- Authentication
- Role-based access control
- Production audit logging
- Cloud deployment
- Enterprise tenant management
- Real-time phishing feed integration
- Website crawling
- Automated ownership verification
- SIEM/SOAR integrations
- Platform takedown workflows
- Browser history collection

These may be documented as future production features, but Cursor must not implement them in this version.

---

## 2. Overall Description

### 2.1 Product Perspective

The AP Trust Local Verification POC is a local simulation of a future production trust-verification system.

In a future production version, AP Trust declarations may be published through DNS TXT records, hosted JSON-LD manifests, signed manifests, public registries, or organization-controlled publishing workflows.

In this POC, all data is stored locally in JSON files. This keeps the demo simple, controlled, explainable, and safe to build with Cursor AI.

---

### 2.2 System Overview

The system has four main parts:

```text
aptrust-poc/
│
├── server/        Local API server, rule engine, and admin UI host
├── extension/     Chrome browser extension
├── data/          Local JSON records, manifests, and rules
├── docs/          Architecture, demo script, and future roadmap
└── README.md      Setup and usage guide
```

The local server is the source of truth for the POC. The browser extension talks only to the local server. The admin UI edits local JSON data. The rule engine classifies URLs against selected trust boundaries.

---

### 2.3 Product Functions

The system shall provide these high-level functions:

1. Search for a trust boundary
2. Select a trust boundary
3. Verify the current browser tab URL
4. Verify a manually entered URL
5. Classify URLs as official, related, social-verified, suspicious, unknown, or out of boundary
6. Detect suspicious lookalike domains
7. Detect suspicious unidirectional claims
8. Detect bidirectional organization relationships
9. Support editable local AP Trust records
10. Support editable local manifests
11. Support editable local rules
12. Support nameserver allowlist metadata, disabled by default
13. Provide a local admin verification tester
14. Provide a demo-ready UI and explanation flow

---

### 2.4 User Classes

#### 2.4.1 Browser User

A person using the extension to check whether a current website or entered URL belongs to a selected trust boundary.

The browser user can:

- Turn Protect Mode on or off
- Search for a trust boundary
- Select a trust boundary
- Verify the current tab URL
- Manually verify a URL
- View trust status, status code, relationship, and reasons

#### 2.4.2 Local Admin / Demo Operator

A person managing the local AP Trust POC data.

The admin can:

- View and edit organizations
- View and edit manifests
- View and edit rules
- Toggle rules on and off
- Test verification outcomes
- Save changes to local JSON files

#### 2.4.3 Developer

A person extending or maintaining the system.

The developer can:

- Add new rule types
- Add new demo records
- Modify rule engine logic
- Run tests
- Improve extension UI
- Improve admin UI

---

### 2.5 Operating Environment

The POC shall run locally on a developer machine.

Expected environment:

- Windows, macOS, or Linux
- Node.js installed
- Chrome or Chromium-based browser
- Cursor AI or VS Code
- Local server running at `http://localhost:3000`

Recommended stack:

- Node.js
- Express
- TypeScript
- React or simple server-rendered UI for admin
- Chrome Manifest V3
- Local JSON files
- Vitest or Jest for tests

---

### 2.6 Design Constraints

The system must follow these constraints:

1. Everything must run locally.
2. No real DNS lookup shall be performed.
3. No real nameserver lookup shall be performed.
4. No GitHub manifest fetching shall be performed.
5. No hash verification shall be performed.
6. Unknown domains must not be trusted by default.
7. Nameserver allowlist metadata must be disabled by default.
8. Nameserver allowlist metadata must never classify a domain as `OFFICIAL` by itself.
9. Records, manifests, rules, and rule engine logic must remain separate.
10. JHU-specific logic must not be hardcoded into the engine.
11. The browser extension must not collect browsing history.
12. The extension must only send the current tab URL or manually entered URL to the local server.
13. The system must be simple enough for Cursor AI to build phase by phase.

---

### 2.7 Assumptions

The POC assumes:

- The local server is trusted during the demo.
- Local JSON files represent the local AP Trust source of truth.
- The admin UI is local-only and does not need authentication in this POC.
- The demo operator starts the local server before using the extension.
- Fake domains may not resolve online; manual URL verification must still allow demoing them.
- Production security controls are documented but not implemented.

---

## 3. Architecture

### 3.1 High-Level Architecture

```text
+-------------------+        +----------------------+        +-------------------+
| Browser Extension | -----> | Local AP Trust Server | -----> | Local JSON Files  |
| Chrome MV3        |        | http://localhost:3000 |        | records/manifests |
+-------------------+        +----------------------+        +-------------------+
        |                              |
        |                              v
        |                     +----------------+
        |                     | Rule Engine    |
        |                     +----------------+
        |
        v
+-------------------+
| Current Tab URL   |
| Manual URL Input  |
+-------------------+
```

---

### 3.2 Component Breakdown

#### 3.2.1 Local Server

The local server shall:

- Serve API endpoints
- Load local JSON data
- Save local JSON data from admin edits
- Run the verification rule engine
- Serve the local admin UI
- Return clear errors when data or input is invalid

#### 3.2.2 Browser Extension

The browser extension shall:

- Provide a popup UI
- Provide Protect Mode toggle
- Search for trust boundaries
- Store selected trust boundary locally
- Verify current tab URL
- Verify manually entered URL
- Display status, status code, relationship, and reasons
- Show local server unavailable state if `localhost:3000` is unreachable

#### 3.2.3 Local Data Store

The local data store shall use JSON files:

```text
data/records.json
data/manifests.json
data/rules.json
```

Optional:

```text
data/verification-results.json
```

The optional verification-results file must not become a browsing history log. It may only store manually triggered test results if explicitly implemented.

#### 3.2.4 Admin UI

The admin UI shall:

- Run at `http://localhost:3000/admin`
- Display records, manifests, and rules
- Allow edits
- Save changes to local JSON files
- Include a verification tester
- Show warnings about default deny and disabled nameserver allowlist

#### 3.2.5 Rule Engine

The rule engine shall:

- Normalize URLs
- Extract hostname and profile path
- Load selected boundary record and manifest
- Apply rule priority order
- Detect official domains
- Detect related domains
- Detect social profiles
- Detect bidirectional relationships
- Detect suspicious unidirectional claims
- Detect lookalikes
- Apply default deny

---

## 4. Data Model

### 4.1 Design Principle

For this local POC, the manifest data model shall use clear fields instead of overloading `sameAsDomain`.

The local POC shall use:

```text
officialDomains
relatedOrganizations
socialProfiles
parentOrganization
```

This avoids ambiguity between domains that are official assets of the same organization and domains that are only related through another organization.

Future production versions may map these fields into JSON-LD or schema.org-style terms.

---

### 4.2 `records.json`

#### Purpose

Stores organization-level records and policies.

#### Required Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `canonicalDomain` | string | Yes | Main domain used as boundary key |
| `displayName` | string | Yes | Human-readable organization name |
| `type` | string | Yes | Organization type |
| `status` | string | Yes | `active`, `test`, or `disabled` |
| `manifestKey` | string | Yes | Key used in `manifests.json` |
| `aliases` | string[] | Yes | Search aliases or alternate domains |
| `policy` | object | Yes | Local policy flags |

#### Example

```json
[
  {
    "canonicalDomain": "jhu.edu",
    "displayName": "Johns Hopkins University",
    "type": "CollegeOrUniversity",
    "status": "active",
    "manifestKey": "jhu.edu",
    "aliases": [
      "jh.edu",
      "johnshopkins.edu",
      "Johns Hopkins",
      "Johns Hopkins University"
    ],
    "policy": {
      "defaultDecision": "deny",
      "allowNameserverExpansion": false,
      "requireBidirectionalVerification": true
    }
  },
  {
    "canonicalDomain": "hopkinsmedicine.org",
    "displayName": "Johns Hopkins Medicine",
    "type": "MedicalOrganization",
    "status": "active",
    "manifestKey": "hopkinsmedicine.org",
    "aliases": [
      "jhmi.edu",
      "Johns Hopkins Medicine",
      "Hopkins Medicine"
    ],
    "policy": {
      "defaultDecision": "deny",
      "allowNameserverExpansion": false,
      "requireBidirectionalVerification": true
    }
  },
  {
    "canonicalDomain": "jhuu.edu",
    "displayName": "Johns Hopkins University",
    "type": "SuspiciousExample",
    "status": "test",
    "manifestKey": "jhuu.edu",
    "aliases": [
      "fake jhu",
      "suspicious jhu"
    ],
    "policy": {
      "defaultDecision": "deny",
      "allowNameserverExpansion": false,
      "requireBidirectionalVerification": true
    }
  }
]
```

---

### 4.3 `manifests.json`

#### Purpose

Stores local AP Trust declarations.

#### Required Top-Level Fields Per Manifest

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Organization name |
| `url` | string | Yes | Primary URL |
| `officialDomains` | string[] | Yes | Domains that are official assets of the organization |
| `relatedOrganizations` | object[] | No | Declared related organizations |
| `parentOrganization` | object | No | Parent organization declaration |
| `socialProfiles` | string[] | Yes | Declared social profiles |

#### Example

```json
{
  "jhu.edu": {
    "name": "Johns Hopkins University",
    "url": "https://jhu.edu/",
    "officialDomains": [
      "https://jhu.edu/",
      "https://www.jhu.edu/",
      "https://jh.edu/",
      "https://www.jh.edu/",
      "https://johnshopkins.edu/",
      "https://www.johnshopkins.edu/"
    ],
    "relatedOrganizations": [
      {
        "name": "Johns Hopkins Medicine",
        "canonicalDomain": "hopkinsmedicine.org",
        "url": "https://www.hopkinsmedicine.org/",
        "domains": [
          "https://www.hopkinsmedicine.org/",
          "https://www.jhmi.edu/"
        ],
        "relationshipType": "medical-system"
      }
    ],
    "socialProfiles": [
      "https://x.com/JohnsHopkins",
      "https://www.facebook.com/johnshopkinsuniversity",
      "https://www.linkedin.com/school/johns-hopkins-university/",
      "https://www.youtube.com/johnshopkins",
      "https://www.instagram.com/johnshopkinsu"
    ]
  },
  "hopkinsmedicine.org": {
    "name": "Johns Hopkins Medicine",
    "url": "https://www.hopkinsmedicine.org/",
    "officialDomains": [
      "https://www.hopkinsmedicine.org/",
      "https://hopkinsmedicine.org/",
      "https://www.jhmi.edu/",
      "https://jhmi.edu/"
    ],
    "parentOrganization": {
      "name": "Johns Hopkins University",
      "canonicalDomain": "jhu.edu",
      "url": "https://jhu.edu/"
    },
    "relatedOrganizations": [],
    "socialProfiles": [
      "https://www.instagram.com/hopkinsmedicine/",
      "https://x.com/HopkinsMedicine"
    ]
  },
  "jhuu.edu": {
    "name": "Johns Hopkins University",
    "url": "https://jhuu.edu/",
    "officialDomains": [
      "https://jhuu.edu/",
      "https://www.jhuu.edu/"
    ],
    "claimedExternalDomains": [
      "https://jhu.edu/",
      "https://jh.edu/",
      "https://johnshopkins.edu/",
      "https://www.hopkinsmedicine.org/"
    ],
    "relatedOrganizations": [
      {
        "name": "Johns Hopkins University",
        "canonicalDomain": "jhu.edu",
        "url": "https://jhu.edu/",
        "domains": [
          "https://jhu.edu/",
          "https://jh.edu/",
          "https://johnshopkins.edu/"
        ],
        "relationshipType": "claimed-affiliation"
      }
    ],
    "socialProfiles": [
      "https://x.com/JohnsHopkins",
      "https://www.instagram.com/johnshopkinsu"
    ]
  }
}
```

#### Important Rule

The fake `jhuu.edu` record intentionally claims assets that belong to JHU. These claims must not make `jhuu.edu` trusted. The rule engine must classify such claims as suspicious when the real JHU manifest does not reciprocally declare `jhuu.edu`.

---

### 4.4 `rules.json`

#### Purpose

Stores local rule definitions.

#### Supported Rule Types

The system shall support these rule types:

- `DOMAIN_EXACT`
- `OFFICIAL_DOMAIN`
- `RELATED_ORGANIZATION`
- `SOCIAL_PROFILE_EXACT`
- `BIDIRECTIONAL_REQUIRED`
- `UNIDIRECTIONAL_CLAIM_DETECTION`
- `LOOKALIKE_DETECTION`
- `NAMESERVER_ALLOWLIST`
- `DENY_PATTERN`

#### Required Rule Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Unique rule ID |
| `type` | string | Yes | Rule type |
| `enabled` | boolean | Yes | Whether the rule is active |
| `scope` | string | Yes | `global` or specific boundary |
| `effect` | string | Yes | Result or signal produced by rule |
| `priority` | number | Yes | Rule priority |
| `requiresBidirectionalVerification` | boolean | Yes | Whether reciprocal declaration is needed |
| `notes` | string | No | Human-readable explanation |

#### Example

```json
[
  {
    "id": "rule-unidirectional-claim-detection",
    "type": "UNIDIRECTIONAL_CLAIM_DETECTION",
    "enabled": true,
    "scope": "global",
    "effect": "SUSPICIOUS_UNIDIRECTIONAL_CLAIM",
    "priority": 100,
    "requiresBidirectionalVerification": true,
    "notes": "Detects when a boundary claims assets owned by another known AP Trust record without reciprocal confirmation."
  },
  {
    "id": "rule-lookalike-detection",
    "type": "LOOKALIKE_DETECTION",
    "enabled": true,
    "scope": "global",
    "effect": "SUSPICIOUS_LOOKALIKE",
    "priority": 90,
    "requiresBidirectionalVerification": false,
    "notes": "Detects typo, repeated character, punycode, and suspicious keyword lookalikes."
  },
  {
    "id": "rule-domain-exact",
    "type": "DOMAIN_EXACT",
    "enabled": true,
    "scope": "global",
    "effect": "OFFICIAL",
    "priority": 80,
    "requiresBidirectionalVerification": false,
    "notes": "Exact selected boundary match."
  },
  {
    "id": "rule-official-domain",
    "type": "OFFICIAL_DOMAIN",
    "enabled": true,
    "scope": "global",
    "effect": "OFFICIAL",
    "priority": 70,
    "requiresBidirectionalVerification": false,
    "notes": "Matches domains listed in officialDomains."
  },
  {
    "id": "rule-related-organization",
    "type": "RELATED_ORGANIZATION",
    "enabled": true,
    "scope": "global",
    "effect": "RELATED",
    "priority": 60,
    "requiresBidirectionalVerification": true,
    "notes": "Matches declared related organizations and checks reciprocal relationship where available."
  },
  {
    "id": "rule-social-exact",
    "type": "SOCIAL_PROFILE_EXACT",
    "enabled": true,
    "scope": "global",
    "effect": "SOCIAL_VERIFIED",
    "priority": 50,
    "requiresBidirectionalVerification": false,
    "notes": "Exact declared social profile match."
  },
  {
    "id": "ns-jhu-local-test",
    "type": "NAMESERVER_ALLOWLIST",
    "enabled": false,
    "scope": "jhu.edu",
    "nameservers": [
      "ns1.jhu.edu",
      "ns2.jhu.edu"
    ],
    "effect": "RELATED_CANDIDATE",
    "priority": 20,
    "requiresBidirectionalVerification": true,
    "notes": "Disabled by default. Simulated metadata only. No live NS lookup. Nameserver match does not make a domain official."
  }
]
```

---

## 5. Verification Model

### 5.1 Supported Statuses

| Status | Meaning |
|---|---|
| `OFFICIAL` | URL belongs to selected boundary or its official domains. |
| `RELATED` | URL belongs to a declared related organization or related domain. |
| `SOCIAL_VERIFIED` | URL exactly matches a declared social profile. |
| `RELATED_CANDIDATE` | URL matched a weak candidate rule only, such as nameserver metadata. |
| `OUT_OF_BOUNDARY` | URL is not declared inside the selected trust boundary. |
| `SUSPICIOUS_LOOKALIKE` | URL looks similar to a trusted domain but is not declared. |
| `SUSPICIOUS_UNIDIRECTIONAL_CLAIM` | Boundary claims another known organization’s assets without reciprocal confirmation. |
| `UNKNOWN` | System cannot classify the URL due to invalid or incomplete data. |

---

### 5.2 Relationship Types

| Relationship | Meaning |
|---|---|
| `SELF_VERIFIED` | Target is the selected boundary itself. |
| `OFFICIAL_DOMAIN_DECLARED` | Target is listed in selected boundary’s `officialDomains`. |
| `PARENT_CHILD_DECLARED` | Target is linked through parent/child organization declaration. |
| `BIDIRECTIONAL_VERIFIED` | Both sides declare each other. |
| `UNIDIRECTIONAL_CLAIM` | Only one side declares the relationship. |
| `SOCIAL_PROFILE_DECLARED` | Target matches a declared social profile. |
| `LOOKALIKE_DETECTED` | Target resembles a trusted domain but is not declared. |
| `NO_RELATIONSHIP_FOUND` | No valid relationship exists. |

---

### 5.3 Rule Priority Order

The rule engine must apply logic in the following order.

This order is required to prevent fake manifests from becoming self-validating.

```text
1. Normalize URL and selected boundary.
2. Verify selected boundary exists in records.json.
3. Load selected boundary manifest.
4. Check whether selected boundary is disabled.
5. Check suspicious unidirectional claims.
6. Check suspicious lookalike detection.
7. Check exact boundary match.
8. Check officialDomains match.
9. Check relatedOrganizations match.
10. Check socialProfiles match.
11. Check nameserver allowlist metadata if enabled.
12. Apply default deny / OUT_OF_BOUNDARY.
```

#### Critical Requirement

If a selected boundary claims domains that belong to another known AP Trust record, and the other known record does not reciprocally declare the selected boundary, the result must be `SUSPICIOUS_UNIDIRECTIONAL_CLAIM`, even if the claimed domain appears inside the selected boundary’s local manifest.

This requirement is mandatory for the `jhuu.edu` test case.

---

### 5.4 Status Code Model

The system shall return a simple numeric status code from 0 to 100.

| Condition | Suggested status code |
|---|---:|
| Exact selected boundary match | 95 |
| Official domain declared | 90 |
| Bidirectionally verified related organization | 85 |
| Declared social profile | 80 |
| Related organization without full reciprocal proof | 65 |
| Related candidate only | 55 |
| Unknown / out of boundary | 35 |
| Suspicious lookalike | 15 |
| Suspicious unidirectional claim | 10 |
| Invalid input or disabled boundary | 0 |

The status code is for demo clarity. It does not need to be a mathematically perfect risk score.

---

## 6. Functional Requirements

## 6.1 Local Server Requirements

### FR-SRV-001: Health Check

The server shall provide a health endpoint.

**Endpoint:** `GET /health`

**Response Example:**

```json
{
  "status": "ok",
  "service": "aptrust-local-server",
  "version": "2.0.0"
}
```

**Acceptance Criteria:**

- Returns HTTP 200 when server is running.
- Includes service name and version.

---

### FR-SRV-002: Search Trust Boundaries

The server shall allow searching records by keyword.

**Endpoint:** `GET /search?q=jhu`

**Search Fields:**

- `canonicalDomain`
- `displayName`
- `aliases`
- `type`

**Response Example:**

```json
[
  {
    "canonicalDomain": "jhu.edu",
    "displayName": "Johns Hopkins University",
    "type": "CollegeOrUniversity",
    "aliases": ["jh.edu", "johnshopkins.edu"],
    "status": "active"
  }
]
```

**Acceptance Criteria:**

- Searching `jhu` returns `jhu.edu` and `jhuu.edu`.
- Searching `medicine` returns `hopkinsmedicine.org`.
- Empty query returns a controlled list of records.
- Disabled records are either excluded or clearly marked as disabled.

---

### FR-SRV-003: Get Organization Entry

The server shall return one organization record.

**Endpoint:** `GET /entry/:domain`

**Example:** `GET /entry/jhu.edu`

**Acceptance Criteria:**

- Known domain returns HTTP 200.
- Unknown domain returns HTTP 404.
- Entry includes policy information.

---

### FR-SRV-004: Get Manifest

The server shall return one local manifest.

**Endpoint:** `GET /manifest/:domain`

**Acceptance Criteria:**

- Known manifest returns HTTP 200.
- Unknown manifest returns HTTP 404.
- Manifest data comes from `data/manifests.json`.

---

### FR-SRV-005: Get Rules

The server shall return local rules.

**Endpoint:** `GET /rules`

**Acceptance Criteria:**

- Returns all rules.
- Disabled rules are included with `enabled: false`.
- Nameserver allowlist rule is present and disabled by default.

---

### FR-SRV-006: Verify URL

The server shall verify a URL against a selected boundary.

**Endpoint:** `POST /verify`

**Request Example:**

```json
{
  "boundary": "jhu.edu",
  "url": "https://www.hopkinsmedicine.org/"
}
```

**Response Example:**

```json
{
  "boundary": "jhu.edu",
  "url": "https://www.hopkinsmedicine.org/",
  "normalizedDomain": "hopkinsmedicine.org",
  "status": "RELATED",
  "statusCode": 85,
  "relationship": "BIDIRECTIONAL_VERIFIED",
  "reasons": [
    "Target domain is declared as related by jhu.edu.",
    "Target organization declares jhu.edu as parent organization.",
    "Relationship is bidirectionally verified."
  ]
}
```

**Acceptance Criteria:**

- `jhu.edu` under boundary `jhu.edu` returns `OFFICIAL`.
- `johnshopkins.edu` under boundary `jhu.edu` returns `OFFICIAL`.
- `hopkinsmedicine.org` under boundary `jhu.edu` returns `RELATED` with bidirectional relationship.
- `jhmi.edu` under boundary `hopkinsmedicine.org` returns `OFFICIAL`.
- `jhmi.edu` under boundary `jhu.edu` returns `RELATED`.
- `instagram.com/hopkinsmedicine` under boundary `hopkinsmedicine.org` returns `SOCIAL_VERIFIED`.
- `x.com/HopkinsMedicine` under boundary `hopkinsmedicine.org` returns `SOCIAL_VERIFIED`.
- `jhuu.edu` under boundary `jhu.edu` returns `SUSPICIOUS_LOOKALIKE`.
- `jhu.edu` under boundary `jhuu.edu` returns `SUSPICIOUS_UNIDIRECTIONAL_CLAIM`.
- Unknown unrelated domains return `OUT_OF_BOUNDARY`.

---

### FR-SRV-007: Get Admin Data

The server shall return all editable local data for the admin UI.

**Endpoint:** `GET /admin/data`

**Response Fields:**

- `records`
- `manifests`
- `rules`

**Acceptance Criteria:**

- Admin UI can load all local data through one endpoint.
- Server handles missing files safely.

---

### FR-SRV-008: Save Records

The server shall save edited records.

**Endpoint:** `POST /admin/save-records`

**Acceptance Criteria:**

- Valid records are saved to `data/records.json`.
- Invalid records are rejected with clear errors.
- Existing JSON is not corrupted on failed save.

---

### FR-SRV-009: Save Manifests

The server shall save edited manifests.

**Endpoint:** `POST /admin/save-manifests`

**Acceptance Criteria:**

- Valid manifests are saved to `data/manifests.json`.
- Invalid manifests are rejected with clear errors.
- Existing JSON is not corrupted on failed save.

---

### FR-SRV-010: Save Rules

The server shall save edited rules.

**Endpoint:** `POST /admin/save-rules`

**Acceptance Criteria:**

- Valid rules are saved to `data/rules.json`.
- Invalid rules are rejected with clear errors.
- Nameserver rule may be toggled but remains disabled by default in seed data.

---

## 6.2 Rule Engine Requirements

### FR-RULE-001: URL Normalization

The rule engine shall normalize URLs before comparison.

**Normalization Steps:**

- Lowercase hostname
- Strip protocol for domain comparison
- Strip `www.` where appropriate
- Remove trailing slash where appropriate
- Extract hostname from full URL
- Preserve social media path for profile matching
- Detect punycode prefix `xn--`

**Acceptance Criteria:**

- `https://www.jhu.edu/` and `https://jhu.edu` match correctly.
- `https://www.instagram.com/hopkinsmedicine/` matches the declared profile.
- Malformed URLs return controlled error or `UNKNOWN`.

---

### FR-RULE-002: Selected Boundary Validation

The rule engine shall validate the selected boundary before checking the target URL.

**Acceptance Criteria:**

- Unknown boundary returns `UNKNOWN` or clear 404-style verification error.
- Disabled boundary returns status `UNKNOWN` or `DISABLED_BOUNDARY` if implemented.
- Rule engine does not crash on missing boundary.

---

### FR-RULE-003: Suspicious Unidirectional Claim Detection

The rule engine shall detect when a selected boundary claims assets owned by another known AP Trust record without reciprocal confirmation.

**Mandatory Behavior:**

If selected boundary `A` claims known organization `B`, but organization `B` does not declare `A`, then verification involving the claimed relationship must return:

```text
SUSPICIOUS_UNIDIRECTIONAL_CLAIM
```

**Example:**

Boundary: `jhuu.edu`  
URL: `https://jhu.edu/`  
Expected: `SUSPICIOUS_UNIDIRECTIONAL_CLAIM`

**Acceptance Criteria:**

- This check runs before official-domain or related-domain approval.
- `jhuu.edu` cannot self-validate by claiming JHU assets.
- Reasons explain that the claim is not reciprocally confirmed.

---

### FR-RULE-004: Suspicious Lookalike Detection

The rule engine shall detect suspicious lookalike domains.

**Detection Methods:**

- Levenshtein distance
- Repeated character detection
- Trusted brand/domain string with suspicious keywords
- Punycode prefix `xn--`
- Similarity to official or related domains

**Suspicious Keywords:**

- `login`
- `verify`
- `security`
- `account`
- `support`
- `auth`
- `portal`

**Examples:**

- `jhuu.edu`
- `jhu-login-security.com`
- `johnshopklns.edu`
- `xn--jhu-example.com`

**Acceptance Criteria:**

- `jhuu.edu` under `jhu.edu` returns `SUSPICIOUS_LOOKALIKE`.
- Suspicious keyword domains are flagged.
- Punycode domains are flagged for this POC.

---

### FR-RULE-005: Exact Boundary Match

If the target domain exactly matches the selected boundary, classify as `OFFICIAL`.

**Example:**

Boundary: `jhu.edu`  
URL: `https://jhu.edu/`  
Status: `OFFICIAL`

---

### FR-RULE-006: Official Domain Match

If the target domain is listed in the selected boundary manifest’s `officialDomains`, classify as `OFFICIAL`.

**Example:**

Boundary: `jhu.edu`  
URL: `https://johnshopkins.edu/`  
Status: `OFFICIAL`

**Acceptance Criteria:**

- `www.` variations match correctly.
- Official domain match only applies to `officialDomains`, not arbitrary external claims.

---

### FR-RULE-007: Related Organization Match

If the target domain is listed under `relatedOrganizations`, classify as `RELATED`.

**Bidirectional Behavior:**

- If the related organization also declares the selected boundary as parent or related, relationship is `BIDIRECTIONAL_VERIFIED`.
- If not, relationship is `UNIDIRECTIONAL_CLAIM` or lower-confidence related, depending on context.
- If the selected boundary itself is suspicious or the claim is to a known high-value organization without reciprocity, classify as `SUSPICIOUS_UNIDIRECTIONAL_CLAIM`.

**Acceptance Criteria:**

- `hopkinsmedicine.org` under `jhu.edu` returns `RELATED` and `BIDIRECTIONAL_VERIFIED`.
- `jhmi.edu` under `jhu.edu` returns `RELATED` through Hopkins Medicine.
- `jhu.edu` under `jhuu.edu` returns `SUSPICIOUS_UNIDIRECTIONAL_CLAIM`.

---

### FR-RULE-008: Social Profile Match

If the target URL exactly matches a declared social profile, classify as `SOCIAL_VERIFIED`.

**Examples:**

Boundary: `hopkinsmedicine.org`  
URL: `https://www.instagram.com/hopkinsmedicine/`  
Status: `SOCIAL_VERIFIED`

Boundary: `hopkinsmedicine.org`  
URL: `https://x.com/HopkinsMedicine`  
Status: `SOCIAL_VERIFIED`

**Acceptance Criteria:**

- Exact social URL/profile path is required.
- Generic platform domain such as `instagram.com` alone is not trusted.
- Unlisted social profile is not trusted.

---

### FR-RULE-009: Nameserver Allowlist Metadata

The rule engine shall support nameserver allowlist rules as local metadata only.

**Important Constraints:**

- The system must not perform live DNS or NS queries.
- Nameserver rules are manually configured in `rules.json`.
- Nameserver rules are disabled by default.
- If enabled, a nameserver rule may only produce `RELATED_CANDIDATE` by itself.
- Nameserver metadata must never classify a domain as `OFFICIAL` by itself.

**Acceptance Criteria:**

- Nameserver rule exists in seed data.
- Nameserver rule is disabled by default.
- Admin can toggle it.
- Enabling it does not make any domain official.

---

### FR-RULE-010: Default Deny

Unknown domains shall be classified as `OUT_OF_BOUNDARY` by default.

**Acceptance Criteria:**

- Unknown unrelated domain is not trusted.
- Response explains the domain is not declared.
- Default policy is deny.

---

### FR-RULE-011: Rule Extensibility

The rule engine shall be modular enough to add new rule types.

**Acceptance Criteria:**

- Rule types are represented by constants or enums.
- Rule handlers are separated logically.
- Unsupported rule types are ignored safely or reported as warnings.
- Adding a new rule type does not require rewriting the entire engine.

---

## 6.3 Browser Extension Requirements

### FR-EXT-001: Extension Platform

The browser extension shall use Chrome Manifest V3.

**Acceptance Criteria:**

- Extension can be loaded unpacked in Chrome.
- Extension has a popup UI.
- Extension connects only to `http://localhost:3000`.

---

### FR-EXT-002: Protect Mode Toggle

The extension shall provide a Protect Mode toggle.

**Behavior:**

- When off, the extension does not automatically verify the current tab.
- When on, the extension verifies the current active tab using the selected boundary.

**Acceptance Criteria:**

- Toggle state is saved in extension local storage.
- UI clearly shows Protect Mode status.

---

### FR-EXT-003: Trust Boundary Search

The extension shall let users search for a trust boundary.

**Behavior:**

- User enters text such as `jhu`.
- Extension calls `GET /search?q=jhu`.
- Results appear in popup.

**Acceptance Criteria:**

- Search results show display name and canonical domain.
- User can select a result.
- Local server errors are handled gracefully.

---

### FR-EXT-004: Boundary Selection

The extension shall allow selecting one active trust boundary.

**Acceptance Criteria:**

- Selected boundary is stored in `chrome.storage.local`.
- Popup displays selected boundary.
- Selected boundary persists after popup closes.

---

### FR-EXT-005: Current Tab Verification

The extension shall verify the active tab URL.

**Behavior:**

- Extension reads current active tab URL.
- Extension sends selected boundary and current URL to `POST /verify`.
- Extension displays returned result.

**Acceptance Criteria:**

- Current URL appears in popup.
- Status, status code, relationship, and reasons appear clearly.
- Works with `jhu.edu`, `hopkinsmedicine.org`, and other demo URLs.

---

### FR-EXT-006: Manual URL Verification

The extension shall support manual URL verification.

**Behavior:**

- User enters a URL.
- Extension calls `POST /verify`.
- Result appears in popup.

**Acceptance Criteria:**

- Allows testing fake URLs such as `https://jhuu.edu/` even if the domain is not live.
- Allows testing `https://jhu-login-security.com/`.

---

### FR-EXT-007: Display Trust Result

The extension shall display:

- Selected boundary
- Checked URL
- Status
- Rating
- Relationship
- Reasons

**Acceptance Criteria:**

- Suspicious statuses are visually distinct.
- Reasons are readable and not overly technical.
- Result does not require opening developer tools.

---

### FR-EXT-008: Local Server Unavailable State

The extension shall detect when `localhost:3000` is unavailable.

**Required Message:**

```text
Local AP Trust server unavailable. Start the local server and try again.
```

**Acceptance Criteria:**

- Extension does not fail silently.
- User receives clear guidance.
- No remote fallback is attempted.

---

### FR-EXT-009: Privacy Constraint

The extension shall not collect browsing history.

**Acceptance Criteria:**

- Extension only checks current active tab or manually entered URL.
- Extension does not store a history of visited URLs.
- Extension does not call remote APIs.
- Permissions are minimal.

---

## 6.4 Admin UI Requirements

### FR-ADM-001: Admin UI Availability

The local server shall serve an admin UI at:

```text
http://localhost:3000/admin
```

**Acceptance Criteria:**

- Admin UI loads locally.
- Admin UI shows system status.
- Admin UI does not require login in this POC.

---

### FR-ADM-002: Dashboard

The admin dashboard shall show:

- Server status
- Number of records
- Number of manifests
- Number of rules
- Default deny warning
- Nameserver allowlist warning

**Required Warning Text:**

```text
Default policy is DENY. Unknown domains are not trusted.
```

```text
Nameserver allowlist is disabled by default and can only produce RELATED_CANDIDATE, not OFFICIAL.
```

---

### FR-ADM-003: View Organizations

The admin UI shall display organization records.

**Fields:**

- Canonical domain
- Display name
- Type
- Status
- Manifest key
- Aliases
- Policy

**Acceptance Criteria:**

- `jhu.edu`, `hopkinsmedicine.org`, and `jhuu.edu` are visible.
- Status values are visible.

---

### FR-ADM-004: Add/Edit Organizations

The admin UI shall allow adding and editing organization records.

**Editable Fields:**

- Canonical domain
- Display name
- Type
- Status
- Manifest key
- Aliases
- Policy values

**Acceptance Criteria:**

- Admin can edit existing records.
- Admin can add a new record.
- Save writes to `records.json` through `POST /admin/save-records`.

---

### FR-ADM-005: View/Edit Manifests

The admin UI shall allow viewing and editing manifests.

**Editable Fields:**

- Name
- URL
- Official domains
- Related organizations
- Parent organization
- Social profiles
- Claimed external domains, if present

**Acceptance Criteria:**

- Admin can add/remove official domains.
- Admin can add/remove related organizations.
- Admin can add/remove social profiles.
- Save writes to `manifests.json` through `POST /admin/save-manifests`.

---

### FR-ADM-006: View/Edit Rules

The admin UI shall allow viewing and editing rules.

**Editable Fields:**

- ID
- Type
- Enabled
- Scope
- Effect
- Priority
- Requires bidirectional verification
- Notes

**Acceptance Criteria:**

- Admin can toggle rules.
- Admin can toggle nameserver allowlist rule.
- Admin can save rules through `POST /admin/save-rules`.

---

### FR-ADM-007: Verification Tester

The admin UI shall include a verification tester.

**Behavior:**

- Admin selects boundary.
- Admin enters URL.
- UI calls `POST /verify`.
- Result displays status, status code, relationship, and reasons.

**Acceptance Criteria:**

- Admin can test all demo cases from the SRS.
- Results match browser extension behavior.

---

### FR-ADM-008: Admin POC Limitation Notice

The admin UI shall display a note that this is a local POC.

**Required Message:**

```text
This admin interface is local-only for the POC. A production version would require authentication, authorization, signed updates, change approvals, and audit logs.
```

---

## 7. API Specification

### 7.1 `GET /health`

Returns local server health.

---

### 7.2 `GET /search?q=`

Searches local records.

Query Parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `q` | string | No | Search keyword |

---

### 7.3 `GET /entry/:domain`

Returns one organization record.

---

### 7.4 `GET /manifest/:domain`

Returns one manifest.

---

### 7.5 `GET /rules`

Returns all rules.

---

### 7.6 `POST /verify`

Verifies a URL against a selected boundary.

Request:

```json
{
  "boundary": "jhu.edu",
  "url": "https://www.hopkinsmedicine.org/"
}
```

Response:

```json
{
  "boundary": "jhu.edu",
  "url": "https://www.hopkinsmedicine.org/",
  "normalizedDomain": "hopkinsmedicine.org",
  "status": "RELATED",
  "statusCode": 85,
  "relationship": "BIDIRECTIONAL_VERIFIED",
  "reasons": [
    "Target domain is declared as a related organization by jhu.edu.",
    "hopkinsmedicine.org declares jhu.edu as parent organization.",
    "The relationship is bidirectionally verified."
  ]
}
```

---

### 7.7 `GET /admin/data`

Returns editable data for admin UI.

Response:

```json
{
  "records": [],
  "manifests": {},
  "rules": []
}
```

---

### 7.8 `POST /admin/save-records`

Saves records.

---

### 7.9 `POST /admin/save-manifests`

Saves manifests.

---

### 7.10 `POST /admin/save-rules`

Saves rules.

---

## 8. User Interface Requirements

### 8.1 Browser Extension Popup Layout

The popup shall include:

1. AP Trust title
2. Local server connection indicator
3. Protect Mode toggle
4. Selected boundary display
5. Boundary search input
6. Search results
7. Current tab URL section
8. Verify current tab button
9. Manual URL input
10. Verify manual URL button
11. Trust status badge
12. Rating display
13. Relationship display
14. Reasons list

---

### 8.2 Admin UI Layout

The admin UI shall include these sections:

1. Dashboard
2. Organizations
3. Manifests
4. Rules
5. Verification Tester

The UI does not need to be visually complex. It must be clear, demo-ready, and easy to use.

---

## 9. Non-Functional Requirements

### NFR-001: Local-Only Operation

The system must run fully locally.

---

### NFR-002: No External Dependencies at Runtime

The browser extension and server must not depend on remote APIs or remote manifests.

---

### NFR-003: Simplicity

The system must remain simple enough for Cursor AI to implement and modify safely.

---

### NFR-004: Maintainability

The system must separate:

- Server routes
- Data access
- Rule engine
- Extension UI
- Admin UI
- Tests

---

### NFR-005: Extensibility

The rule engine must support adding future rule types without a full rewrite.

---

### NFR-006: Privacy

The extension must not collect browsing history or send data to remote services.

---

### NFR-007: Reliability

The system must handle:

- Missing data files
- Invalid JSON
- Unknown domains
- Malformed URLs
- Local server unavailable state
- Disabled records

---

### NFR-008: Performance

Target performance:

- `/verify` under 200 ms for local demo data
- `/search` under 200 ms for local demo data

---

### NFR-009: Usability

The demo user must quickly understand:

- Which boundary is selected
- Which URL is checked
- What status was assigned
- Why that status was assigned

---

### NFR-010: Demo Robustness

The POC must support fake-domain testing through manual URL verification.

---

## 10. Security and Trust Requirements

### SEC-001: Default Deny

Unknown domains must not be trusted.

---

### SEC-002: No Blind Self-Trust

A boundary must not become trusted simply because it claims trusted assets.

---

### SEC-003: Bidirectional Verification

High-value relationships should be reciprocally declared where possible.

---

### SEC-004: Suspicious Unidirectional Claims

A boundary claiming assets owned by another known AP Trust record without reciprocal confirmation must be flagged.

---

### SEC-005: Suspicious Lookalikes

Lookalike, typo, punycode, and suspicious keyword domains must be flagged.

---

### SEC-006: Nameserver Caution

Nameserver allowlist metadata must not classify a site as official by itself.

---

### SEC-007: Admin POC Limitation

The admin UI is local-only and unauthenticated in this POC. Production would require authentication, authorization, signed updates, approvals, and audit logs.

---

## 11. Test Requirements

### 11.1 Server Tests

| Test ID | Scenario | Expected Result |
|---|---|---|
| T-SRV-001 | `GET /health` | HTTP 200 |
| T-SRV-002 | Search `jhu` | Returns `jhu.edu` and `jhuu.edu` |
| T-SRV-003 | Search `medicine` | Returns `hopkinsmedicine.org` |
| T-SRV-004 | Get entry `jhu.edu` | Returns JHU record |
| T-SRV-005 | Get unknown entry | Returns 404 |
| T-SRV-006 | Get manifest `jhu.edu` | Returns JHU manifest |
| T-SRV-007 | Get rules | Returns rules including disabled nameserver rule |
| T-SRV-008 | Get admin data | Returns records, manifests, and rules |

---

### 11.2 Rule Engine Tests

| Test ID | Boundary | URL | Expected Status | Expected Relationship |
|---|---|---|---|---|
| T-RULE-001 | `jhu.edu` | `https://jhu.edu/` | `OFFICIAL` | `SELF_VERIFIED` |
| T-RULE-002 | `jhu.edu` | `https://www.jhu.edu/` | `OFFICIAL` | `OFFICIAL_DOMAIN_DECLARED` |
| T-RULE-003 | `jhu.edu` | `https://johnshopkins.edu/` | `OFFICIAL` | `OFFICIAL_DOMAIN_DECLARED` |
| T-RULE-004 | `jhu.edu` | `https://www.hopkinsmedicine.org/` | `RELATED` | `BIDIRECTIONAL_VERIFIED` |
| T-RULE-005 | `hopkinsmedicine.org` | `https://www.jhmi.edu/` | `OFFICIAL` | `OFFICIAL_DOMAIN_DECLARED` |
| T-RULE-006 | `jhu.edu` | `https://www.jhmi.edu/` | `RELATED` | `BIDIRECTIONAL_VERIFIED` |
| T-RULE-007 | `hopkinsmedicine.org` | `https://www.instagram.com/hopkinsmedicine/` | `SOCIAL_VERIFIED` | `SOCIAL_PROFILE_DECLARED` |
| T-RULE-008 | `hopkinsmedicine.org` | `https://x.com/HopkinsMedicine` | `SOCIAL_VERIFIED` | `SOCIAL_PROFILE_DECLARED` |
| T-RULE-009 | `jhu.edu` | `https://jhuu.edu/` | `SUSPICIOUS_LOOKALIKE` | `LOOKALIKE_DETECTED` |
| T-RULE-010 | `jhuu.edu` | `https://jhu.edu/` | `SUSPICIOUS_UNIDIRECTIONAL_CLAIM` | `UNIDIRECTIONAL_CLAIM` |
| T-RULE-011 | `jhu.edu` | `https://random-example.com/` | `OUT_OF_BOUNDARY` | `NO_RELATIONSHIP_FOUND` |
| T-RULE-012 | `jhu.edu` | `https://xn--jhu-example.com/` | `SUSPICIOUS_LOOKALIKE` | `LOOKALIKE_DETECTED` |
| T-RULE-013 | `jhu.edu` | `https://jhu-login-security.com/` | `SUSPICIOUS_LOOKALIKE` | `LOOKALIKE_DETECTED` |

---

### 11.3 Extension Manual Tests

1. Extension loads unpacked in Chrome.
2. Protect Mode toggle works.
3. Local server unavailable message appears when server is down.
4. Searching `jhu` shows records.
5. Selecting `jhu.edu` saves boundary.
6. Current tab verification works.
7. Manual URL verification works.
8. Suspicious statuses display clearly.
9. Extension does not call remote APIs.

---

### 11.4 Admin UI Manual Tests

1. Admin UI loads at `/admin`.
2. Dashboard shows warnings.
3. Records are displayed.
4. Manifests are displayed.
5. Rules are displayed.
6. Nameserver rule is disabled by default.
7. Admin can edit and save records.
8. Admin can edit and save manifests.
9. Admin can edit and save rules.
10. Verification tester returns expected results.

---

## 12. Demo Requirements

### 12.1 Demo Flow

The final demo shall support this sequence:

#### Step 1: Start Local Server

```text
npm run dev
```

Expected:

```text
AP Trust local server running at http://localhost:3000
```

---

#### Step 2: Open Admin UI

```text
http://localhost:3000/admin
```

Show:

- `jhu.edu` record
- `hopkinsmedicine.org` record
- `jhuu.edu` suspicious test record
- Default deny warning
- Nameserver allowlist disabled warning

---

#### Step 3: Select JHU Boundary

In extension:

```text
Search: jhu
Select: Johns Hopkins University / jhu.edu
```

---

#### Step 4: Verify Official JHU Domain

URL:

```text
https://www.jhu.edu/
```

Expected:

```text
Status: OFFICIAL
Rating: 95
```

---

#### Step 5: Verify Official JHU Alias

URL:

```text
https://johnshopkins.edu/
```

Expected:

```text
Status: OFFICIAL
Rating: 90
```

---

#### Step 6: Verify Related Organization

Boundary:

```text
jhu.edu
```

URL:

```text
https://www.hopkinsmedicine.org/
```

Expected:

```text
Status: RELATED
Relationship: BIDIRECTIONAL_VERIFIED
Rating: 85
```

---

#### Step 7: Verify Hopkins Medicine Official Alias

Boundary:

```text
hopkinsmedicine.org
```

URL:

```text
https://www.jhmi.edu/
```

Expected:

```text
Status: OFFICIAL
Rating: 90
```

---

#### Step 8: Verify Hopkins Medicine Social Profile

Boundary:

```text
hopkinsmedicine.org
```

URL:

```text
https://www.instagram.com/hopkinsmedicine/
```

Expected:

```text
Status: SOCIAL_VERIFIED
Rating: 80
```

---

#### Step 9: Verify Fake Lookalike

Boundary:

```text
jhu.edu
```

URL:

```text
https://jhuu.edu/
```

Expected:

```text
Status: SUSPICIOUS_LOOKALIKE
Rating: 15
```

---

#### Step 10: Select Fake Boundary and Test Claim

Boundary:

```text
jhuu.edu
```

URL:

```text
https://jhu.edu/
```

Expected:

```text
Status: SUSPICIOUS_UNIDIRECTIONAL_CLAIM
Rating: 10
Reason: jhuu.edu claims JHU assets, but JHU does not reciprocally declare jhuu.edu.
```

---

#### Step 11: Show Nameserver Rule

Open admin rules page.

Show:

```text
NAMESERVER_ALLOWLIST: disabled
Effect: RELATED_CANDIDATE only
No live NS lookup
```

Explain:

Nameserver-based trust can be useful as weak metadata, but it is not enough to prove official ownership. Many unrelated domains can share DNS infrastructure. Therefore AP Trust keeps this disabled by default and never uses it alone to mark a domain as official.

---

## 13. Implementation Plan for Cursor AI

Cursor must implement in phases.

### Phase 1: Base Structure and Seed Data

Create:

```text
server/
extension/
data/
docs/
README.md
```

Create:

```text
data/records.json
data/manifests.json
data/rules.json
```

Use the seed data defined in this SRS.

Do not build extension, admin UI, DNS, or hash verification in Phase 1.

---

### Phase 2: Local Server

Implement:

- `GET /health`
- `GET /search?q=`
- `GET /entry/:domain`
- `GET /manifest/:domain`
- `GET /rules`
- `GET /admin/data`

---

### Phase 3: Rule Engine and Verification Endpoint

Implement:

- URL normalization
- Boundary validation
- Suspicious unidirectional claim detection
- Lookalike detection
- Exact boundary match
- Official domain match
- Related organization match
- Social profile match
- Nameserver metadata handling
- Default deny
- `POST /verify`

Add rule engine tests.

---

### Phase 4: Browser Extension

Implement:

- Chrome Manifest V3 extension
- Popup UI
- Protect Mode toggle
- Boundary search
- Boundary selection
- Current tab verification
- Manual URL verification
- Server unavailable message
- Result display

---

### Phase 5: Admin UI

Implement:

- `/admin`
- Dashboard
- Organization editor
- Manifest editor
- Rule editor
- Verification tester
- Save records/manifests/rules endpoints

---

### Phase 6: Tests and Documentation

Implement:

- Server tests
- Rule engine tests
- Manual extension test checklist
- Manual admin UI checklist

Create:

```text
docs/architecture.md
docs/demo-script.md
docs/future-production-roadmap.md
```

---

## 14. Cursor AI Guardrails

Cursor must follow these rules:

1. Do not add real DNS lookup.
2. Do not add real nameserver lookup.
3. Do not add GitHub manifest fetching.
4. Do not add hash verification.
5. Do not add authentication.
6. Do not add database.
7. Do not call remote APIs from extension.
8. Do not hardcode JHU-specific logic into the rule engine.
9. Do not merge records, manifests, and rules into one object.
10. Do not allow `jhuu.edu` to self-validate by claiming JHU assets.
11. Keep nameserver allowlist disabled by default.
12. Keep unknown domains denied by default.
13. Implement one phase at a time.
14. Update README when behavior changes.

---

## 15. Future Production Enhancements

These are future features and must not be implemented now:

1. Real DNS TXT lookup
2. Real nameserver verification
3. Hosted JSON-LD manifests
4. Manifest hash verification
5. Signed manifests
6. Organization-controlled publishing workflow
7. Admin authentication
8. Role-based access control
9. Audit logs
10. Change approval workflow
11. Redirect-chain verification
12. Link scanning on webpages
13. API integration for SIEM/SOAR
14. Threat intelligence enrichment
15. Certificate transparency integration
16. Public AP Trust registry
17. Platform takedown integration
18. Enterprise dashboard
19. Cloud deployment
20. Multi-tenant management

---

## 16. Success Criteria

The POC is successful when:

1. Local server runs successfully.
2. Local JSON data loads successfully.
3. Browser extension loads in Chrome.
4. Extension can select a boundary.
5. Extension can verify current tab and manual URL.
6. JHU official domains are classified correctly.
7. Hopkins Medicine is classified correctly.
8. Hopkins Medicine social profiles are verified.
9. `jhuu.edu` is flagged as a lookalike under `jhu.edu`.
10. `jhuu.edu` claiming JHU assets is flagged as suspicious unidirectional claim.
11. Admin UI can edit records, manifests, and rules.
12. Nameserver allowlist is visible but disabled by default.
13. Unknown domains are denied by default.
14. Demo works without remote infrastructure.

---

## 17. Recommended Cursor Prompt 1

```text
We are building AP Trust Local Verification POC based on the SRS in this project.

Important constraints:
- Everything is local.
- No DNS lookup.
- No nameserver lookup.
- No GitHub manifest fetching.
- No hash verification.
- No authentication.
- Local JSON files are the source of truth.

First inspect the current project structure.
Then create or update only the base folder structure and seed data files:
- server/
- extension/
- data/
- docs/
- data/records.json
- data/manifests.json
- data/rules.json

Use seed data for:
- jhu.edu
- hopkinsmedicine.org
- jhmi.edu through hopkinsmedicine.org
- jhuu.edu as suspicious fake example

Important:
- Use officialDomains, relatedOrganizations, socialProfiles, and parentOrganization fields.
- Do not use sameAsDomain for the local POC.
- Do not build the extension yet.
- Do not build the admin UI yet.
```

---

## 18. Recommended Cursor Prompt 2

```text
Now build the local server only.

Use Node.js, Express, and TypeScript.

Implement:
- GET /health
- GET /search?q=
- GET /entry/:domain
- GET /manifest/:domain
- GET /rules
- GET /admin/data

Load data from local JSON files in the data/ folder.
Add basic validation and clear error responses.
Do not build the extension yet.
Do not build admin UI yet.
```

---

## 19. Recommended Cursor Prompt 3

```text
Now implement the AP Trust rule engine and POST /verify.

The engine must classify URLs as:
- OFFICIAL
- RELATED
- SOCIAL_VERIFIED
- RELATED_CANDIDATE
- OUT_OF_BOUNDARY
- SUSPICIOUS_LOOKALIKE
- SUSPICIOUS_UNIDIRECTIONAL_CLAIM
- UNKNOWN

Mandatory priority order:
1. Normalize URL and selected boundary.
2. Verify selected boundary exists.
3. Load selected boundary manifest.
4. Check whether selected boundary is disabled.
5. Check suspicious unidirectional claims.
6. Check suspicious lookalike detection.
7. Check exact boundary match.
8. Check officialDomains match.
9. Check relatedOrganizations match.
10. Check socialProfiles match.
11. Check nameserver allowlist metadata if enabled.
12. Apply default deny / OUT_OF_BOUNDARY.

Critical case:
- Boundary jhuu.edu verifying https://jhu.edu/ must return SUSPICIOUS_UNIDIRECTIONAL_CLAIM.
- jhuu.edu must not self-validate by claiming JHU assets.

Add tests for all required demo cases.
```

---

## 20. Recommended Cursor Prompt 4

```text
Now build the Chrome browser extension.

Use Manifest V3.
The extension must connect only to http://localhost:3000.

Features:
- Protect Mode toggle
- Trust boundary search
- Boundary selection
- Current tab verification
- Manual URL verification
- Display selected boundary, checked URL, status, status code, relationship, and reasons
- Show "Local AP Trust server unavailable" when localhost:3000 is unavailable

Do not scan browsing history.
Do not call remote APIs.
Keep the UI simple and demo-ready.
```

---

## 21. Recommended Cursor Prompt 5

```text
Now build the local admin UI at /admin.

Features:
- Dashboard
- View/edit organizations
- View/edit manifests
- View/edit rules
- Toggle nameserver allowlist rule
- Save records using POST /admin/save-records
- Save manifests using POST /admin/save-manifests
- Save rules using POST /admin/save-rules
- Add verification tester

Show warnings:
- Default policy is DENY.
- Nameserver allowlist is disabled by default.
- Nameserver metadata only creates RELATED_CANDIDATE, not OFFICIAL.
- This admin UI is local-only for the POC. Production requires authentication, authorization, signed updates, approvals, and audit logs.

Do not add login/auth.
Keep it local-only.
```

---

# End of SRS


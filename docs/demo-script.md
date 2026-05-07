# AP Trust Local Verification POC \u2014 Demo Script

Walk-through that mirrors SRS section 12. All steps run against the local
server at `http://localhost:3000` with the seed data shipped in `data/`.

## Setup

```bash
npm install
npm run dev
```

Expected log line:

```
AP Trust local server running at http://localhost:3000
```

Load the unpacked extension:

1. Open `chrome://extensions`.
2. Enable Developer mode.
3. Click **Load unpacked** and choose the `extension/` folder.

## Step 1 \u2014 Open Admin UI

Visit <http://localhost:3000/admin>.

Show:

- `jhu.edu`, `hopkinsmedicine.org`, and `jhuu.edu` records.
- The default-deny banner.
- The nameserver-allowlist warning.

## Step 2 \u2014 Select the JHU boundary in the extension

Open the extension popup, search `jhu`, then click **Johns Hopkins University
(jhu.edu)**.

## Step 3 \u2014 Verify an official JHU domain

Tab URL: `https://www.jhu.edu/`.
Expected: `OFFICIAL`, status code `90`, relationship `OFFICIAL_DOMAIN_DECLARED`.

## Step 4 \u2014 Verify the canonical domain itself

Manual URL: `https://jhu.edu/`.
Expected: `OFFICIAL`, status code `95`, relationship `SELF_VERIFIED`.

## Step 5 \u2014 Verify an official alias

Manual URL: `https://johnshopkins.edu/`.
Expected: `OFFICIAL`, status code `90`, relationship `OFFICIAL_DOMAIN_DECLARED`.

## Step 6 \u2014 Verify a bidirectionally related organization

Manual URL: `https://www.hopkinsmedicine.org/`.
Expected: `RELATED`, status code `85`, relationship `BIDIRECTIONAL_VERIFIED`.

## Step 7 \u2014 Switch boundary to `hopkinsmedicine.org` and verify `jhmi.edu`

Manual URL: `https://www.jhmi.edu/`.
Expected: `OFFICIAL`, status code `90`, relationship `OFFICIAL_DOMAIN_DECLARED`.

## Step 8 \u2014 Verify a Hopkins Medicine social profile

Manual URL: `https://www.instagram.com/hopkinsmedicine/`.
Expected: `SOCIAL_VERIFIED`, status code `80`,
relationship `SOCIAL_PROFILE_DECLARED`.

## Step 9 \u2014 Switch back to `jhu.edu` and try the fake lookalike

Manual URL: `https://jhuu.edu/`.
Expected: `SUSPICIOUS_LOOKALIKE`, status code `15`,
relationship `LOOKALIKE_DETECTED`.

## Step 10 \u2014 Switch boundary to `jhuu.edu` and try claiming JHU

Manual URL: `https://jhu.edu/`.
Expected: `SUSPICIOUS_UNIDIRECTIONAL_CLAIM`, status code `10`,
relationship `UNIDIRECTIONAL_CLAIM`.

The reasons explain that `jhuu.edu` claims a relationship to `jhu.edu` but
`jhu.edu` does not reciprocate. This is the marquee anti-impersonation
demonstration of the POC.

## Step 11 \u2014 Show the nameserver rule on the admin Rules tab

Highlight:

- The rule exists.
- It is **disabled by default**.
- Its effect can only be `RELATED_CANDIDATE`, never `OFFICIAL`.
- No live NS lookup is ever performed.

## Step 12 \u2014 Edit + save a record from the admin UI

For example, change `Johns Hopkins University` display name and click
**Save organizations**. Verify the change persists by reloading the admin
tab.

## Optional \u2014 Out-of-boundary control

Manual URL: `https://random-example.com/`.
Expected: `OUT_OF_BOUNDARY`, status code `35`.

Confirms the **default deny** policy.

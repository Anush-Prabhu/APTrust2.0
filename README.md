# APT 1.1 — APTrust boundary checker (POC)

Chrome extension (Manifest V3) plus a small **Node.js** index server. Pick a trust boundary (e.g. Johns Hopkins / `jhu.edu`), load its JSON-LD manifest from the local server, and get **warnings** (never blocking) when tabs, links, pastes, or redirects leave that boundary.

Repository: [github.com/Anush-Prabhu/APT1.1](https://github.com/Anush-Prabhu/APT1.1)

## Requirements

- **Node.js** 18 or newer ([nodejs.org](https://nodejs.org/))
- **Google Chrome** (or another Chromium browser that supports unpacked MV3 extensions)

## Install (any machine)

1. **Clone**

   ```bash
   git clone https://github.com/Anush-Prabhu/APT1.1.git
   cd APT1.1
   ```

2. **Install dependencies** (always from the **repository root**, not only `server/`):

   ```bash
   npm install
   ```

   This uses npm workspaces and installs `express` / `cors` for the server.

3. **Start the index server** (default port **8787**):

   ```bash
   npm start
   ```

   You should see:

   - `index server listening on http://localhost:8787`
   - `records dir: …/aptrust-records`

   **Port in use:** stop the other process or use another port:

   - **macOS / Linux:** `PORT=8788 npm start`
   - **Windows PowerShell:** `$env:PORT='8788'; npm start`
   - **Windows CMD:** `set PORT=8788&& npm start`

4. **Load the extension in Chrome**

   - Open `chrome://extensions`
   - Enable **Developer mode**
   - **Load unpacked** → choose the `extension` folder inside this repo

5. **Smoke test the server**

   ```bash
   curl http://localhost:8787/health
   ```

   Expect JSON: `{ "ok": true, "service": "aptrust-index-server", ... }`.

## Use

1. Ensure `npm start` is running.
2. Click the extension icon → turn **Protect Mode** on.
3. Search for **jhu.edu** (or your entry) and select it.
4. Browse: the badge and optional in-page banner reflect trust; external links in untrusted contexts can be outlined.

Sample data lives under `aptrust-records/` (index + `jhu.edu` manifest). The extension talks to `http://localhost:8787` by default (`extension/src/config.js`).

## Layout

| Path | Role |
|------|------|
| `server/` | Express app: `/health`, `/search`, `/entry/:domain`, `/manifest/:domain`, `POST /report` (mock) |
| `extension/` | Unpacked MV3 extension |
| `aptrust-records/` | Sample `entries.json` + per-domain `manifest.jsonld` |

## License / disclaimer

Proof-of-concept only: no warranty, not production security tooling. Hash verification and real report routing are left as TODOs in code and manifests.

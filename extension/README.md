# REQUIEM SecretGuard: Chrome/Edge extension (v0.3)

A small **manual and local** inspection tool for inline and **same-origin** JavaScript of a webpage you own or have explicit permission to test. It is not a vulnerability certification. It does **not** perform active exploitation, enumerate subdomains, validate credentials or inspect network traffic.

## Install on Windows (Chrome / Edge)

1. Download and extract the full project ZIP first. Do **not** select a ZIP file when installing an unpacked extension.
2. Chrome: open `chrome://extensions` (Edge: `edge://extensions`).
3. Turn **Developer mode** ON.
4. Click **Load unpacked** (or **Загрузить распакованное расширение**).
5. Select the **`extension`** directory inside `requiem-secretguard` (the directory with `manifest.json`).
6. Pin the purple extension icon via the extensions menu if you want easy access. Chrome may show a generic icon in this initial build.

## Use

1. Navigate to **your own website** (e.g. your deployed portfolio).
2. Click the SecretGuard extension icon.
3. Review the domain, confirm **I own this website or have permission to test it**, and click **Run security scan**.
4. Review findings, which contain only a rule name, severity, source path, line and remediation. Use **Export JSON** if you need a copy.

Scanning is on-demand. No accounts, API keys, third-party services or local server are required for the extension. The existing standalone Python dashboard still starts with `start_secretguard_windows.bat` and runs independently.

## Safe local test page

Run the local dashboard (`start_secretguard_windows.bat`) and open `http://127.0.0.1:8765/extension-demo`. Click the extension icon, approve your own localhost site and scan. You should see **two demo findings**. These are intentionally invented example values, not active credentials. Close the terminal to shut down the test server.

## What gets inspected

- Inline JavaScript in `<script>` tags (including ES modules).
- Referenced JavaScript on the **same origin**. Fetches are `GET` requests with `credentials: 'omit'`, without auth cookies or headers. No cross-origin assets, HTML form contents, localStorage, WebSockets, fetch/XHR traffic, or browser cookies are scanned.
- Limited to 60 inline scripts, 20 unique same-origin script URLs, 512 KiB per script, 5 MiB total scanned characters, and 75 findings. Scripts larger than limits or unavailable URLs are marked as **partial coverage**.
- Findings are kept in popup memory; clicking Export creates a local JSON file of **redacted metadata only**. The addon has no storage permissions, telemetry, analytics, or network upload endpoints.

Some protected sites do not allow fetching scripts without credentials and will show partial results. This is expected. Cross-origin scripts and bundles loaded dynamically after the page was scanned may be missed. Findings are **pattern matches** and may be false positives, particularly in test bundles or examples; an empty scan never proves a site is secure.

## Development tests

Requires Node 20+ (no npm packages):

```bash
node --test extension/tests/*.cjs
```

The extension is not published in Chrome Web Store. Install only the ZIP you downloaded directly from this conversation or a source repository that you trust. Do not share reports containing private paths or internal project details.

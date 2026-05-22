```
+------------------------------------------------------------------+
|  WP  S E C U R I T Y   S C A N N E R  —  documentation  v1.0      |
+------------------------------------------------------------------+
```

```
+--- [ WARN ] -----------------------------------------------------+
|  Authorized use only. Scan sites you own or have written         |
|  permission to test.                                             |
+------------------------------------------------------------------+
```

## Requirements

```
  [INFO]  Node.js 18 or newer
  [INFO]  npm (comes with Node)
```

## Quick start

```bash
cd wp-security-scanner
npm install
npm run dev
```

```
  [OK]   UI  ->  http://127.0.0.1:3847/
```

Production:

```bash
npm run build
npm start
```

Override port: `PORT=8080 npm run dev`

---

## Target URL input

The scanner accepts **three** forms. What you type is what gets honored.

```
+--- [ INPUT FORMATS ] --------------------------------------------+
|                                                                  |
|  https://example.com     explicit HTTPS  (recommended)           |
|  http://example.com      explicit HTTP   (local / legacy sites)  |
|  example.com             no scheme       -> tries HTTPS first    |
|  www.example.com/wp      no scheme       -> then HTTP if needed   |
|                                                                  |
+------------------------------------------------------------------+
```

| You enter | Behavior |
|-----------|----------|
| `https://site.com` | Scans over **HTTPS** only |
| `http://site.com` | Scans over **HTTP** only |
| `site.com` (no scheme) | Tries **HTTPS** first; if unreachable, auto-retries **HTTP** |

```
  [INFO]  Do not paste paths only (e.g. /wp-admin) — use a full host.
  [INFO]  Ports are OK:  http://localhost:8080
```

The web form uses a plain text field (not strict browser URL validation) so `example.com` and `http://...` both work.

---

## Project layout

```
wp-security-scanner/
|-- src/
|   |-- scanner.ts    scan engine (parallel probes)
|   |-- server.ts     HTTP server + static UI
|   |-- url.ts        http / https / scheme-less parsing
|   |-- types.ts      TypeScript types
|   +-- pool.ts       concurrent request pool
|-- public/
|   |-- index.html    terminal UI
|   |-- app.js        frontend
|   +-- styles.css
+-- package.json
```

---

## API

```
  POST  /api/scan
  Content-Type: application/json
```

Body:

```json
{ "url": "http://example.com" }
```

Any of:

```json
{ "url": "https://example.com" }
{ "url": "http://example.com" }
{ "url": "example.com" }
```

Response (JSON):

```json
{
  "report": { "...": "..." },
  "progress": [{ "message": "Fetching homepage…" }]
}
```

Live progress — header:

```
  Accept: application/x-ndjson
```

Each line is a JSON event: `progress`, `complete`, or `error`.

---

## Checks performed

```
+--- [ SCAN MODULES ] ---------------------------------------------+
|  [CRAWL]     homepage + same-origin links (depth 2, max 25)      |
|  [WP]        generator, wp-content, wp-json signals              |
|  [BACKDOOR]  known paths + PHP obfuscation patterns              |
|  [ROBOTS]    disallow rules, sensitive paths                     |
|  [XSS]       reflected probes (s, q, redirect_to)                |
|  [ADMIN]     wp-login, wp-admin, REST users, ?author=1, xmlrpc   |
|  [AUTH]      weak-credential probes (limited, non-destructive)   |
+------------------------------------------------------------------+
```

---

## Limitations

```
  [WARN]  Shallow, signature-based — not a full penetration test
  [WARN]  No logged-in / plugin CVE coverage
  [WARN]  WAF/CDN may block or skew results
  [WARN]  Some hosts only answer on http OR https — pick the right scheme
```

---

## Troubleshooting

```
+--- [ FAQ ] ------------------------------------------------------+
|  "Not found" in browser                                          |
|    -> Run  npm run dev  and open http://127.0.0.1:3847/          |
|    -> Do not open index.html as a file:// URL                    |
|                                                                  |
|  http:// target fails                                            |
|    -> Type the full URL:  http://your-host  (include http://)    |
|    -> For local WordPress, http is often required                |
|                                                                  |
|  bare domain fails both ways                                     |
|    -> Check DNS, firewall, and that the site is up               |
+------------------------------------------------------------------+
```

```
+------------------------------------------------------------------+
|  _                                                               |
+------------------------------------------------------------------+
```

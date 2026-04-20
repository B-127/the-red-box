# Security Policy

## Reporting a Vulnerability

If you discover a security issue in The Red Box, please open a GitHub Issue or contact the maintainer directly. Do not disclose security vulnerabilities publicly until they have been addressed.

## Security Design

The Red Box is a **static site** — there is no server, no database, and no user authentication. The attack surface is intentionally minimal.

### Content Security Policy

`index.html` includes a strict CSP that:
- Blocks all inline scripts and styles (`script-src 'self'`, `style-src 'self' fonts.googleapis.com`)
- Disallows framing (`frame-ancestors 'none'`)
- Blocks form submissions (`form-action 'none'`)
- Enforces HTTPS (`upgrade-insecure-requests`)

### Feed Fetcher (`scripts/fetch-feeds.js`)

The RSS fetcher runs only in GitHub Actions, never in the browser. It applies multiple layers of defence:

| Code | Description |
|---|---|
| H-1 | Redirect limit (max 3 hops) + SSRF blocklist rejects private IPs |
| H-2 | All article links validated to `https?://` before being written |
| M-3 | Response body capped at 2 MB — prevents memory exhaustion from XML bombs |
| M-5 | HTML entity decode happens BEFORE tag stripping, preventing double-encode bypasses |
| L-1 | Only HTTPS feed URLs are accepted — HTTP is rejected at source validation |
| L-3 | Every parsed item is schema-validated before inclusion in output |
| +A  | All URLs validated via the WHATWG URL API before any network call |
| +B  | Hostname allowlist derived from `sources.json` — no arbitrary outbound requests |
| +C  | Response `Content-Type` must match RSS/Atom/XML patterns |
| +D  | Title capped at 300 chars, deck at 500 chars |
| +E  | `feed.json` written atomically: temp file written, then renamed |
| +F  | `sources.json` fully validated at startup before any network activity |

### GitHub Actions

- All third-party Actions are **pinned to full commit SHAs** (not mutable tags)
- `permissions` block uses least privilege: only `contents: write`
- No `push:` trigger — prevents compromised commits from auto-executing
- `concurrency` group prevents simultaneous pushes

### Front-end (`assets/app.js`)

- All external data rendered via `textContent` — never via `innerHTML`
- All links validated through `safeHref()` before insertion into the DOM
- External data is treated as untrusted at all times

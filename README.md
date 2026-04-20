# The Red Box

**Sri Lanka's English-language news, aggregated from RSS feeds.**

A static news aggregator. Scheduled GitHub Actions workflow that fetches RSS feeds every 30 minutes and writes a static `feed.json`, which the front-end reads directly.

---

## Sources

| Publication | RSS Coverage |
|---|---|
| Daily FT | Front page, News, Sectors, Opinion, Sports |
| EconomyNext | Economy, Finance, Markets, Politics, Energy, Tech, World, Sports |
| Ada Derana | All stories (single feed) |
| Daily News | Local, World, Business, Sports, Features |

---

## Project Structure

```
the-red-box/
├── index.html              # Single-page app shell
├── feed.json               # Generated — committed by GitHub Actions
├── stats.json              # Run stats — committed by GitHub Actions
├── sources.json            # Feed definitions
├── package.json
├── assets/
│   ├── app.css             # All styles (design tokens → components)
│   └── app.js              # All front-end logic (vanilla JS)
├── scripts/
│   └── fetch-feeds.js      # Node.js RSS fetcher + story clusterer
└── .github/workflows/
    └── fetch-feeds.yml     # Runs every 30 min via cron
```

---

## Setup

### 1. Fork / push to GitHub

```bash
git init
git add .
git commit -m "init: The Red Box"
git remote add origin https://github.com/YOUR_USERNAME/the-red-box.git
git push -u origin main
```

### 2. Enable GitHub Pages

Go to **Settings → Pages → Source → Deploy from branch → main / root**.

### 3. Update base href

In `index.html`, update the `<base href>` to match your repo name:

```html
<base href="/the-red-box/">
```

### 4. Trigger first fetch

Go to **Actions → Fetch RSS Feeds → Run workflow** to run the feed fetch immediately rather than waiting for the cron.

### 5. Local development

```bash
npm install
npm run fetch   # fetches feeds and writes feed.json
npm run dev     # serves on http://localhost:8080
```

---

## Security

All security hardening from the original audit is preserved:

- **H-1** Redirect depth limit (max 3) + private-IP / SSRF blocklist
- **H-2** All RSS article links validated before write
- **M-3** Response body capped at 2 MB before XML parse
- **M-5** HTML entities decoded before tag stripping
- **L-1** HTTP feeds rejected — HTTPS only
- **L-3** Schema validation on every item
- **+A** URL validated via WHATWG URL API before any fetch
- **+B** Hostname allowlist derived from `sources.json` at startup
- **+C** Response `Content-Type` checked
- **+D** Title/deck length capped
- **+E** `feed.json` written atomically (temp file → rename)
- **+F** `sources.json` validated at startup
- **CSP** Strict Content-Security-Policy in `index.html`
- **CI** All Actions pinned to full commit SHA, least-privilege permissions

---

## Adding sources

Edit `sources.json`. Each source needs:

```json
{
  "id": "unique-id",
  "name": "Full Name",
  "abbr": "ABBR",
  "feeds": [
    { "url": "https://example.com/rss", "cat": "Politics" }
  ]
}
```

Valid categories: `Politics`, `Economy`, `Business`, `World`, `Technology`, `Sports`, `Opinion`, `Health`, `Environment`

---

*Not affiliated with any publication. Built for readers.*

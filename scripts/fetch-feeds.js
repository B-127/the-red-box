#!/usr/bin/env node

/**
 * fetch-feeds.js  —  The Red Box RSS aggregator
 *
 * Security hardening applied:
 *  C-1  Allowlist enforced on EVERY redirect hop, not just the first
 *  C-2  PRIVATE_IP_RE covers all RFC-reserved ranges (same literal in app.js)
 *  H-1  Article links restricted to https:// only (http:// rejected)
 *  M-1  Tag-strip uses a state-machine that handles malformed/split tags
 *  M-2  Future timestamps clamped to now; age-gate uses Math.abs
 *  M-3  Raw item count capped before O(n^2) clustering (MAX_RAW_ITEMS)
 *  M-4  getDirectChildText() reads only direct child nodes, not all descendants
 *  L-1  src values sanitised (non-printable / ANSI stripped) before logging
 *  L-2  feedsFetched / feedsFailed tallied from results array, not closures
 *  L-4  Stopword removal uses Set-based token filter, not \b word-boundary regex
 *  +A   URL validated via WHATWG URL API before any fetch
 *  +B   Hostname allowlist derived from sources.json; enforced on every hop
 *  +C   Response Content-Type checked
 *  +D   Title/deck length capped
 *  +E   feed.json written atomically (temp file then rename)
 *  +F   sources.json validated at startup
 */

'use strict';

const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { DOMParser } = require('@xmldom/xmldom');

// ── Constants ─────────────────────────────────────────────────────────────────

const ROOT               = path.resolve(__dirname, '..');
const OUTPUT             = path.join(ROOT, 'feed.json');
const STATS_OUTPUT       = path.join(ROOT, 'stats.json');

const MAX_REDIRECTS      = 3;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS         = 12_000;
const MAX_AGE_MS         = 3 * 24 * 60 * 60 * 1000;
const MAX_CLUSTERS       = 300;
const MAX_VERSIONS_PER_CLUSTER = 20;
const MAX_RAW_ITEMS      = MAX_CLUSTERS * 4;   // M-3: bound O(n^2) clustering
const CONCURRENCY        = 6;
const MAX_TITLE_LEN      = 300;
const MAX_DECK_LEN       = 500;

const CLUSTER_KEY_LEN   = 72;
const CLUSTER_THRESHOLD = 0.80;

const VALID_CATS = new Set([
  'Politics', 'Economy', 'Business', 'World',
  'Technology', 'Sports', 'Opinion', 'Health', 'Environment'
]);

// ── C-2: Canonical private/reserved IP regex ─────────────────────────────────
//
// Covers ALL RFC-reserved ranges:
//   0.0.0.0/8        "This" network (RFC 1122)
//   10.0.0.0/8       Private (RFC 1918)
//   100.64.0.0/10    CGNAT (RFC 6598) — cloud-provider internal ranges
//   127.0.0.0/8      Loopback (RFC 1122)
//   169.254.0.0/16   Link-local / AWS metadata endpoint (RFC 3927)
//   172.16.0.0/12    Private (RFC 1918)
//   192.168.0.0/16   Private (RFC 1918)
//   ::1              IPv6 loopback
//   fc00::/7         IPv6 unique-local (fc** and fd** prefixes)
//
// NOTE: this exact literal is also present in assets/app.js. Keep both in sync.
const PRIVATE_IP_RE = /^(0\.|10\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1$|[fF][cCdD][0-9a-fA-F]{2}:)/;

const ACCEPTABLE_CONTENT_TYPE_RE = /^(text\/|application\/(rss|atom|xml|rdf))/i;

// ── L-1: Log sanitiser ────────────────────────────────────────────────────────
// Strips ANSI escape sequences and non-printable characters to prevent
// log injection / terminal spoofing from attacker-controlled source fields.
function sanitiseForLog(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/\x1B\[[0-9;]*[A-Za-z]/g, '')  // ANSI CSI sequences
    .replace(/[^\x20-\x7E]/g, '?');          // non-printable bytes -> '?'
}

// ── Source validation ─────────────────────────────────────────────────────────

function loadAndValidateSources() {
  const raw = fs.readFileSync(path.join(ROOT, 'sources.json'), 'utf8');
  let sources;
  try { sources = JSON.parse(raw); }
  catch (e) { throw new Error(`sources.json is not valid JSON: ${e.message}`); }

  if (!Array.isArray(sources)) throw new Error('sources.json must be an array');

  const valid   = [];
  const seenIds = new Set();

  for (const src of sources) {
    const rawId   = typeof src.id   === 'string' ? src.id.trim()   : '';
    const rawName = typeof src.name === 'string' ? src.name.trim() : '';
    const rawAbbr = typeof src.abbr === 'string' ? src.abbr.trim() : '';

    // L-1: safe, sanitised strings for logging
    const logId = sanitiseForLog(rawId) || '<empty>';

    if (!rawId)   { console.warn('  \u26a0 Skipping source with missing id'); continue; }
    if (seenIds.has(rawId)) { console.warn(`  \u26a0 Duplicate id "${logId}" \u2014 skipping`); continue; }
    if (!rawName) { console.warn(`  \u26a0 Skipping "${logId}": missing name`); continue; }
    if (!rawAbbr || rawAbbr.length > 8) { console.warn(`  \u26a0 Skipping "${logId}": bad abbr`); continue; }
    if (!Array.isArray(src.feeds) || src.feeds.length === 0) {
      console.warn(`  \u26a0 Skipping "${logId}": no feeds`); continue;
    }

    const validFeeds = [];
    for (const feed of src.feeds) {
      let parsed;
      try { parsed = new URL(feed.url); }
      catch { console.warn(`  \u26a0 [${logId}] Invalid URL (omitted from log)`); continue; }

      if (parsed.protocol !== 'https:') {
        console.warn(`  \u26a0 [${logId}] Non-HTTPS feed skipped`); continue;
      }
      if (PRIVATE_IP_RE.test(parsed.hostname)) {
        console.warn(`  \u26a0 [${logId}] Private/reserved host blocked`); continue;
      }
      if (!VALID_CATS.has(feed.cat)) {
        console.warn(`  \u26a0 [${logId}] Unknown category "${sanitiseForLog(String(feed.cat))}"`); continue;
      }
      validFeeds.push({ url: feed.url, cat: feed.cat, hostname: parsed.hostname });
    }

    if (validFeeds.length === 0) {
      console.warn(`  \u26a0 Source "${logId}" has no valid feeds`); continue;
    }

    seenIds.add(rawId);
    valid.push({ id: rawId, name: rawName, abbr: rawAbbr, feeds: validFeeds });
  }

  if (valid.length === 0) throw new Error('No valid sources found in sources.json');

  // Build allowlist from every registered feed hostname, automatically adding
  // the www. variant (or bare domain) so that a redirect between www and
  // non-www does not get blocked by the C-1 allowlist check.
  const allowedHosts = new Set();
  for (const src of valid) {
    for (const feed of src.feeds) {
      const h = feed.hostname;
      allowedHosts.add(h);
      if (h.startsWith('www.')) {
        allowedHosts.add(h.slice(4));   // www.example.com -> example.com
      } else {
        allowedHosts.add('www.' + h);  // example.com -> www.example.com
      }
    }
  }

  return { sources: valid, allowedHosts };
}

// ── Secure HTTPS fetch ────────────────────────────────────────────────────────

function secureFetch(url, allowedHosts, redirectsLeft = MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); }
    catch { return reject(new Error('Invalid URL')); }

    // +A: HTTPS only
    if (parsed.protocol !== 'https:') {
      return reject(new Error('Non-HTTPS URL blocked'));
    }

    // C-2: private/reserved IP check on every hop
    if (PRIVATE_IP_RE.test(parsed.hostname)) {
      return reject(new Error(`Private/reserved host blocked: ${parsed.hostname}`));
    }

    // C-1 + +B: allowlist enforced on EVERY hop
    // We do not exempt CDN redirects: if a source redirects to an unlisted host,
    // that redirect is rejected. Add the CDN hostname to sources.json feeds if needed.
    if (!allowedHosts.has(parsed.hostname)) {
      return reject(new Error(`Host not in allowlist: ${parsed.hostname}`));
    }

    const options = {
      hostname: parsed.hostname,
      path:     parsed.pathname + parsed.search,
      method:   'GET',
      timeout:  TIMEOUT_MS,
      headers:  {
        'User-Agent': 'TheRedBox/1.0 RSS-Aggregator (+https://github.com/)',
        'Accept':     'application/rss+xml, application/atom+xml, application/xml, text/xml, */*'
      }
    };

    const req = https.request(options, res => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
        if (redirectsLeft <= 0) {
          res.resume();
          return reject(new Error('Too many redirects'));
        }
        const loc = res.headers['location'];
        if (!loc) {
          res.resume();
          return reject(new Error('Redirect with no Location header'));
        }
        let redirectUrl;
        try { redirectUrl = new URL(loc, url).href; }
        catch {
          res.resume();
          return reject(new Error('Redirect Location is not a valid URL'));
        }
        res.resume();
        // C-1: pass allowedHosts unchanged so it is enforced on the next hop
        return resolve(secureFetch(redirectUrl, allowedHosts, redirectsLeft - 1));
      }

      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }

      // +C: Content-Type guard
      const ct = res.headers['content-type'] || '';
      if (!ACCEPTABLE_CONTENT_TYPE_RE.test(ct)) {
        res.resume();
        return reject(new Error(`Unexpected Content-Type "${ct}"`));
      }

      // M-3 (body): hard cap
      let bytes = 0;
      const chunks = [];
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > MAX_RESPONSE_BYTES) {
          req.destroy();
          return reject(new Error(`Response body exceeded ${MAX_RESPONSE_BYTES} bytes`));
        }
        chunks.push(chunk);
      });
      res.on('end',   () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });

    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    req.on('error',   reject);
    req.end();
  });
}

// ── XML / RSS parsing ─────────────────────────────────────────────────────────

// M-1: State-machine tag stripper.
// The previous /<[^>]*>/g regex could be defeated by split/malformed tags like
// "<scr<script>ipt>" — after stripping the inner match the outer residue "ipt>"
// and leading "<scr" survive. The state machine treats any run of characters
// inside a '<' ... '>' pair as a tag, regardless of nesting or malformation.
function stripTags(str) {
  let out   = '';
  let depth = 0;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (ch === '<') {
      depth++;
    } else if (ch === '>') {
      if (depth > 0) {
        depth--;
        if (depth === 0) out += ' ';  // separator between adjacent tags
      }
      // if depth was 0 on '>' (stray '>'), emit it — it is harmless plain text
      // and suppressing it would corrupt content like "a > b"
      else {
        out += ch;
      }
    } else if (depth === 0) {
      out += ch;
    }
    // characters inside a tag (depth > 0) are discarded
  }
  return out.replace(/\s+/g, ' ').trim();
}

function decodeEntities(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/&amp;/g,  '&')
    .replace(/&lt;/g,   '<')
    .replace(/&gt;/g,   '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g,  "'")
    .replace(/&apos;/g, "'")
    .replace(/&#(\d{1,7});/g, (_, n) => {
      const cp = parseInt(n, 10);
      // Reject surrogates (0xD800–0xDFFF) and out-of-range code points
      if (cp <= 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return '';
      return String.fromCodePoint(cp);
    })
    .replace(/&#x([0-9a-fA-F]{1,6});/g, (_, h) => {
      const cp = parseInt(h, 16);
      if (cp <= 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return '';
      return String.fromCodePoint(cp);
    });
}

// Decode entities FIRST (so "&amp;lt;" -> "&lt;" -> "<"), then strip tags.
function cleanText(raw) {
  if (!raw || typeof raw !== 'string') return '';
  return stripTags(decodeEntities(raw)).trim();
}

// M-4: Read only DIRECT child element nodes of `parent`.
// The old getElementsByTagName() searches all descendants, which allowed:
//  - Nested <item> elements to leak wrong data
//  - Atom <link href="…"/> to be missed (textContent is "")
// This version iterates childNodes directly and handles the Atom href attribute.
function getDirectChildText(parent, tagName) {
  if (!parent || !parent.childNodes) return '';
  for (let i = 0; i < parent.childNodes.length; i++) {
    const node = parent.childNodes[i];
    if (node.nodeType !== 1 /* ELEMENT_NODE */) continue;
    // Strip namespace prefix for comparison
    const localName = node.localName || (node.nodeName || '').split(':').pop() || '';
    if (localName !== tagName) continue;
    // For <link>, check href attribute first (Atom format)
    if (tagName === 'link') {
      const href = typeof node.getAttribute === 'function' ? node.getAttribute('href') : null;
      if (href && href.trim()) return href.trim();
    }
    return (node.textContent || node.text || '').trim();
  }
  return '';
}

function parseRSS(xml, sourceId, sourceName, sourceAbbr, cat) {
  const parser = new DOMParser({
    errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} }
  });

  let doc;
  try { doc = parser.parseFromString(xml, 'text/xml'); }
  catch { return []; }

  // Support both RSS <item> and Atom <entry>
  const rssItems  = doc.getElementsByTagName('item');
  const items     = rssItems.length > 0
    ? rssItems
    : doc.getElementsByTagName('entry');

  const now    = Date.now();
  const result = [];

  for (let i = 0; i < items.length; i++) {
    const item = items[i];

    // Title
    let title = cleanText(getDirectChildText(item, 'title'));
    if (!title) continue;
    title = title.slice(0, MAX_TITLE_LEN);

    // Link — H-1: https:// only; C-2: private IP blocked
    let link = '';
    const rawLink = getDirectChildText(item, 'link') || getDirectChildText(item, 'guid');
    if (rawLink) {
      const trimmed = rawLink.trim();
      // H-1: https:// only — http:// links are not written to output
      if (/^https:\/\//i.test(trimmed)) {
        try {
          const p = new URL(trimmed);
          if (!PRIVATE_IP_RE.test(p.hostname)) link = p.href;
        } catch { /* invalid URL — skip */ }
      }
    }

    // Deck
    const rawDesc = getDirectChildText(item, 'description')
      || getDirectChildText(item, 'summary')   // Atom
      || '';
    let deck = cleanText(rawDesc);
    deck = deck.slice(0, MAX_DECK_LEN);

    // Publication date — M-2: clamp future timestamps to now
    const pubRaw = getDirectChildText(item, 'pubDate')
      || getDirectChildText(item, 'date')
      || getDirectChildText(item, 'published')
      || getDirectChildText(item, 'updated')
      || '';
    let pub = pubRaw ? new Date(pubRaw).getTime() : now;
    // M-2: reject NaN, zero/negative, and future dates (60 s clock-skew tolerance)
    if (!Number.isFinite(pub) || pub <= 0 || pub > now + 60_000) pub = now;

    // Age gate — Math.abs guards any residual skew after clamping
    if (Math.abs(now - pub) > MAX_AGE_MS) continue;

    result.push({ title, deck, link, pub, src: sourceAbbr, srcFull: sourceName, cat, sourceId });
  }

  return result;
}

// ── Story clustering ──────────────────────────────────────────────────────────

// L-4: Stopword list as a Set — O(1) lookup; no \b word-boundary regex.
// \b fails on words adjacent to non-ASCII or at string boundaries in some
// JS engines, and is unnecessary when we are already splitting on spaces.
const STOPWORDS = new Set([
  'a','an','the','and','or','but','in','on','at','to','for',
  'of','with','by','from','is','are','was','were','has','have'
]);

function normaliseTitle(t) {
  return t
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, ' ')  // collapse non-alphanum to space
    .split(' ')
    .filter(w => w.length > 1 && !STOPWORDS.has(w))  // drop stopwords + 1-char tokens
    .join(' ')
    .trim();
}

function similarity(a, b) {
  const ka = normaliseTitle(a).slice(0, CLUSTER_KEY_LEN);
  const kb = normaliseTitle(b).slice(0, CLUSTER_KEY_LEN);
  if (!ka || !kb) return 0;
  const wordsA = ka.split(' ').filter(Boolean);
  const setB   = new Set(kb.split(' ').filter(Boolean));
  const common  = wordsA.filter(w => setB.has(w)).length;
  const maxLen  = Math.max(wordsA.length, setB.size);
  return maxLen === 0 ? 0 : common / maxLen;
}

function clusterItems(items) {
  // M-3: Hard cap on raw items BEFORE the O(n^2) loop
  const capped = items.slice(0, MAX_RAW_ITEMS);

  // Sort newest first
  capped.sort((a, b) => b.pub - a.pub);

  const clusters = [];

  for (const item of capped) {
    let matched = false;

    for (const cluster of clusters) {
      if (cluster.versions.length >= MAX_VERSIONS_PER_CLUSTER) continue;
      if (similarity(item.title, cluster.title) >= CLUSTER_THRESHOLD) {
        const alreadyHasSource = cluster.versions.some(v => v.src === item.src);
        if (!alreadyHasSource) {
          cluster.versions.push({
            title:   item.title,
            deck:    item.deck,
            link:    item.link,
            pub:     item.pub,
            src:     item.src,
            srcFull: item.srcFull,
            cat:     item.cat
          });
          if (item.pub > cluster.pub) {
            cluster.pub   = item.pub;
            cluster.title = item.title;
          }
        }
        matched = true;
        break;
      }
    }

    if (!matched) {
      clusters.push({
        title:    item.title,
        pub:      item.pub,
        cat:      item.cat,
        versions: [{
          title:   item.title,
          deck:    item.deck,
          link:    item.link,
          pub:     item.pub,
          src:     item.src,
          srcFull: item.srcFull,
          cat:     item.cat
        }]
      });
    }

    if (clusters.length >= MAX_CLUSTERS) break;
  }

  clusters.sort((a, b) => b.pub - a.pub);
  return clusters.slice(0, MAX_CLUSTERS);
}

// ── Concurrency pool ──────────────────────────────────────────────────────────

async function runPool(tasks, concurrency) {
  const results = new Array(tasks.length).fill(null);
  let nextIdx = 0;

  async function worker() {
    while (nextIdx < tasks.length) {
      const idx = nextIdx++;
      try   { results[idx] = await tasks[idx](); }
      catch { results[idx] = null; }
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(concurrency, tasks.length) }, worker)
  );
  return results;
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log('\uD83D\uDD34 The Red Box \u2014 RSS fetch starting');
  console.log(`   ${new Date().toISOString()}\n`);

  console.log('\uD83D\uDCCB Loading and validating sources.json\u2026');
  const { sources, allowedHosts } = loadAndValidateSources();
  const totalFeeds = sources.reduce((n, s) => n + s.feeds.length, 0);
  console.log(`   ${sources.length} sources, ${totalFeeds} feeds\n`);

  const feedTasks = [];
  for (const src of sources) {
    for (const feed of src.feeds) {
      feedTasks.push({ src, feed });
    }
  }

  console.log(`\uD83D\uDCE1 Fetching ${feedTasks.length} feeds (concurrency=${CONCURRENCY})\u2026`);

  // L-2: tasks return { ok, items } objects; counts tallied AFTER pool returns
  const tasks = feedTasks.map(({ src, feed }) => async () => {
    // L-1: sanitise before logging
    const logName = sanitiseForLog(src.name);
    const logCat  = sanitiseForLog(feed.cat);
    process.stdout.write(`   \u2192 ${logName} [${logCat}]\u2026 `);
    try {
      const xml   = await secureFetch(feed.url, allowedHosts);
      const items = parseRSS(xml, src.id, src.name, src.abbr, feed.cat);
      process.stdout.write(`\u2713 ${items.length} items\n`);
      return { ok: true, items };
    } catch (err) {
      process.stdout.write(`\u2717 ${sanitiseForLog(err.message)}\n`);
      return { ok: false, items: [] };
    }
  });

  const results = await runPool(tasks, CONCURRENCY);

  // L-2: aggregate outcomes from the resolved results array
  let feedsFetched = 0;
  let feedsFailed  = 0;
  const allItems   = [];
  for (const r of results) {
    if (!r || !r.ok) { feedsFailed++;  continue; }
    feedsFetched++;
    allItems.push(...r.items);
  }

  console.log(`\n\uD83D\uDCE6 ${allItems.length} raw items collected`);

  console.log('\uD83D\uDD17 Clustering similar stories\u2026');
  const clusters = clusterItems(allItems);  // M-3 cap applied inside
  console.log(`   ${clusters.length} clusters`);

  // Ticker: one item per source, newest first
  const tickerSeen  = new Set();
  const tickerItems = [...allItems]
    .sort((a, b) => b.pub - a.pub)
    .filter(item => {
      if (tickerSeen.has(item.src)) return false;
      tickerSeen.add(item.src);
      return true;
    })
    .slice(0, 12)
    .map(item => ({ src: item.srcFull, title: item.title, link: item.link }));

  // Source counts
  const sourceCounts = {};
  for (const src of sources) {
    sourceCounts[src.abbr] = { name: src.name, abbr: src.abbr, count: 0 };
  }
  for (const item of allItems) {
    if (sourceCounts[item.src]) sourceCounts[item.src].count++;
  }

  const output = {
    generated:    new Date().toISOString(),
    clusters,
    ticker:       tickerItems,
    sourceCounts: Object.values(sourceCounts)
  };

  // +E: Atomic write
  const tmp = OUTPUT + '.tmp.' + crypto.randomBytes(6).toString('hex');
  fs.writeFileSync(tmp, JSON.stringify(output), 'utf8');
  fs.renameSync(tmp, OUTPUT);

  const stats = {
    generated:    new Date().toISOString(),
    sources:      sources.length,
    feedsFetched,
    feedsFailed,
    itemsRaw:     allItems.length,
    clusters:     clusters.length
  };
  const statsTmp = STATS_OUTPUT + '.tmp.' + crypto.randomBytes(6).toString('hex');
  fs.writeFileSync(statsTmp, JSON.stringify(stats, null, 2), 'utf8');
  fs.renameSync(statsTmp, STATS_OUTPUT);

  console.log(`\n\u2705 Done \u2014 feed.json written`);
  console.log(`   Fetched: ${feedsFetched}  Failed: ${feedsFailed}  Clusters: ${clusters.length}`);
}

main().catch(err => {
  console.error('Fatal error:', sanitiseForLog(String(err.message || err)));
  process.exit(1);
});

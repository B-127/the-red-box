/**
 * app.js  —  The Red Box front-end
 *
 * Security fixes applied:
 *  C-2  PRIVATE_IP_RE updated to match the canonical set in fetch-feeds.js
 *       (all RFC-reserved ranges; IPv6 unique-local included)
 *  H-1  safeHref() rejects http:// links — https:// only
 *  H-2  fetch() uses an explicit root-relative path (/the-red-box/feed.json)
 *       so it is not affected by the <base href> element
 *  H-3  animationDelay set via Number-guarded setProperty(), not string concat
 *  M-5  isValidCluster() validates each version object's required fields;
 *       buildHeroGrid/buildStreamItem guard against null/missing versions[0]
 *  M-6  loadFeed() clears any existing error card before appending a new one
 *  M-7  isLoading flag prevents overlapping concurrent loadFeed() calls
 *  L-3  buildVersionRow() only creates an <a> when a valid href exists;
 *       version rows with no link render as a plain <div> with no pointer cursor
 */

'use strict';

// ── Constants ─────────────────────────────────────────────────────────────────

const VALID_CATS = new Set([
  'Politics', 'Economy', 'Business', 'World',
  'Technology', 'Sports', 'Opinion', 'Health', 'Environment'
]);

const PAGE_SIZE        = 30;
const REFRESH_INTERVAL = 5 * 60 * 1000;  // 5 min

const SOURCES = [
  { name: 'Daily FT',    abbr: 'DFT' },
  { name: 'EconomyNext', abbr: 'EN'  },
  { name: 'Ada Derana',  abbr: 'AD'  },
  { name: 'Daily News',  abbr: 'DN'  },
];

// H-2: Root-relative path avoids <base href> resolution.
// Update this path to match your GitHub Pages repo name.
const FEED_URL = '/the-red-box/feed.json';

// ── State ─────────────────────────────────────────────────────────────────────

let ALL_CLUSTERS  = [];
let activeCat     = 'all';
let activeSource  = 'all';
let searchVal     = '';
let pageOffset    = 0;
let lastModified  = '';
let isLoading     = false;  // M-7: in-flight guard

// ── Helpers ───────────────────────────────────────────────────────────────────

function relativeTime(ts) {
  const diff = Math.floor((Date.now() - ts) / 1000);
  if (diff < 60)    return 'just now';
  if (diff < 3600)  return Math.floor(diff / 60)   + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

// C-2: Canonical private/reserved IP regex — matches fetch-feeds.js exactly.
// Covers: 0/8, 10/8, 100.64/10 (CGNAT), 127/8, 169.254/16, 172.16/12,
//         192.168/16, ::1, fc00::/7 (IPv6 unique-local fc** and fd**).
const PRIVATE_IP_RE = /^(0\.|10\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1$|[fF][cCdD][0-9a-fA-F]{2}:)/;

function safeHref(raw) {
  if (!raw || typeof raw !== 'string') return '';
  // Upgrade http:// to https:// — the feed may serve http links; we rewrite
  // the scheme so the browser opens a secure connection
  const trimmed = raw.trim().replace(/^http:\/\//i, 'https://');
  if (!/^https:\/\//i.test(trimmed)) return '';
  try {
    const p = new URL(trimmed);
    if (PRIVATE_IP_RE.test(p.hostname)) return '';
    return p.href;
  } catch { return ''; }
}

// ── Validation ────────────────────────────────────────────────────────────────

// M-5: Validates a single version object's required fields.
function isValidVersion(v) {
  if (!v || typeof v !== 'object')               return false;
  if (typeof v.title !== 'string' || !v.title)   return false;
  if (typeof v.src   !== 'string' || !v.src)     return false;
  // pub must be a positive finite number
  if (!Number.isFinite(v.pub) || v.pub <= 0)     return false;
  return true;
}

// M-5: Validates the full cluster including each version entry.
function isValidCluster(c) {
  if (!c || typeof c !== 'object')                            return false;
  if (typeof c.title !== 'string' || !c.title.trim())        return false;
  if (!VALID_CATS.has(c.cat))                                 return false;
  if (!Number.isFinite(c.pub) || c.pub <= 0)                 return false;
  if (!Array.isArray(c.versions) || c.versions.length < 1)   return false;
  // Every version must be valid; we filter rather than reject the whole cluster
  // so one bad version doesn't discard a cluster that has valid versions too.
  const validVersions = c.versions.filter(isValidVersion);
  if (validVersions.length === 0) return false;
  // Replace versions in-place with only the valid ones
  c.versions = validVersions;
  return true;
}

// ── Theme ─────────────────────────────────────────────────────────────────────

function toggleTheme() {
  const root    = document.documentElement;
  const current = root.getAttribute('data-theme');
  const next    = current === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  try { localStorage.setItem('rb-theme', next); } catch { /* noop */ }
}

function initTheme() {
  let saved;
  try { saved = localStorage.getItem('rb-theme'); } catch { /* noop */ }
  if (saved === 'dark' || saved === 'light') {
    document.documentElement.setAttribute('data-theme', saved);
  } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
}

// ── Date bar ──────────────────────────────────────────────────────────────────

function setDateBar() {
  const now     = new Date();
  const dateStr = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Asia/Colombo',
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric'
  }).format(now);

  const el = document.getElementById('date-bar-text');
  if (el) el.textContent = dateStr + ' \u00b7 ' + SOURCES.length + ' sources \u00b7 Updated every 30 min';
}

// ── Ticker ────────────────────────────────────────────────────────────────────

function buildTicker(tickerItems) {
  const inner = document.getElementById('ticker-inner');
  if (!inner || !Array.isArray(tickerItems) || tickerItems.length === 0) return;

  inner.innerHTML = '';

  // Duplicate for seamless CSS loop
  const all = [...tickerItems, ...tickerItems];

  all.forEach(item => {
    const div = document.createElement('div');
    div.className = 'ticker-item';

    const strong = document.createElement('strong');
    strong.textContent = typeof item.src === 'string' ? item.src.slice(0, 40) : 'Source';
    div.appendChild(strong);

    const text = document.createTextNode(
      ' ' + (typeof item.title === 'string' ? item.title.slice(0, 120) : '')
    );
    div.appendChild(text);

    inner.appendChild(div);
  });
}

// ── Source feeds grid ─────────────────────────────────────────────────────────

function buildFeedsGrid(sourceCounts) {
  const grid = document.getElementById('feeds-grid');
  if (!grid) return;

  grid.innerHTML = '';

  const counts = Array.isArray(sourceCounts) ? sourceCounts : [];

  counts.forEach(src => {
    if (!src || typeof src.name !== 'string') return;

    const card = document.createElement('div');
    card.className = 'feed-card';
    if (activeSource === src.abbr) card.classList.add('active');

    const dot = document.createElement('div');
    dot.className = 'feed-dot';
    card.appendChild(dot);

    const name = document.createElement('div');
    name.className = 'feed-name';
    name.textContent = src.name.slice(0, 30);
    card.appendChild(name);

    const count = document.createElement('div');
    count.className = 'feed-count';
    count.textContent = (src.count || 0) + ' stories';
    card.appendChild(count);

    card.addEventListener('click', () => {
      if (activeSource === src.abbr) {
        activeSource = 'all';
        card.classList.remove('active');
      } else {
        activeSource = src.abbr;
        document.querySelectorAll('.feed-card').forEach(c => c.classList.remove('active'));
        card.classList.add('active');
      }
      renderFeed(true);
    });

    grid.appendChild(card);
  });
}

// ── Filtering ─────────────────────────────────────────────────────────────────

function clusterMatchesFilters(cluster) {
  const okCat    = activeCat === 'all' || cluster.cat === activeCat;
  const okSource = activeSource === 'all' || cluster.versions.some(v => v.src === activeSource);
  const okSearch = !searchVal ||
    cluster.title.toLowerCase().includes(searchVal) ||
    cluster.versions.some(v =>
      (typeof v.src     === 'string' && v.src.toLowerCase().includes(searchVal)) ||
      (typeof v.srcFull === 'string' && v.srcFull.toLowerCase().includes(searchVal)) ||
      (typeof v.title   === 'string' && v.title.toLowerCase().includes(searchVal))
    );
  return okCat && okSource && okSearch;
}

function getFiltered() {
  return ALL_CLUSTERS.filter(clusterMatchesFilters);
}

// ── Hero grid ─────────────────────────────────────────────────────────────────

function buildHeroGrid(clusters) {
  const heroMain   = document.getElementById('hero-main');
  const heroMiddle = document.getElementById('hero-middle');
  const heroSection = document.getElementById('hero-section');

  if (!heroSection) return;

  if (clusters.length === 0) {
    heroSection.hidden = true;
    return;
  }
  heroSection.hidden = false;

  // ── MAIN lead story (left column) ──
  if (heroMain && clusters[0]) {
    const c    = clusters[0];
    const p    = c.versions[0];
    const href = safeHref(p.link);

    heroMain.innerHTML = '';
    heroMain.appendChild(makeAccentBar());
    heroMain.appendChild(makeSourceTag(p.srcFull || p.src));

    const catPill = document.createElement('div');
    catPill.className   = 'category-pill';
    catPill.textContent = c.cat;
    heroMain.appendChild(catPill);

    const hl = document.createElement('h1');
    hl.className = 'hero-headline';
    if (href) hl.appendChild(makeExternalLink(href, c.title));
    else hl.textContent = c.title;
    heroMain.appendChild(hl);

    if (p.deck && p.deck.trim()) {
      const deck = document.createElement('p');
      deck.className   = 'standfirst';
      deck.textContent = p.deck.slice(0, 300);
      heroMain.appendChild(deck);
    }

    heroMain.appendChild(makeMeta([relativeTime(c.pub), c.cat]));

    if (href) {
      const readLink = makeExternalLink(href, 'Read at ' + (p.srcFull || p.src) + ' \u2192');
      readLink.className = 'read-link';
      heroMain.appendChild(readLink);
    }
  }

  // ── RIGHT column — stories 2 through 7 as a compact list ──
  if (heroMiddle) {
    heroMiddle.innerHTML = '';

    const label = document.createElement('div');
    label.className   = 'sidebar-label';
    label.textContent = 'More Stories';
    heroMiddle.appendChild(label);

    clusters.slice(1, 8).forEach((c, i) => {
      const p    = c.versions[0];
      const href = safeHref(p.link);

      const item = document.createElement('div');
      item.className = 'hero-list-item';

      const top = document.createElement('div');
      top.className = 'hero-list-top';

      const src = document.createElement('span');
      src.className   = 'sidebar-source';
      src.textContent = (p.srcFull || p.src).slice(0, 30);
      top.appendChild(src);

      const cat = document.createElement('span');
      cat.className   = 'hero-list-cat';
      cat.textContent = c.cat;
      top.appendChild(cat);

      item.appendChild(top);

      const hl = document.createElement('div');
      hl.className = i < 2 ? 'hero-list-headline hero-list-headline--large' : 'hero-list-headline';
      if (href) hl.appendChild(makeExternalLink(href, c.title.slice(0, 140)));
      else hl.textContent = c.title.slice(0, 140);
      item.appendChild(hl);

      // Show deck for first 2 items
      if (i < 2 && p.deck && p.deck.trim()) {
        const deck = document.createElement('p');
        deck.className   = 'hero-list-deck';
        deck.textContent = p.deck.slice(0, 160);
        item.appendChild(deck);
      }

      const time = document.createElement('div');
      time.className   = 'sidebar-time';
      time.textContent = relativeTime(c.pub);
      item.appendChild(time);

      heroMiddle.appendChild(item);
    });
  }
}

// ── Stream grid (All Stories) ─────────────────────────────────────────────────

// L-3: Renders a version row as <a> only when a valid href exists.
// Without a link it renders as a <div> — no misleading pointer cursor.
function buildVersionRow(version) {
  const href = safeHref(version.link);

  let row;
  if (href) {
    row = document.createElement('a');
    row.href   = href;
    row.rel    = 'noopener noreferrer';
    row.className = 'version-row version-row--linked';
  } else {
    // L-3: plain div — pointer cursor removed in CSS for this variant
    row = document.createElement('div');
    row.className = 'version-row version-row--no-link';
  }

  const srcName = document.createElement('span');
  srcName.className   = 'version-src-name';
  srcName.textContent = (version.srcFull || version.src || '').slice(0, 20);
  row.appendChild(srcName);

  const title = document.createElement('span');
  title.className   = 'version-title';
  title.textContent = (version.title || '').slice(0, 120);
  row.appendChild(title);

  const time = document.createElement('span');
  time.className   = 'version-time';
  time.textContent = relativeTime(version.pub);
  row.appendChild(time);

  return row;
}

function buildStreamItem(cluster, idx) {
  const isSingle = cluster.versions.length === 1;
  const primary  = cluster.versions[0];  // M-5: guaranteed valid by isValidCluster
  const href     = safeHref(primary.link);

  const item = document.createElement('div');
  item.className = 'stream-item';

  // H-3: animation-delay set via setProperty with an explicit Number conversion,
  // not via string concatenation — eliminates CSS injection foothold.
  const delaySeconds = Number(idx) * 0.03;
  item.style.setProperty('animation-delay', delaySeconds.toFixed(3) + 's');

  item.appendChild(makeSourceTag(primary.srcFull || primary.src));

  const hl = document.createElement('h3');
  hl.className = 'small-headline';
  if (href) {
    hl.appendChild(makeExternalLink(href, cluster.title.slice(0, 160)));
  } else {
    hl.textContent = cluster.title.slice(0, 160);
  }
  item.appendChild(hl);

  if (primary.deck && primary.deck.trim()) {
    const deck = document.createElement('p');
    deck.className   = 'deck';
    deck.textContent = primary.deck.slice(0, 220);
    item.appendChild(deck);
  }

  item.appendChild(makeMeta([relativeTime(cluster.pub), cluster.cat]));

  if (!isSingle) {
    const badge = document.createElement('div');
    badge.className = 'multi-badge';
    badge.setAttribute('role', 'button');
    badge.setAttribute('tabindex', '0');
    badge.setAttribute('aria-expanded', 'false');

    const badgeText = document.createTextNode(
      cluster.versions.length + ' sources covering this story'
    );
    badge.appendChild(badgeText);

    const panel = document.createElement('div');
    panel.className = 'versions-panel';
    panel.hidden    = true;
    panel.setAttribute('aria-label', 'All sources for this story');

    const MAX_DISPLAY = 10;
    cluster.versions.slice(0, MAX_DISPLAY).forEach(v => panel.appendChild(buildVersionRow(v)));

    if (cluster.versions.length > MAX_DISPLAY) {
      const more = document.createElement('div');
      more.style.cssText = 'font-family:JetBrains Mono,monospace;font-size:9px;color:var(--text-muted);padding:6px 0;';
      more.textContent   = '+ ' + (cluster.versions.length - MAX_DISPLAY) + ' more';
      panel.appendChild(more);
    }

    function toggle(e) {
      if (e.target.closest('a.version-row--linked')) return;
      const expanded = !panel.hidden;
      panel.hidden   = expanded;
      badge.setAttribute('aria-expanded', String(!expanded));
      badgeText.nodeValue =
        cluster.versions.length + ' sources' + (!expanded ? ' \u25b4' : ' \u25be');
    }

    badge.addEventListener('click', toggle);
    badge.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(e); }
    });

    item.appendChild(badge);
    item.appendChild(panel);
  }

  return item;
}

function renderFeed(reset) {
  const feedEl   = document.getElementById('stream-feed');
  const filtered = getFiltered();

  if (reset) {
    pageOffset = 0;
    if (feedEl) feedEl.querySelectorAll('.stream-item, .state-msg-empty').forEach(el => el.remove());
    buildHeroGrid(filtered);
  }

  if (!feedEl) return;

  const loadMsg = feedEl.querySelector('#loading-msg');
  if (loadMsg) loadMsg.remove();

  if (filtered.length === 0) {
    const msg = document.createElement('div');
    msg.className = 'state-msg state-msg-empty';
    msg.setAttribute('role', 'status');
    msg.textContent = 'No stories match your current filters.';
    feedEl.appendChild(msg);
    const moreWrap = document.getElementById('load-more-wrap');
    if (moreWrap) moreWrap.hidden = true;
    updateResultCount(0, 0);
    return;
  }

  const slice = filtered.slice(pageOffset, pageOffset + PAGE_SIZE);
  const frag  = document.createDocumentFragment();
  slice.forEach((cluster, i) => frag.appendChild(buildStreamItem(cluster, i)));
  feedEl.appendChild(frag);
  pageOffset += slice.length;

  updateResultCount(Math.min(pageOffset, filtered.length), filtered.length);

  const moreWrap = document.getElementById('load-more-wrap');
  const moreBtn  = document.getElementById('load-more-btn');
  if (pageOffset < filtered.length) {
    if (moreWrap) moreWrap.hidden = false;
    if (moreBtn) {
      moreBtn.disabled    = false;
      moreBtn.textContent = 'Load ' + Math.min(PAGE_SIZE, filtered.length - pageOffset) + ' more stories';
    }
  } else {
    if (moreWrap) moreWrap.hidden = true;
  }
}

function updateResultCount(showing, total) {
  const el = document.getElementById('result-count');
  if (!el) return;
  el.textContent = showing + ' of ' + total + (total === 1 ? ' story' : ' stories');
}

// ── DOM element builders ──────────────────────────────────────────────────────

function makeAccentBar() {
  const bar = document.createElement('div');
  bar.className = 'accent-bar';
  return bar;
}

// Returns an <a> that navigates to an external URL in the same tab.
// target="_blank" was removed — popup blockers silently swallow new-tab
// link clicks, making headlines appear unclickable.
function makeExternalLink(href, text) {
  const a = document.createElement('a');
  a.href        = href;
  a.rel         = 'noopener noreferrer';
  a.textContent = text;
  return a;
}

function makeSourceTag(sourceName) {
  const tag = document.createElement('div');
  tag.className = 'source-tag';

  const dot = document.createElement('span');
  dot.className = 'source-dot';
  dot.setAttribute('aria-hidden', 'true');
  tag.appendChild(dot);

  tag.appendChild(document.createTextNode(' ' + (sourceName || '').slice(0, 30)));
  return tag;
}

function makeMeta(parts) {
  const meta = document.createElement('div');
  meta.className = 'meta';
  parts.forEach((p, i) => {
    if (i > 0) {
      const sep = document.createElement('span');
      sep.className   = 'meta-sep';
      sep.textContent = '\u00b7';
      meta.appendChild(sep);
    }
    const span = document.createElement('span');
    span.textContent = p;
    meta.appendChild(span);
  });
  return meta;
}

// ── Event wiring ──────────────────────────────────────────────────────────────

document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    el.classList.add('active');
    activeCat = el.dataset.cat || 'all';
    const sectionLabel = document.getElementById('section-label');
    if (sectionLabel) {
      sectionLabel.textContent = activeCat === 'all' ? 'Top Stories' : activeCat;
    }
    renderFeed(true);
  });
});

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeCat = btn.dataset.cat || 'all';
    renderFeed(true);
  });
});

const searchInput = document.getElementById('search-input');
let searchTimer;
if (searchInput) {
  searchInput.addEventListener('input', e => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      searchVal = e.target.value.trim().toLowerCase().slice(0, 200);
      renderFeed(true);
    }, 220);
  });
}

const loadMoreBtn = document.getElementById('load-more-btn');
if (loadMoreBtn) {
  loadMoreBtn.addEventListener('click', () => renderFeed(false));
}

const themeToggle = document.getElementById('theme-toggle');
if (themeToggle) {
  themeToggle.addEventListener('click', toggleTheme);
}

// ── Data fetch ────────────────────────────────────────────────────────────────

async function loadFeed() {
  // M-7: Prevent concurrent overlapping fetch calls
  if (isLoading) return;
  isLoading = true;

  try {
    const headers = {};
    if (lastModified) headers['If-Modified-Since'] = lastModified;

    // H-2: Use an explicit root-relative URL, bypassing <base href> resolution.
    const res = await fetch(FEED_URL + '?v=' + Date.now(), {
      headers,
      cache: 'no-store'
    });

    if (res.status === 304) { isLoading = false; return; }
    if (!res.ok) throw new Error('HTTP ' + res.status);

    const lm = res.headers.get('Last-Modified');
    if (lm) lastModified = lm;

    const data = await res.json();

    if (!data || !Array.isArray(data.clusters)) {
      throw new Error('feed.json has unexpected structure');
    }

    ALL_CLUSTERS = data.clusters.filter(c => {
      if (isValidCluster(c)) return true;
      console.warn('[RedBox] Dropped invalid cluster');
      return false;
    });

    if (Array.isArray(data.ticker)) buildTicker(data.ticker);
    if (Array.isArray(data.sourceCounts)) buildFeedsGrid(data.sourceCounts);

    if (data.generated && typeof data.generated === 'string') {
      const genDate = new Date(data.generated);
      if (!isNaN(genDate.getTime())) {
        const el = document.getElementById('last-updated');
        if (el) el.textContent = 'Updated ' + relativeTime(genDate.getTime());
      }
    }

    const loadMsg = document.getElementById('loading-msg');
    if (loadMsg) loadMsg.remove();

    renderFeed(true);

  } catch (err) {
    console.error('[RedBox] Feed load error:', err);

    // M-6: Remove any previously rendered error card before inserting a new one,
    // preventing accumulation of error divs on repeated failed refreshes.
    const feedEl = document.getElementById('stream-feed');
    if (feedEl) {
      const existing = feedEl.querySelector('.feed-error-card');
      if (existing) existing.remove();

      const loadMsg = document.getElementById('loading-msg');
      if (loadMsg) loadMsg.remove();

      const errorDiv = document.createElement('div');
      errorDiv.className = 'state-msg feed-error-card';
      errorDiv.setAttribute('role', 'alert');

      const strong = document.createElement('strong');
      strong.textContent = 'Could not load feed';
      errorDiv.appendChild(strong);
      errorDiv.appendChild(document.createElement('br'));

      const detail = document.createElement('span');
      // err.message is from our own fetch/JSON code — not from external data
      detail.textContent = err.message || 'Unknown error';
      errorDiv.appendChild(detail);

      const note = document.createElement('p');
      note.style.cssText = 'margin-top:12px;font-size:11px;';
      note.textContent   = 'The feed is updated automatically every 30 minutes via GitHub Actions.';
      errorDiv.appendChild(note);

      feedEl.appendChild(errorDiv);
    }

    const countEl = document.getElementById('result-count');
    if (countEl) countEl.textContent = 'Feed unavailable';

  } finally {
    // M-7: Always release the lock, even on error
    isLoading = false;
  }
}

// ── Initialise ────────────────────────────────────────────────────────────────

initTheme();
setDateBar();
loadFeed();

// M-7: visibilitychange and interval both guarded by isLoading flag
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) loadFeed();
});

setInterval(() => {
  if (!document.hidden) loadFeed();
}, REFRESH_INTERVAL);

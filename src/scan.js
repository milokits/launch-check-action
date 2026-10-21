// Milo's Launch Check: network layer for Node (CLI + GitHub Action).
// Passive only: plain GET requests to the homepage, the JavaScript files the page itself references,
// their source maps, and a few well-known public file paths (/.env, /.git/HEAD, /.git/config).
// No POST, no auth, no fuzzing, no payloads. Bodies are read with a size cap and never stored.
"use strict";
const http = require("http");
const https = require("https");
const zlib = require("zlib");
const dns = require("dns").promises;
const net = require("net");
const core = require("./core");

const UA = "MiloKits-LaunchCheck/" + core.VERSION + " (passive check; +https://milokits.com)";
const DEFAULTS = { timeoutMs: 8000, maxRedirects: 4, maxScripts: 20, maxMaps: 6, maxJsBytes: 5 * 1024 * 1024, maxProbeBytes: 64 * 1024, concurrency: 4, allowPrivate: false };

// ---------- SSRF guard (same ranges as the milokits.com instant check)
function ipv4ToInt(ip) { return ip.split(".").reduce((a, o) => (a << 8) + (+o), 0) >>> 0; }
const V4_BLOCK = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
].map(([b, m]) => [ipv4ToInt(b), m]);
function blockedV4(ip) { const n = ipv4ToInt(ip); return V4_BLOCK.some(([b, m]) => (n >>> (32 - m)) === (b >>> (32 - m))); }
function blockedIP(ip) {
  if (net.isIPv4(ip)) return blockedV4(ip);
  if (net.isIPv6(ip)) {
    const x = ip.toLowerCase();
    const mapped = x.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return blockedV4(mapped[1]);
    if (x === "::" || x === "::1") return true;
    if (/^(fc|fd|fe[89ab]|ff)/.test(x)) return true;
    if (/^(64:ff9b|2001:db8|2001:0?:|2002:)/.test(x)) return true;
    return false;
  }
  return true;
}
function normalizeTarget(raw, opts) {
  if (typeof raw !== "string" || !raw.trim() || raw.length > 2048) throw new Error("bad_url");
  let s = raw.trim();
  if (!/^[a-z][a-z0-9+.-]*:/i.test(s)) s = "https://" + s;
  let u;
  try { u = new URL(s); } catch { throw new Error("bad_url"); }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("bad_scheme");
  if (u.username || u.password) throw new Error("bad_url");
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!opts.allowPrivate) {
    if (u.port && u.port !== "80" && u.port !== "443") throw new Error("bad_port");
    if (!host || host === "localhost" || /\.(localhost|local|internal|lan|home|arpa|corp)$/.test(host) || (!host.includes(".") && !net.isIP(host))) throw new Error("blocked_host");
    if (net.isIP(host) && blockedIP(host)) throw new Error("blocked_host");
  }
  return { host, hostport: u.host, origin: u.protocol + "//" + u.host };
}
async function resolveSafe(host, opts) {
  if (net.isIP(host)) { if (!opts.allowPrivate && blockedIP(host)) throw new Error("blocked_host"); return { address: host, family: net.isIPv6(host) ? 6 : 4 }; }
  let addrs;
  try { addrs = await dns.lookup(host, { all: true, verbatim: true }); } catch { throw new Error("dns_fail"); }
  if (!addrs.length) throw new Error("dns_fail");
  if (!opts.allowPrivate) for (const a of addrs) if (blockedIP(a.address)) throw new Error("blocked_host");
  return addrs[0];
}

// ---------- one GET, DNS pinned, body capped
async function get(urlStr, opts, { maxBytes, wantBody = true } = {}) {
  const u = new URL(urlStr);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  normalizeTarget(urlStr, opts);
  const pinned = await resolveSafe(host, opts);
  return new Promise((resolve, reject) => {
    const mod = u.protocol === "https:" ? https : http;
    const req = mod.request({
      method: "GET", hostname: host, port: u.port || (u.protocol === "https:" ? 443 : 80),
      path: (u.pathname || "/") + (u.search || ""), servername: net.isIP(host) ? undefined : host,
      headers: { "User-Agent": UA, Accept: "*/*", "Accept-Encoding": "gzip, deflate, br" },
      lookup: (h, o, cb) => (o && o.all) ? cb(null, [{ address: pinned.address, family: pinned.family }]) : cb(null, pinned.address, pinned.family),
      timeout: opts.timeoutMs,
      rejectUnauthorized: !opts.insecureTls,
    }, (res) => {
      const base = { url: urlStr, status: res.statusCode, headers: res.headers };
      if (!wantBody || (res.statusCode >= 300 && res.statusCode < 400)) { res.destroy(); return resolve(base); }
      const enc = String(res.headers["content-encoding"] || "").toLowerCase();
      let stream = res;
      if (enc === "gzip" || enc === "x-gzip") stream = res.pipe(zlib.createGunzip());
      else if (enc === "deflate") stream = res.pipe(zlib.createInflate());
      else if (enc === "br") stream = res.pipe(zlib.createBrotliDecompress());
      const chunks = []; let size = 0; let done = false;
      const finish = (truncated) => { if (done) return; done = true; res.destroy(); resolve(Object.assign(base, { body: Buffer.concat(chunks).toString("utf8"), truncated: !!truncated })); };
      stream.on("data", (c) => { size += c.length; if (size > maxBytes) { chunks.push(c.subarray(0, c.length - (size - maxBytes))); finish(true); } else chunks.push(c); });
      stream.on("end", () => finish(false));
      stream.on("error", () => finish(true));
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (e) => reject(new Error(e.message === "timeout" ? "timeout" : (e.code || "request_failed"))));
    req.end();
  });
}
async function follow(startUrl, opts, getOpts) {
  let url = startUrl;
  for (let i = 0; i <= opts.maxRedirects; i++) {
    const r = await get(url, opts, getOpts);
    if (r.status >= 300 && r.status < 400 && r.headers.location) { url = new URL(r.headers.location, url).toString(); continue; }
    r.url = url;
    return r;
  }
  throw new Error("too_many_redirects");
}
async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; try { out[k] = await fn(items[k]); } catch (e) { out[k] = { url: items[k], status: 0, error: e.message }; } } }));
  return out;
}
function sameSite(u, host) {
  try {
    const h = new URL(u).hostname.toLowerCase();
    const base = host.replace(/^www\./, "");
    return h === host || h === base || h.endsWith("." + base);
  } catch { return false; }
}

/** Run every passive check against one URL. Returns a report object. */
async function scan(rawUrl, options) {
  const opts = Object.assign({}, DEFAULTS, options || {});
  const target = normalizeTarget(rawUrl, opts);
  const startPath = (() => { try { const u = new URL(/^[a-z]+:/i.test(rawUrl.trim()) ? rawUrl.trim() : "https://" + rawUrl.trim()); return u.pathname + u.search; } catch { return "/"; } })();
  const scheme = opts.scheme || "https";
  const errors = {};
  const [httpR, httpsR] = await Promise.allSettled([
    get("http://" + (opts.httpHostport || target.hostport.replace(/:443$/, "")) + "/", opts, { wantBody: false }),
    follow(scheme + "://" + target.hostport + startPath, opts, { maxBytes: 2 * 1024 * 1024 }),
  ]);
  if (httpR.status === "rejected") errors.http = httpR.reason.message;
  if (httpsR.status === "rejected") errors.https = httpsR.reason.message;
  if (errors.http === "blocked_host" || errors.https === "blocked_host") throw new Error("blocked_host");
  if (httpR.status === "rejected" && httpsR.status === "rejected") throw new Error(errors.https || "unreachable");
  const home = httpsR.status === "fulfilled" ? httpsR.value : null;
  const finalUrl = home ? home.url : null;
  const html = home && home.body ? home.body : "";
  const baseUrl = finalUrl || ("http://" + target.hostport + "/");

  // Scripts the page references (same site only), plus chunks those bundles import.
  let scriptUrls = core.extractScriptUrls(html, baseUrl).filter((u) => sameSite(u, target.host)).slice(0, opts.maxScripts);
  let scripts = await pool(scriptUrls, opts.concurrency, (u) => get(u, opts, { maxBytes: opts.maxJsBytes }));
  const more = [];
  for (const s of scripts) if (s && s.status === 200) for (const c of core.extractChunkUrls(s.body, s.url, opts.maxScripts)) if (!scriptUrls.includes(c) && !more.includes(c) && sameSite(c, target.host)) more.push(c);
  const room = Math.max(0, opts.maxScripts - scriptUrls.length);
  if (room && more.length) scripts = scripts.concat(await pool(more.slice(0, room), opts.concurrency, (u) => get(u, opts, { maxBytes: opts.maxJsBytes })));
  scripts = scripts.filter((s) => s && s.status === 200 && !/text\/html/i.test(String(s.headers && s.headers["content-type"] || "")));

  // Source maps: the ones bundles point to, plus "<bundle>.map" for the first few bundles.
  const mapUrls = []; let inlineMaps = 0;
  for (const s of scripts) {
    const ref = core.sourceMapRef(s.body, s.headers, s.url);
    if (ref && ref.inline) inlineMaps++;
    if (ref && ref.url && !mapUrls.includes(ref.url) && sameSite(ref.url, target.host)) mapUrls.push(ref.url);
  }
  for (const s of scripts.slice(0, 3)) { const g = s.url.split("?")[0] + ".map"; if (!mapUrls.includes(g)) mapUrls.push(g); }
  const maps = await pool(mapUrls.slice(0, opts.maxMaps), opts.concurrency, (u) => get(u, opts, { maxBytes: 256 * 1024 }));

  // Well-known public files, one plain GET each.
  const origin = (finalUrl ? new URL(finalUrl).origin : "http://" + target.hostport);
  const probe = (p) => get(origin + p, opts, { maxBytes: opts.maxProbeBytes }).then((r) => Object.assign(r, { path: p })).catch((e) => ({ path: p, status: 0, error: e.message }));
  const [env1, env2, env3, gitHead, gitConfig] = await Promise.all(["/.env", "/.env.local", "/.env.production", "/.git/HEAD", "/.git/config"].map(probe));

  const ev = core.evaluate({
    target, finalUrl,
    https: home ? { status: home.status, headers: home.headers } : null,
    http: httpR.status === "fulfilled" ? { status: httpR.value.status, headers: httpR.value.headers } : null,
    html, scripts, maps: maps.filter(Boolean), inlineMaps,
    probes: { env: [env1, env2, env3], gitHead, gitConfig },
    errors,
  });
  const report = {
    tool: "milokits-launch-check", version: core.VERSION, target: rawUrl, host: target.host, finalUrl, platform: ev.platform,
    checkedAt: new Date().toISOString(), results: ev.results, summary: core.summarize(ev.results),
    requests: 2 + scriptUrls.length + Math.min(more.length, room) + Math.min(mapUrls.length, opts.maxMaps) + 5,
    freeCheck: core.FREE_CHECK_URL, disclaimer: core.DISCLAIMER,
  };
  return report;
}

const MESSAGES = {
  bad_url: "That doesn't look like a valid web address.", bad_scheme: "Only http:// and https:// addresses can be checked.",
  bad_port: "Only standard web ports (80 and 443) can be checked (use --allow-private for local test servers).",
  blocked_host: "That address points to a private or internal network. Use --allow-private only for your own local test server.",
  dns_fail: "Couldn't find that domain. Check the spelling.", timeout: "The site took too long to answer.",
  too_many_redirects: "The site redirected too many times.",
};
module.exports = { scan, normalizeTarget, blockedIP, MESSAGES, UA };

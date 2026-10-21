/*
 * Milo's Launch Check: core rules (shared by the CLI, the GitHub Action and the browser extension).
 * Pure functions only: no network, no file system. Everything here works on data that was
 * already fetched with plain, passive GET requests.
 * MIT License. https://milokits.com
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.LaunchCheckCore = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const VERSION = "1.0.0";
  const SITE = "https://milokits.com";
  const FREE_CHECK_URL = SITE + "/?utm_source=launch-check&utm_medium=tool#free";
  const DISCLAIMER =
    "This is a passive check of public responses only (headers, public files and public JavaScript). " +
    "It is not a full security audit and can't prove an app is secure. Only check sites you own or are allowed to test.";

  const SIX_MONTHS = 15552000;
  const RANK = { pass: 0, info: 0, skip: 0, warn: 1, fail: 2 };

  // ---------- helpers
  function lower(headers) {
    const out = {};
    if (!headers) return out;
    if (typeof headers.forEach === "function" && !Array.isArray(headers) && typeof headers.get === "function") {
      headers.forEach((v, k) => { out[String(k).toLowerCase()] = String(v); });
      return out;
    }
    for (const k of Object.keys(headers)) {
      const v = headers[k];
      out[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
    }
    return out;
  }

  function mask(value) {
    const s = String(value);
    if (s.length <= 8) return s.slice(0, 2) + "…";
    const keep = Math.min(8, Math.max(4, Math.floor(s.length / 6)));
    return s.slice(0, keep) + "…(" + s.length + " chars)";
  }

  function b64urlDecode(seg) {
    let s = seg.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    if (typeof atob === "function") {
      try { return decodeURIComponent(escape(atob(s))); } catch (e) { try { return atob(s); } catch (e2) { return null; } }
    }
    if (typeof Buffer !== "undefined") return Buffer.from(s, "base64").toString("utf8");
    return null;
  }

  function jwtPayload(token) {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const txt = b64urlDecode(parts[1]);
    if (!txt) return null;
    try { const p = JSON.parse(txt); return p && typeof p === "object" ? p : null; } catch (e) { return null; }
  }

  // ---------- secret patterns (pattern match only; values are always masked)
  const SECRET_RULES = [
    { id: "supabase-secret", severity: "fail", name: "Supabase secret key (sb_secret_)", re: /\bsb_secret_[A-Za-z0-9_-]{20,}/g },
    { id: "stripe-live-secret", severity: "fail", name: "Stripe live secret or restricted key", re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g },
    { id: "stripe-test-secret", severity: "warn", name: "Stripe test secret key", re: /\bsk_test_[A-Za-z0-9]{20,}/g },
    { id: "openai", severity: "fail", name: "OpenAI API key", re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g },
    { id: "anthropic", severity: "fail", name: "Anthropic API key", re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}/g },
    { id: "aws-access-key", severity: "fail", name: "AWS access key ID", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
    { id: "github-token", severity: "fail", name: "GitHub token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{50,}/g },
    { id: "slack-token", severity: "fail", name: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g },
    { id: "sendgrid", severity: "fail", name: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
    { id: "resend", severity: "fail", name: "Resend API key", re: /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}\b/g },
    { id: "private-key", severity: "fail", name: "Private key block", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g },
  ];
  const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

  /**
   * Scan text for secret-looking patterns. Returns masked findings only.
   * Supabase JWTs are decoded locally: role "service_role" is a failure, role "anon" is expected and fine.
   */
  function scanSecrets(text, source) {
    const findings = [];
    if (!text) return findings;
    const seen = new Set();
    for (const rule of SECRET_RULES) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(text)) !== null) {
        const key = rule.id + ":" + m[0];
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({ id: rule.id, severity: rule.severity, name: rule.name, masked: mask(m[0]), source: source || null });
        if (findings.length > 50) return findings;
      }
    }
    JWT_RE.lastIndex = 0;
    let j;
    while ((j = JWT_RE.exec(text)) !== null) {
      if (seen.has("jwt:" + j[0])) continue;
      seen.add("jwt:" + j[0]);
      const p = jwtPayload(j[0]);
      if (!p) continue;
      if (p.role === "service_role") {
        findings.push({ id: "supabase-service-role", severity: "fail", name: "Supabase service_role key (bypasses RLS)", masked: "eyJ…(JWT, role: service_role)", source: source || null });
      } else if (p.role === "anon" && p.iss && /supabase/i.test(String(p.iss))) {
        findings.push({ id: "supabase-anon", severity: "info", name: "Supabase anon (public) key", masked: "eyJ…(JWT, role: anon)", source: source || null });
      }
    }
    return findings;
  }

  // ---------- extracting what to fetch next (still passive: only URLs the page itself references)
  function extractScriptUrls(html, baseUrl, limit) {
    const out = [];
    const add = (raw) => {
      if (!raw || /^(data|blob|javascript):/i.test(raw)) return;
      let u;
      try { u = new URL(raw, baseUrl); } catch (e) { return; }
      if (u.protocol !== "https:" && u.protocol !== "http:") return;
      const s = u.toString().split("#")[0];
      if (!out.includes(s)) out.push(s);
    };
    if (!html) return out;
    const scriptRe = /<script\b[^>]*?\bsrc\s*=\s*["']?([^"'\s>]+)/gi;
    const preloadRe = /<link\b[^>]*?\brel\s*=\s*["']?(?:modulepreload|preload)[^>]*>/gi;
    let m;
    while ((m = scriptRe.exec(html)) !== null) add(m[1]);
    while ((m = preloadRe.exec(html)) !== null) {
      const tag = m[0];
      if (/\bas\s*=\s*["']?(?!script)/i.test(tag) && !/modulepreload/i.test(tag)) continue;
      const h = tag.match(/\bhref\s*=\s*["']?([^"'\s>]+)/i);
      if (h) add(h[1]);
    }
    return typeof limit === "number" ? out.slice(0, limit) : out;
  }

  /** JS chunks referenced from inside a bundle (Vite/Webpack style "assets/x.js"). */
  function extractChunkUrls(js, bundleUrl, limit) {
    const out = [];
    if (!js) return out;
    const re = /["'`]((?:\.{1,2}\/|\/)?(?:assets|static\/js|_next\/static\/chunks)\/[A-Za-z0-9_.\-\/]+?\.m?js)["'`]/g;
    let m;
    while ((m = re.exec(js)) !== null) {
      let u;
      try { u = new URL(m[1], bundleUrl); } catch (e) { continue; }
      // "assets/x.js" without ./ is usually relative to the site root in Vite builds
      if (!/^[./]/.test(m[1])) { try { u = new URL("/" + m[1], bundleUrl); } catch (e) { continue; } }
      const s = u.toString();
      if (!out.includes(s)) out.push(s);
      if (typeof limit === "number" && out.length >= limit) break;
    }
    return out;
  }

  function sourceMapRef(js, headers, jsUrl) {
    const h = lower(headers);
    const fromHeader = h["sourcemap"] || h["x-sourcemap"];
    let ref = fromHeader || null;
    if (!ref && js) {
      const tail = js.slice(-2000);
      const m = tail.match(/[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*(?:\*\/)?\s*$/);
      if (m) ref = m[1];
    }
    if (!ref || /^data:/i.test(ref)) return ref ? { url: null, inline: true } : null;
    try { return { url: new URL(ref, jsUrl).toString(), inline: false }; } catch (e) { return null; }
  }

  function looksLikeSourceMap(res) {
    if (!res || res.status !== 200 || !res.body) return false;
    const b = res.body.trimStart();
    return b.startsWith("{") && /"mappings"\s*:/.test(b) && /"sources"\s*:/.test(b);
  }
  function looksLikeHtml(res) {
    const ct = (lower(res && res.headers)["content-type"] || "").toLowerCase();
    const b = (res && res.body ? res.body : "").trimStart().slice(0, 200).toLowerCase();
    return ct.includes("text/html") || b.startsWith("<!doctype") || b.startsWith("<html") || b.startsWith("<");
  }
  function envFileExposed(res) {
    if (!res || res.status !== 200 || !res.body || looksLikeHtml(res)) return null;
    const lines = res.body.split(/\r?\n/).filter((l) => /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/.test(l));
    return lines.length >= 1 ? { variables: lines.length } : null;
  }
  function gitExposed(headRes, configRes) {
    const head = headRes && headRes.status === 200 && headRes.body && !looksLikeHtml(headRes) &&
      /^(?:ref:\s*refs\/|[0-9a-f]{40}\s*$)/.test(headRes.body.trim());
    const cfg = configRes && configRes.status === 200 && configRes.body && !looksLikeHtml(configRes) &&
      /\[core\]/.test(configRes.body);
    return !!(head || cfg);
  }

  // ---------- platform hint for fixes (same as the milokits.com instant check)
  function platform(h) {
    const s = (h["server"] || "").toLowerCase();
    if (s.includes("netlify") || h["x-nf-request-id"]) return "Netlify";
    if (s.includes("vercel") || h["x-vercel-id"]) return "Vercel";
    if (s.includes("cloudflare") || h["cf-ray"]) return "Cloudflare";
    return null;
  }
  function where(p) {
    return p === "Netlify" ? "On Netlify, use a _headers file or netlify.toml."
      : p === "Vercel" ? "On Vercel, use the headers section of vercel.json (or headers() in next.config.js)."
      : p === "Cloudflare" ? "On Cloudflare, use a _headers file (Pages) or a Transform Rule."
      : "Use your hosting platform's way of setting HTTP response headers.";
  }

  /**
   * Turn fetched facts into results.
   * input = {
   *   target, finalUrl,
   *   https: { status, headers } | null,          // final HTTPS response for the homepage
   *   http:  { status, headers } | null,          // first response to http://host/ (not followed)
   *   httpFinalUrl: string | null,                // where http:// ended up (browser mode only)
   *   scripts: [{ url, status, headers, body }],  // public JS the page references
   *   html: string,                               // homepage HTML (scanned for inline secrets)
   *   maps: [{ url, status, headers, body }],     // source map URLs fetched
   *   inlineMaps: number,
   *   probes: { env: [{path,status,headers,body}], gitHead, gitConfig },
   *   errors: { https?: string, http?: string }
   * }
   */
  function evaluate(input) {
    const results = [];
    const add = (id, group, status, label, detail, fix) => results.push({ id, group, status, label, detail: detail || "", fix: status === "pass" || status === "info" || status === "skip" ? null : (fix || null) });
    const h = lower(input.https && input.https.headers);
    const plat = input.https ? platform(h) : null;
    const W = where(plat);
    const csp = h["content-security-policy"] || "";

    // Transport
    const httpsOk = !!input.https && String(input.finalUrl || "").startsWith("https://");
    add("https", "Transport", httpsOk ? "pass" : "fail", "HTTPS works",
      httpsOk ? "Loads over HTTPS with a valid certificate." : "Couldn't load the site over HTTPS" + (input.errors && input.errors.https ? " (" + input.errors.https + ")" : "") + ".",
      "Enable automatic HTTPS on your host and make every page load over https://.");

    let redirOk = false, redirDetail = "";
    if (input.httpFinalUrl) {
      redirOk = /^https:\/\//i.test(input.httpFinalUrl);
      redirDetail = "http:// ended at " + input.httpFinalUrl.slice(0, 80);
    } else if (input.http) {
      const loc = lower(input.http.headers)["location"] || "";
      let abs = "";
      try { abs = loc ? new URL(loc, "http://" + (input.target && input.target.host || "x") + "/").toString() : ""; } catch (e) { abs = ""; }
      redirOk = input.http.status >= 300 && input.http.status < 400 && /^https:\/\//i.test(abs);
      redirDetail = "http:// answered " + input.http.status + (loc ? " → " + loc.slice(0, 80) : "");
    } else {
      redirDetail = "http:// didn't answer" + (input.errors && input.errors.http ? " (" + input.errors.http + ")" : "");
      // No plain HTTP listener at all is acceptable when HSTS is set.
    }
    add("redirect", "Transport", redirOk ? "pass" : "warn", "HTTP redirects to HTTPS", redirDetail,
      "Add a permanent (301) redirect from every http:// URL to the same https:// URL. Most hosts have a \"Force HTTPS\" setting for this.");

    // Headers (same rules as the milokits.com instant check)
    const hsts = h["strict-transport-security"] || "";
    const m = hsts.match(/max-age=(\d+)/i);
    const hstsOk = !!m && +m[1] >= SIX_MONTHS;
    add("hsts", "Headers", hstsOk ? "pass" : "warn", "Strict-Transport-Security (HSTS)",
      m ? (hstsOk ? "max-age=" + m[1] : "max-age=" + m[1] + " is under 6 months") : "Header missing",
      'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains". ' + W);
    add("csp", "Headers", csp ? "pass" : "warn", "Content-Security-Policy",
      csp ? (/unsafe-inline/.test(csp) && /script-src[^;]*unsafe-inline/.test(csp) ? "Set (script-src allows 'unsafe-inline')" : "Set") : "Header missing",
      "Add a Content-Security-Policy. Start with Content-Security-Policy-Report-Only, list the domains your app really uses, and include frame-ancestors 'none'; object-src 'none'; base-uri 'self'. " + W);
    const frameOk = !!h["x-frame-options"] || /frame-ancestors/i.test(csp);
    add("frame", "Headers", frameOk ? "pass" : "warn", "Clickjacking protection (XFO / frame-ancestors)",
      frameOk ? (h["x-frame-options"] ? "X-Frame-Options: " + h["x-frame-options"] : "CSP frame-ancestors set") : "Neither header is set",
      'Add "X-Frame-Options: DENY" and frame-ancestors \'none\' in your CSP. ' + W);
    const nosniff = /nosniff/i.test(h["x-content-type-options"] || "");
    add("nosniff", "Headers", nosniff ? "pass" : "warn", "X-Content-Type-Options: nosniff",
      nosniff ? "Set" : "Header missing", 'Add "X-Content-Type-Options: nosniff" to every response. ' + W);
    const rp = h["referrer-policy"];
    add("referrer", "Headers", rp ? "pass" : "warn", "Referrer-Policy", rp ? rp : "Header missing",
      'Add "Referrer-Policy: strict-origin-when-cross-origin". ' + W);
    const pp = h["permissions-policy"];
    add("permissions", "Headers", pp ? "pass" : "warn", "Permissions-Policy", pp ? "Set" : "Header missing",
      'Add "Permissions-Policy: camera=(), microphone=(), geolocation=()" and allow only what your app uses. ' + W);

    // Public JavaScript: secrets
    const scripts = (input.scripts || []).filter((s) => s && s.status === 200 && typeof s.body === "string");
    const secretFindings = [];
    if (input.html) secretFindings.push(...scanSecrets(input.html, input.finalUrl || "homepage HTML"));
    for (const s of scripts) secretFindings.push(...scanSecrets(s.body, s.url));
    const bad = secretFindings.filter((f) => f.severity === "fail");
    const meh = secretFindings.filter((f) => f.severity === "warn");
    const anon = secretFindings.filter((f) => f.id === "supabase-anon");
    let secStatus = bad.length ? "fail" : meh.length ? "warn" : "pass";
    const describe = (list) => list.slice(0, 5).map((f) => f.name + " " + f.masked + " in " + shortUrl(f.source)).join("; ");
    add("secrets", "Public JavaScript", secStatus, "No secret keys in public JavaScript",
      bad.length || meh.length ? describe(bad.concat(meh)) + (bad.length + meh.length > 5 ? " (+" + (bad.length + meh.length - 5) + " more)" : "")
        : "Scanned " + scripts.length + " script" + (scripts.length === 1 ? "" : "s") + " and the homepage HTML" + (anon.length ? ". Supabase anon key found (that one is meant to be public; protect data with RLS)" : ""),
      "Treat the key as leaked: rotate it now in the provider's dashboard, then move the call that needs it to a server function (Supabase Edge Function, Netlify/Vercel function) and keep the key in server-side environment variables only.");

    // Source maps
    const maps = (input.maps || []).filter(looksLikeSourceMap);
    const withSource = maps.filter((m2) => /"sourcesContent"\s*:\s*\[\s*"/.test(m2.body || ""));
    add("sourcemaps", "Public JavaScript", maps.length ? "warn" : "pass", "Source maps not public",
      maps.length ? maps.length + " public source map" + (maps.length === 1 ? "" : "s") + (withSource.length ? " with full original source" : "") + ", e.g. " + shortUrl(maps[0].url)
        : (input.inlineMaps ? "No .map files public (" + input.inlineMaps + " inline map" + (input.inlineMaps === 1 ? "" : "s") + " found inside bundles)" : "No public .map files found"),
      "Turn off public source maps in production (Vite: build.sourcemap = false or 'hidden'; then don't deploy the .map files).");

    // Public files
    const envHits = (input.probes && input.probes.env || []).map((r) => ({ r, e: envFileExposed(r) })).filter((x) => x.e);
    add("env", "Public files", envHits.length ? "fail" : "pass", "No public .env file",
      envHits.length ? envHits.map((x) => x.r.path + " is public (" + x.e.variables + " variable" + (x.e.variables === 1 ? "" : "s") + "; values not shown)").join("; ") : "Checked " + ((input.probes && input.probes.env || []).map((r) => r.path).join(", ") || "/.env"),
      "Delete the file from your public/build folder, block it at your host, and rotate every key it contained.");
    const git = gitExposed(input.probes && input.probes.gitHead, input.probes && input.probes.gitConfig);
    add("git", "Public files", git ? "fail" : "pass", "No public .git folder",
      git ? "/.git/ is readable, so your source code and history can be downloaded" : "Checked /.git/HEAD and /.git/config",
      "Stop deploying the .git folder (deploy only your build output) and rotate any secrets that were ever committed.");

    return { results, platform: plat, findings: secretFindings };
  }

  function shortUrl(u) {
    if (!u) return "?";
    try { const x = new URL(u); const p = x.pathname.length > 40 ? "…" + x.pathname.slice(-38) : x.pathname; return p || "/"; } catch (e) { return String(u).slice(0, 40); }
  }

  function summarize(results) {
    const count = { pass: 0, warn: 0, fail: 0 };
    for (const r of results) if (count[r.status] !== undefined) count[r.status]++;
    const headerIds = ["hsts", "csp", "frame", "nosniff", "referrer", "permissions"];
    const hdr = results.filter((r) => headerIds.includes(r.id));
    const headerScore = hdr.filter((r) => r.status === "pass").length;
    const worst = results.reduce((w, r) => (RANK[r.status] > RANK[w] ? r.status : w), "pass");
    return { count, headerScore, headerTotal: hdr.length, grade: grade(headerScore, hdr.length), worst };
  }
  function grade(n, total) {
    const r = total ? n / total : 0;
    return r === 1 ? "A" : r >= 0.83 ? "B" : r >= 0.66 ? "C" : r >= 0.5 ? "D" : "F";
  }
  function exceeds(results, threshold) {
    const t = String(threshold || "none").toLowerCase();
    if (t === "none" || t === "off" || t === "never") return false;
    const lim = t === "warn" ? 1 : 2;
    return results.some((r) => RANK[r.status] >= lim);
  }

  const ICON = { pass: "✅", warn: "⚠️", fail: "❌", info: "ℹ️", skip: "⏭️" };
  function toMarkdown(report) {
    const s = report.summary;
    const lines = [];
    lines.push("## Milo's Launch Check: " + report.host);
    lines.push("");
    lines.push("**Header score " + s.headerScore + "/" + s.headerTotal + " (" + s.grade + ")** · " + s.count.pass + " passed · " + s.count.warn + " warnings · " + s.count.fail + " failed");
    lines.push("");
    lines.push("| Status | Check | Details |");
    lines.push("|---|---|---|");
    for (const r of report.results) lines.push("| " + ICON[r.status] + " " + r.status.toUpperCase() + " | " + esc(r.label) + " | " + esc(r.detail) + " |");
    const fixes = report.results.filter((r) => r.fix);
    if (fixes.length) {
      lines.push("");
      lines.push("### How to fix");
      for (const r of fixes) lines.push("- **" + esc(r.label) + ":** " + esc(r.fix));
    }
    lines.push("");
    lines.push("Want a person to look at the parts a passive check can't see (database rules, auth, storage)? Get the free mini-check at [milokits.com](" + FREE_CHECK_URL + ").");
    lines.push("");
    lines.push("<sub>" + DISCLAIMER + " Checked " + report.checkedAt + " by launch-check v" + VERSION + ".</sub>");
    return lines.join("\n");
  }
  function esc(s) { return String(s == null ? "" : s).replace(/\|/g, "\\|").replace(/\r?\n/g, " "); }

  return {
    VERSION, SITE, FREE_CHECK_URL, DISCLAIMER, SECRET_RULES,
    lower, mask, jwtPayload, scanSecrets, extractScriptUrls, extractChunkUrls, sourceMapRef,
    looksLikeSourceMap, envFileExposed, gitExposed, evaluate, summarize, exceeds, toMarkdown, platform,
  };
});

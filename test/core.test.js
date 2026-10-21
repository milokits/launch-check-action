"use strict";
const test = require("node:test");
const assert = require("node:assert");
const core = require("../src/core");
const { fake } = require("./fixtures");

const GOOD_HEADERS = {
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  Server: "Netlify",
};
const base = (over) => Object.assign({
  target: { host: "example.com" }, finalUrl: "https://example.com/",
  https: { status: 200, headers: GOOD_HEADERS }, http: { status: 301, headers: { location: "https://example.com/" } },
  html: "<html></html>", scripts: [], maps: [], probes: { env: [{ path: "/.env", status: 404, body: "" }], gitHead: { status: 404 }, gitConfig: { status: 404 } },
}, over);
const byId = (r, id) => r.results.find((x) => x.id === id);

test("good site passes everything with an A", () => {
  const r = core.evaluate(base());
  const s = core.summarize(r.results);
  assert.strictEqual(s.headerScore, 6);
  assert.strictEqual(s.grade, "A");
  assert.strictEqual(s.count.fail, 0);
  assert.strictEqual(s.count.warn, 0);
  assert.strictEqual(r.platform, "Netlify");
  assert.strictEqual(core.exceeds(r.results, "warn"), false);
});

test("header rules mirror the milokits.com instant check", () => {
  const r = core.evaluate(base({ https: { status: 200, headers: { "strict-transport-security": "max-age=600", "x-frame-options": "DENY" } } }));
  assert.strictEqual(byId(r, "hsts").status, "warn");          // under 6 months
  assert.match(byId(r, "hsts").detail, /under 6 months/);
  assert.strictEqual(byId(r, "frame").status, "pass");         // XFO alone is enough
  assert.strictEqual(byId(r, "csp").status, "warn");
  assert.strictEqual(byId(r, "nosniff").status, "warn");
  const r2 = core.evaluate(base({ https: { status: 200, headers: { "content-security-policy": "frame-ancestors 'self'" } } }));
  assert.strictEqual(byId(r2, "frame").status, "pass");        // frame-ancestors alone is enough
});

test("https failure and missing redirect", () => {
  const r = core.evaluate(base({ https: null, finalUrl: null, http: { status: 200, headers: {} }, errors: { https: "ECONNREFUSED" } }));
  assert.strictEqual(byId(r, "https").status, "fail");
  assert.strictEqual(byId(r, "redirect").status, "warn");
  const r2 = core.evaluate(base({ http: { status: 301, headers: { location: "http://example.com/x" } } }));
  assert.strictEqual(byId(r2, "redirect").status, "warn");     // redirect that stays on http
  const r3 = core.evaluate(base({ http: null, httpFinalUrl: "https://example.com/" }));
  assert.strictEqual(byId(r3, "redirect").status, "pass");     // browser mode
});

test("secret scanning flags service_role and live keys, masks values", () => {
  const js = `const a="${fake.serviceRole}";const b="${fake.stripeLive}";const c="${fake.openai}";const d="${fake.aws}";const e="${fake.github}";`;
  const f = core.scanSecrets(js, "https://example.com/assets/index.js");
  const ids = f.map((x) => x.id).sort();
  assert.deepStrictEqual(ids, ["aws-access-key", "github-token", "openai", "stripe-live-secret", "supabase-service-role"]);
  for (const x of f) {
    assert.ok(x.masked.includes("…"), "value is masked");
    assert.ok(x.masked.length < 40, "masked value is short");
  }
  const json = JSON.stringify(f);
  for (const secret of [fake.serviceRole, fake.stripeLive, fake.openai, fake.github]) assert.ok(!json.includes(secret), "full secret never appears in findings");
});

test("anon key is fine, test key is a warning", () => {
  const f = core.scanSecrets(`x="${fake.anon}"`, "a.js");
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].severity, "info");
  const r = core.evaluate(base({ scripts: [{ url: "https://example.com/a.js", status: 200, body: `k="${fake.anon}";t="${fake.stripeTest}"` }] }));
  assert.strictEqual(byId(r, "secrets").status, "warn");
});

test("no false positives on ordinary code", () => {
  const js = 'const sk="sk-" + id; var task_live_count=3; const skeleton="sk-loading"; fetch("/api"); // AKIA is a word';
  assert.deepStrictEqual(core.scanSecrets(js, "a.js"), []);
});

test("SPA fallback HTML is not mistaken for .env or .git", () => {
  const html = { status: 200, headers: { "content-type": "text/html" }, body: "<!doctype html><html><body>APP=1</body></html>" };
  assert.strictEqual(core.envFileExposed(Object.assign({ path: "/.env" }, html)), null);
  assert.strictEqual(core.gitExposed(html, html), false);
  assert.deepStrictEqual(core.envFileExposed({ status: 200, headers: { "content-type": "text/plain" }, body: "A=1\nB=2\n# c\n" }), { variables: 2 });
  assert.strictEqual(core.gitExposed({ status: 200, headers: {}, body: "ref: refs/heads/main\n" }, null), true);
  assert.strictEqual(core.gitExposed(null, { status: 200, headers: {}, body: "[core]\n\trepositoryformatversion = 0\n" }), true);
});

test("source map detection", () => {
  const ref = core.sourceMapRef("console.log(1)\n//# sourceMappingURL=index.js.map", {}, "https://example.com/assets/index.js");
  assert.deepStrictEqual(ref, { url: "https://example.com/assets/index.js.map", inline: false });
  assert.deepStrictEqual(core.sourceMapRef("x\n//# sourceMappingURL=data:application/json;base64,e30=", {}, "https://e.com/a.js"), { url: null, inline: true });
  assert.strictEqual(core.sourceMapRef("x", { SourceMap: "/m.map" }, "https://e.com/a.js").url, "https://e.com/m.map");
  assert.ok(core.looksLikeSourceMap({ status: 200, body: '{"version":3,"sources":["a.ts"],"mappings":"AAAA"}' }));
  assert.ok(!core.looksLikeSourceMap({ status: 200, body: "<!doctype html>" }));
});

test("script and chunk extraction", () => {
  const html = '<script type="module" crossorigin src="/assets/index-abc.js"></script><link rel="modulepreload" href="/assets/vendor-1.js"><script src="https://cdn.example.net/x.js"></script><link rel="preload" as="style" href="/a.css">';
  const urls = core.extractScriptUrls(html, "https://example.com/");
  assert.deepStrictEqual(urls, ["https://example.com/assets/index-abc.js", "https://cdn.example.net/x.js", "https://example.com/assets/vendor-1.js"]);
  const chunks = core.extractChunkUrls('import("./Dash-9f.js");const m=["assets/Settings-1a.js"]', "https://example.com/assets/index-abc.js");
  assert.deepStrictEqual(chunks, ["https://example.com/assets/Settings-1a.js"]);
});

test("fail-on thresholds", () => {
  const rs = [{ status: "pass" }, { status: "warn" }];
  assert.strictEqual(core.exceeds(rs, "fail"), false);
  assert.strictEqual(core.exceeds(rs, "warn"), true);
  assert.strictEqual(core.exceeds([{ status: "fail" }], "none"), false);
  assert.strictEqual(core.exceeds([{ status: "fail" }], "fail"), true);
});

test("markdown summary has table, free check link and disclaimer", () => {
  const r = core.evaluate(base());
  const md = core.toMarkdown({ host: "example.com", results: r.results, summary: core.summarize(r.results), checkedAt: "2026-10-21T00:00:00Z" });
  assert.match(md, /\| Status \| Check \| Details \|/);
  assert.match(md, /milokits\.com/);
  assert.match(md, /not a full security audit/);
  assert.doesNotMatch(md, /second opinion/i);
});

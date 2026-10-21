"use strict";
// Integration tests against local servers (http only, so they run with --allow-private).
const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const path = require("path");
const { execFile } = require("child_process");
const { scan, normalizeTarget } = require("../src/scan");
const { fake } = require("./fixtures");

function serve(handler) {
  return new Promise((res) => { const s = http.createServer(handler); s.listen(0, "127.0.0.1", () => res(s)); });
}
const leakyApp = (req, res) => {
  const send = (code, type, body, extra) => { res.writeHead(code, Object.assign({ "Content-Type": type }, extra || {})); res.end(body); };
  if (req.method !== "GET") return send(405, "text/plain", "no");
  switch (req.url) {
    case "/": return send(200, "text/html", '<!doctype html><script type="module" src="/assets/index-abc.js"></script>');
    case "/assets/index-abc.js": return send(200, "application/javascript", `const s="${fake.serviceRole}";import("./Dash-1.js");const c=["assets/Dash-1.js"];\n//# sourceMappingURL=index-abc.js.map`);
    case "/assets/Dash-1.js": return send(200, "application/javascript", `const k="${fake.stripeLive}";`);
    case "/assets/index-abc.js.map": return send(200, "application/json", '{"version":3,"sources":["src/App.tsx"],"sourcesContent":["export default 1"],"mappings":"AAAA"}');
    case "/.env": return send(200, "text/plain", "VITE_SUPABASE_URL=x\nSUPABASE_SERVICE_ROLE_KEY=y\n");
    case "/.git/HEAD": return send(200, "text/plain", "ref: refs/heads/main\n");
    default: return send(404, "text/plain", "not found");
  }
};
const spaApp = (req, res) => {
  // Every path returns the app shell with 200, like most SPA hosts.
  if (req.url.endsWith(".js")) { res.writeHead(200, { "Content-Type": "application/javascript" }); return res.end(`const anon="${fake.anon}";`); }
  res.writeHead(200, { "Content-Type": "text/html", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff" });
  res.end('<!doctype html><div id="root"></div><script type="module" src="/assets/app.js"></script>');
};

test("refuses private targets unless allowed", () => {
  assert.throws(() => normalizeTarget("http://127.0.0.1/", {}), /blocked_host/);
  assert.throws(() => normalizeTarget("http://localhost/", {}), /blocked_host/);
  assert.throws(() => normalizeTarget("http://10.1.2.3/", {}), /blocked_host/);
  assert.throws(() => normalizeTarget("https://example.com:8443/", {}), /bad_port/);
  assert.throws(() => normalizeTarget("ftp://example.com/", {}), /bad_scheme/);
  assert.doesNotThrow(() => normalizeTarget("example.com", {}));
});

test("leaky app: finds secrets, source map, .env and .git, never prints full secrets", async () => {
  const s = await serve(leakyApp);
  const hp = "127.0.0.1:" + s.address().port;
  try {
    const r = await scan("http://" + hp + "/", { allowPrivate: true, scheme: "http", httpHostport: hp, timeoutMs: 3000 });
    const st = Object.fromEntries(r.results.map((x) => [x.id, x.status]));
    assert.strictEqual(st.https, "fail");
    assert.strictEqual(st.secrets, "fail");
    assert.strictEqual(st.sourcemaps, "warn");
    assert.strictEqual(st.env, "fail");
    assert.strictEqual(st.git, "fail");
    assert.strictEqual(r.summary.headerScore, 0);
    const detail = r.results.find((x) => x.id === "secrets").detail;
    assert.match(detail, /service_role/);
    assert.match(detail, /Stripe live/);           // found in the lazily loaded chunk
    const all = JSON.stringify(r);
    for (const secret of [fake.serviceRole, fake.stripeLive]) assert.ok(!all.includes(secret));
    assert.ok(!all.includes("SUPABASE_SERVICE_ROLE_KEY=y"), ".env values are never included");
  } finally { s.close(); }
});

test("SPA fallback: 200 HTML on every path is not flagged as .env/.git", async () => {
  const s = await serve(spaApp);
  const hp = "127.0.0.1:" + s.address().port;
  try {
    const r = await scan("http://" + hp + "/", { allowPrivate: true, scheme: "http", httpHostport: hp, timeoutMs: 3000 });
    const st = Object.fromEntries(r.results.map((x) => [x.id, x.status]));
    assert.strictEqual(st.env, "pass");
    assert.strictEqual(st.git, "pass");
    assert.strictEqual(st.secrets, "pass");          // anon key only
    assert.strictEqual(st.sourcemaps, "pass");
    assert.strictEqual(st.frame, "pass");
    assert.strictEqual(st.nosniff, "pass");
  } finally { s.close(); }
});

test("CLI: requires ownership confirmation and honours --fail-on", async () => {
  const s = await serve(leakyApp);
  const hp = "127.0.0.1:" + s.address().port;
  const bin = path.join(__dirname, "..", "bin", "launch-check.js");
  const run = (args) => new Promise((res) => execFile(process.execPath, [bin, ...args], { env: Object.assign({}, process.env, { NO_COLOR: "1" }) }, (err, stdout, stderr) => res({ code: err ? err.code : 0, stdout, stderr })));
  try {
    const noConsent = await run(["http://" + hp + "/", "--allow-private"]);
    assert.strictEqual(noConsent.code, 2);
    assert.match(noConsent.stderr, /--i-own-this/);
    const common = ["http://" + hp + "/", "--i-own-this", "--allow-private", "--scheme", "http", "--http-hostport", hp, "--timeout", "3000"];
    const failing = await run(common);
    assert.strictEqual(failing.code, 1);
    assert.match(failing.stdout, /FAIL/);
    assert.match(failing.stdout, /milokits\.com/);
    const lenient = await run([...common, "--fail-on", "none", "--json"]);
    assert.strictEqual(lenient.code, 0);
    assert.strictEqual(JSON.parse(lenient.stdout).tool, "milokits-launch-check");
  } finally { s.close(); }
});

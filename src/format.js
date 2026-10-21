"use strict";
const core = require("./core");
const C = (process.env.NO_COLOR || !process.stdout.isTTY) ? { g: "", y: "", r: "", d: "", b: "", x: "" }
  : { g: "\x1b[32m", y: "\x1b[33m", r: "\x1b[31m", d: "\x1b[2m", b: "\x1b[1m", x: "\x1b[0m" };
const TAG = { pass: C.g + "PASS" + C.x, warn: C.y + "WARN" + C.x, fail: C.r + "FAIL" + C.x, info: "INFO", skip: "SKIP" };
function pad(s, n) { s = String(s); return s.length >= n ? s.slice(0, n - 1) + "…" : s + " ".repeat(n - s.length); }
function toTable(report) {
  const s = report.summary;
  const out = [];
  out.push(C.b + "Milo's Launch Check" + C.x + "  " + report.host + (report.platform ? C.d + "  (" + report.platform + ")" + C.x : ""));
  out.push("Header score " + s.headerScore + "/" + s.headerTotal + " (" + s.grade + ")   " + s.count.pass + " passed, " + s.count.warn + " warnings, " + s.count.fail + " failed");
  out.push("");
  out.push(pad("STATUS", 8) + pad("CHECK", 50) + "DETAILS");
  out.push("-".repeat(100));
  for (const r of report.results) out.push(TAG[r.status] + "    " + pad(r.label, 50) + C.d + r.detail + C.x);
  const fixes = report.results.filter((r) => r.fix);
  if (fixes.length) { out.push(""); out.push(C.b + "How to fix" + C.x); for (const r of fixes) out.push("- " + r.label + ": " + r.fix); }
  out.push("");
  out.push("Free mini-check (a person looks at what a passive check can't see): " + core.FREE_CHECK_URL);
  out.push(C.d + core.DISCLAIMER + C.x);
  return out.join("\n");
}
module.exports = { toTable, toMarkdown: core.toMarkdown };

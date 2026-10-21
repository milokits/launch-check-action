// GitHub Action entry point. No dependencies: reads inputs from INPUT_* env vars and writes
// outputs, annotations and the job summary with the standard runner files.
"use strict";
const fs = require("fs");
const path = require("path");
const { scan, MESSAGES } = require("./scan");
const { toTable, toMarkdown } = require("./format");
const core = require("./core");

function input(name, def) {
  const v = process.env["INPUT_" + name.replace(/ /g, "_").toUpperCase()];
  return v === undefined || v === "" ? def : v.trim();
}
function setOutput(k, v) {
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, k + "=" + String(v).replace(/\r?\n/g, " ") + "\n");
}
function esc(s) { return String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A"); }

async function run() {
  const url = input("url");
  const owner = String(input("i-own-this", "false")).toLowerCase() === "true";
  const failOn = String(input("fail-on", "fail")).toLowerCase();
  const timeoutMs = parseInt(input("timeout-ms", "8000"), 10) || 8000;
  if (!url) { console.log("::error::Input 'url' is required."); return 2; }
  if (!owner) { console.log("::error::Set 'i-own-this: true' to confirm you own this site or are allowed to test it."); return 2; }
  if (!["fail", "warn", "none"].includes(failOn)) { console.log("::error::'fail-on' must be fail, warn or none."); return 2; }

  let report;
  // LAUNCH_CHECK_ALLOW_PRIVATE=true lets self-hosted runners check their own internal staging hosts.
  const allowPrivate = process.env.LAUNCH_CHECK_ALLOW_PRIVATE === "true";
  try { report = await scan(url, { timeoutMs, allowPrivate }); }
  catch (e) { console.log("::error::Launch Check couldn't run: " + esc(MESSAGES[e.message] || e.message)); return 3; }

  console.log(toTable(report));
  for (const r of report.results) {
    if (r.status === "fail") console.log("::error title=" + esc(r.label) + "::" + esc(r.detail + (r.fix ? " Fix: " + r.fix : "")));
    else if (r.status === "warn") console.log("::warning title=" + esc(r.label) + "::" + esc(r.detail + (r.fix ? " Fix: " + r.fix : "")));
  }
  const md = toMarkdown(report);
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + "\n");
  const out = path.join(process.env.RUNNER_TEMP || process.cwd(), "launch-check-report.json");
  fs.writeFileSync(out, JSON.stringify(report, null, 2));
  const s = report.summary;
  setOutput("header-score", s.headerScore + "/" + s.headerTotal);
  setOutput("grade", s.grade);
  setOutput("passed", s.count.pass);
  setOutput("warnings", s.count.warn);
  setOutput("failed", s.count.fail);
  setOutput("report-path", out);
  if (core.exceeds(report.results, failOn)) {
    console.log("::error::Launch Check found results at or above the fail-on level (" + failOn + ").");
    return 1;
  }
  return 0;
}
run().then((c) => { process.exitCode = c; });

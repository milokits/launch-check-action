#!/usr/bin/env node
"use strict";
const fs = require("fs");
const { scan, MESSAGES } = require("../src/scan");
const { toTable, toMarkdown } = require("../src/format");
const core = require("../src/core");

const HELP = `Milo's Launch Check v${core.VERSION}: passive security check for a site you own.

Usage:
  launch-check <url> --i-own-this [options]

Options:
  --i-own-this         Confirm you own the site or are allowed to test it (required)
  --fail-on <level>    Exit 1 when a result is at least this bad: fail (default), warn, none
  --json               Print the full report as JSON
  --markdown           Print a Markdown summary (what the GitHub Action writes to the job summary)
  --summary <file>     Also append the Markdown summary to <file>
  --timeout <ms>       Per-request timeout (default 8000)
  --allow-private      Allow localhost/private IPs and custom ports (for your own local test server)
  -h, --help           Show this help

What it does: plain GET requests to your homepage, the JavaScript files it references, their source
maps, and /.env, /.env.local, /.env.production, /.git/HEAD and /.git/config. Nothing else.
${core.DISCLAIMER}
Free mini-check: ${core.FREE_CHECK_URL}`;

function parse(argv) {
  const a = { failOn: "fail", timeoutMs: 8000 };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === "-h" || k === "--help") a.help = true;
    else if (k === "--i-own-this" || k === "--yes") a.owner = true;
    else if (k === "--json") a.json = true;
    else if (k === "--markdown") a.markdown = true;
    else if (k === "--allow-private") a.allowPrivate = true;
    else if (k === "--insecure-tls") a.insecureTls = true;
    else if (k === "--fail-on") a.failOn = argv[++i];
    else if (k.startsWith("--fail-on=")) a.failOn = k.split("=")[1];
    else if (k === "--summary") a.summary = argv[++i];
    else if (k === "--timeout") a.timeoutMs = parseInt(argv[++i], 10) || 8000;
    else if (k === "--scheme") a.scheme = argv[++i]; // test hook
    else if (k === "--http-hostport") a.httpHostport = argv[++i]; // test hook
    else if (!k.startsWith("-") && !a.url) a.url = k;
    else { a.error = "Unknown option " + k; }
  }
  return a;
}

async function main() {
  const a = parse(process.argv.slice(2));
  if (a.help || (!a.url && !a.error)) { console.log(HELP); return 0; }
  if (a.error) { console.error(a.error + "\n\n" + HELP); return 2; }
  if (!["fail", "warn", "none"].includes(String(a.failOn).toLowerCase())) { console.error("--fail-on must be fail, warn or none"); return 2; }
  if (!a.owner && process.env.LAUNCH_CHECK_I_OWN_THIS !== "true") {
    console.error("Please confirm you own this site or are allowed to test it: add --i-own-this.\nOnly check sites you own or have permission to test.");
    return 2;
  }
  let report;
  try {
    report = await scan(a.url, { timeoutMs: a.timeoutMs, allowPrivate: !!a.allowPrivate, insecureTls: !!a.insecureTls, scheme: a.scheme, httpHostport: a.httpHostport });
  } catch (e) {
    console.error("Launch Check couldn't run: " + (MESSAGES[e.message] || e.message));
    return 3;
  }
  const md = toMarkdown(report);
  if (a.json) console.log(JSON.stringify(report, null, 2));
  else if (a.markdown) console.log(md);
  else console.log(toTable(report));
  if (a.summary) fs.appendFileSync(a.summary, md + "\n");
  return core.exceeds(report.results, a.failOn) ? 1 : 0;
}
if (require.main === module) main().then((c) => { process.exitCode = c; });
module.exports = { parse, main };

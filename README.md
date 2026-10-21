# Milo's Launch Check (CLI + GitHub Action)

A free, open-source, **passive** security check for a live site you own. Built for apps made with Lovable, Bolt, Cursor, v0 and friends, where the risky bits are usually in public: missing security headers, secret keys shipped in the JavaScript bundle, public source maps, or a `.env` file that got deployed.

Zero dependencies. Runs as a GitHub Action or from the command line with Node 18+.

```
Milo's Launch Check  your-app.example  (Netlify)
Header score 4/6 (C)   7 passed, 4 warnings, 1 failed

STATUS  CHECK                                             DETAILS
----------------------------------------------------------------------------------------------------
PASS    HTTPS works                                       Loads over HTTPS with a valid certificate.
WARN    HTTP redirects to HTTPS                           http:// didn't answer (ECONNREFUSED)
PASS    Strict-Transport-Security (HSTS)                  max-age=31536000
WARN    Content-Security-Policy                           Header missing
PASS    Clickjacking protection (XFO / frame-ancestors)   X-Frame-Options: DENY
PASS    X-Content-Type-Options: nosniff                   Set
PASS    Referrer-Policy                                   strict-origin-when-cross-origin
WARN    Permissions-Policy                                Header missing
FAIL    No secret keys in public JavaScript               Supabase service_role key (bypasses RLS) eyJ…(JWT, role: service_role) in /assets/index-abc.js
WARN    Source maps not public                            1 public source map with full original source, e.g. /assets/index-abc.js.map
PASS    No public .env file                               Checked /.env, /.env.local, /.env.production
PASS    No public .git folder                             Checked /.git/HEAD and /.git/config
```

## What it checks

| Group | Check | Result if it's wrong |
|---|---|---|
| Transport | HTTPS works | fail |
| Transport | `http://` redirects to `https://` | warn |
| Headers | Strict-Transport-Security (at least 6 months) | warn |
| Headers | Content-Security-Policy | warn |
| Headers | X-Frame-Options or CSP `frame-ancestors` | warn |
| Headers | X-Content-Type-Options: nosniff | warn |
| Headers | Referrer-Policy | warn |
| Headers | Permissions-Policy | warn |
| Public JavaScript | Secret keys in the homepage and its same-site JS bundles: Supabase `service_role` JWTs and `sb_secret_` keys, Stripe `sk_live_`/`rk_live_`, OpenAI, Anthropic, AWS, GitHub, Slack, SendGrid, Resend keys, private key blocks | fail (Stripe test keys: warn) |
| Public JavaScript | Public source maps (`.map` files) | warn |
| Public files | `/.env`, `/.env.local`, `/.env.production` | fail |
| Public files | `/.git/HEAD`, `/.git/config` | fail |

Secrets are matched by pattern and always **masked** (for example `sk_live_…(32 chars)`); the full value is never printed, logged or stored. A Supabase **anon** key is expected in a frontend and isn't flagged: protect your data with Row Level Security instead.

The header rules are the same ones the free instant check on [milokits.com](https://milokits.com/?utm_source=launch-check&utm_medium=readme) uses.

## What it does NOT do

Everything is a plain `GET`, the same request any visitor's browser makes:

- the page you give it, plus one request to `http://` to see if it redirects,
- the JavaScript files that page itself references (same site only, up to 20), and the source maps they point to,
- the five well-known file paths listed above.

No logins, no form submissions, no POST/PUT/DELETE, no payloads, no fuzzing, no port scanning, no attempts to get around authentication. Private and internal network addresses are refused by default. Response bodies are read with a size cap and thrown away after the check.

## Use it as a GitHub Action

```yaml
# .github/workflows/launch-check.yml
name: Launch Check
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 8 * * 1"   # every Monday
  workflow_dispatch:

permissions:
  contents: read

jobs:
  launch-check:
    runs-on: ubuntu-latest
    steps:
      - uses: milokits/launch-check-action@v1
        id: check
        with:
          url: https://your-app.example.com
          i-own-this: "true"
          fail-on: fail
```

The results show up as a table in the job summary, as annotations on the run, and as outputs.

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `url` | yes | | The live URL of a site you own or are allowed to test |
| `i-own-this` | yes | `false` | Set to `"true"` to confirm you own the site or may test it |
| `fail-on` | no | `fail` | `fail`: fail the job on real exposures only. `warn`: also on missing headers. `none`: never fail |
| `timeout-ms` | no | `8000` | Per-request timeout |

### Outputs

`header-score` (e.g. `5/6`), `grade` (A to F), `passed`, `warnings`, `failed`, `report-path` (full JSON report).

## Use it from the command line

```bash
npx github:milokits/launch-check-action https://your-app.example.com --i-own-this
# or, from a clone:
node bin/launch-check.js https://your-app.example.com --i-own-this --fail-on warn
```

| Option | Description |
|---|---|
| `--i-own-this` | Confirm you own the site or may test it (required) |
| `--fail-on fail\|warn\|none` | Exit code 1 when a result is at least this bad (default `fail`) |
| `--json` | Full report as JSON |
| `--markdown` | Markdown summary |
| `--summary <file>` | Append the Markdown summary to a file |
| `--timeout <ms>` | Per-request timeout |
| `--allow-private` | Allow localhost, private IPs and custom ports, for your own local test server |

Exit codes: `0` OK, `1` threshold reached, `2` usage error, `3` the site couldn't be checked.

## Something failed. Now what?

Each problem comes with a short fix you can paste into your AI builder. If a key was found, **rotate it first**: once a key has been public, assume someone has it.

A passive check only sees the outside. It can't see your database rules, auth settings or storage policies, which is where most data leaks in AI-built apps happen. For that, get the **free mini-check** at [milokits.com](https://milokits.com/?utm_source=launch-check&utm_medium=readme#free): a person looks at the public side of your live app and emails you your top 3 issues, each with a fix prompt.

## Development

```bash
npm test   # node:test, no dependencies
```

Fake keys used in the tests are assembled at runtime, so the repository doesn't contain anything that looks like a real secret.

## Disclaimer

This is a passive check of public responses only. It is not a full security audit, it can miss things, and a clean result doesn't mean an app is secure. Only check sites you own or are allowed to test.

## License

MIT © Milo Kits · [milokits.com](https://milokits.com) · hello@milokits.com

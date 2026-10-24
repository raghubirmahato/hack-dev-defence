# Lab demo: deliberately vulnerable login origin (`lab/demo/vuln_login`)

**WARNING: this application is intentionally vulnerable. It exists only as the
"without HDD" target for the HK1 demo rehearsal. Never expose it beyond loopback.
It is lab-only, is not part of any shipped binary, and is not a product.**

`app.py` is a single-file Python 3 app (standard library + `sqlite3` only, no pip
install). It builds its login query by string concatenation on purpose:

```python
sql = "SELECT id, username, role FROM users WHERE username='%s' AND password='%s'" % (username, password)
```

That is the vulnerability the HK1 demo is about: a real string-concatenated SQL
query executed by a real SQL engine (SQLite), not a fake query evaluator and not
payload special-casing. The app exists so the demo can show that HDD blocks the
payload through the proxy even though the origin itself is injectable.

## Run it (loopback only)

```bash
python lab/demo/vuln_login/app.py          # http://127.0.0.1:8081/login
```

- Bind address: `127.0.0.1:8081` by default (`--host` / `--port`, `HDD_VULN_HOST`,
  `HDD_VULN_PORT`). The process refuses any non-loopback bind address.
- Seed users (`admin`, `demo`, `auditor`) are created at start with randomly
  generated passwords printed once to the console. There is no hardcoded default
  password and no password file. Restarting regenerates them.
- Routes: `/login` (form; a GET with `username`/`password` query values also runs
  the same query so the query-string vector is real), `/admin` (only after a
  successful login), `/logout`, `/healthz`.
- Every login attempt prints the exact SQL it executed, so the rehearsal log shows
  the injection honestly.

## Verified direct behaviour (no HDD), 12 demo payloads

Measured with `lab/demo/attack.ps1` / `attack.sh` against this app (POST form and
GET query string give the same result; the payload is sent in both the username and
password fields). "Yes" means the response was the admin page.

| id | group | payload | direct result on SQLite |
| --- | --- | --- | --- |
| M1 | mandated | `' OR 1=1--` | **yes** (tautology + comment) |
| M2 | mandated | `' OR '1'='1` | **yes** (string tautology) |
| M3 | mandated | `admin' --` | **yes** (comment truncation) |
| M4 | mandated | `admin' #` | no (HTTP 500: SQLite has no `#` comment; unrecognized token) |
| M5 | mandated | `admin'/*` | **yes** (SQLite treats the unterminated `/*` as a comment to end of input) |
| M6 | mandated | `' or 1=1 LIMIT 1 --` | **yes** (tautology + row limiter + comment) |
| B1 | auth-bypass | `admin'--` | **yes** |
| B2 | auth-bypass | `admin' or '1'='1` | **yes** |
| B3 | auth-bypass | `admin') or ('1'='1` | no (HTTP 500: parentheses this query shape does not have) |
| B4 | auth-bypass | `' or 1=1#` | no (HTTP 500: `#` is not SQLite syntax) |
| B5 | auth-bypass | `" or ""="` | no (runs, but matches no row on this app) |
| B6 | auth-bypass | `admin'/*` | **yes** (same payload string as M5; kept as a distinct auth-bypass label) |

Summary: **8/12 reach the admin page directly**; the six mandated payloads are
M1, M2, M3, M5, M6. M4 is the one mandated payload that is dialect-invalid here.
This is expected: spec `docs/SPEC.md` E1.1 and P28 record that some mandated payloads
are dialect-invalid on a given endpoint (direct outcomes are recorded per endpoint;
"direct exploit failed because of syntax" is distinguished from "blocked"), and the
demo documentation states it instead of pretending all six exploit this engine.

Through HDD in `block` mode all **12/12** payloads must get HTTP 403 with a block
page/Ray ID and the source must be banned; the two dialect-invalid payloads are
blocked just as well because the detector works on intent, not on the origin's
SQL dialect.

## Demo use

```bash
# direct origin ("before"): several payloads reach /admin
pwsh -File lab/demo/attack.ps1 -TargetUrl http://127.0.0.1:8081
# through HDD ("after"): all 12 must be blocked and the source banned
pwsh -File lab/demo/attack.ps1 -TargetUrl http://127.0.0.1:8080
```

The full 10-minute rehearsal script is [`docs/DEMO.md`](../../../docs/DEMO.md).
The scripts enforce the target allowlist in `lab/demo/targets.allow` (operator
created; loopback is always allowed) and cap the request rate at 2 req/s. They only
send the 12 catalogue payloads to the login endpoint: no scanning, no other attack
classes, never a third-party target.

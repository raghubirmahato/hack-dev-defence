# `lab/demo`: HK1 rehearsal kit (lab only, never shipped)

This directory holds the local rehearsal material for the HK1 hackathon demo. It is
**lab-only**: it is not part of any shipped binary or Cargo graph, is not referenced
from the product crates, and must never be deployed or exposed beyond loopback.

| Path | What |
| --- | --- |
| `vuln_login/app.py` + `vuln_login/README.md` | deliberately vulnerable single-file Python login app (loopback `127.0.0.1:8081`), real concatenated SQL query, README states the vulnerability and the verified direct results |
| `payloads.tsv` | the demo payload catalogue: the six mandated SQL-injection payloads M1-M6 (`docs/SPEC.md` C4.1/E1.1) and the six auth-bypass forms B1-B6; read by both attack scripts |
| `attack.ps1` | Windows PowerShell 5.1+/7 attack script: login POSTs and GET query strings, per-request output, final "reached admin / blocked yes/no per payload" table, 2 req/s cap, allowlist refusal |
| `attack.sh` | bash twin of `attack.ps1` (Linux/macOS/Git Bash) |
| `targets.allow.example` | template for the operator-created allowlist; copy to `targets.allow` (one operator-authorised host per line). Loopback is always allowed |
| `shop/` | a separate, older Vercel/serverless lab artifact; not used by the HK1 local stack |

## Rules of the road

- **Loopback only for the rehearsal.** The lab app refuses a non-loopback bind address
  and every launcher keeps it on `127.0.0.1`. Never expose it through a tunnel, port
  forward, reverse proxy or public interface - not even "briefly for a demo".
- **Operator-authorised targets only.** Both attack scripts refuse any non-loopback
  target that is not listed in `lab/demo/targets.allow`, before sending anything. There
  is no scanning, no other paths, no other attack classes, and never a third-party host.
- **Rate cap.** The scripts space requests at 2 req/s (500 ms minimum) and send 24
  requests per run (12 payloads x POST + GET). A run takes about 12 seconds.
- **Lab only, no product claims.** These files are demo material; they are not a
  security product and make no protection claim. See `docs/DEMO.md` for the honest
  limits and the live-site checklist.

## Quick use

```bash
# local stack (vulnerable origin 8081 + HDD proxy 8080 + dashboard 9090)
npm run dev

# direct origin ("before"): several payloads reach the admin page
npm run attack -- --target http://127.0.0.1:8081
# or directly:
pwsh -File lab/demo/attack.ps1 -TargetUrl http://127.0.0.1:8081

# through HDD in block mode ("after"): all 12 must be blocked and the source banned
npm run attack -- --target http://127.0.0.1:8080
# or directly:
pwsh -File lab/demo/attack.ps1 -TargetUrl http://127.0.0.1:8080
```

The full 10-minute demo script: [`docs/DEMO.md`](../../docs/DEMO.md).

## CoreByte shop on Vercel: lock and front door

The shop in `shop/` locks itself as soon as `HDD_ORIGIN_SECRET` is set: a request without HDD's secret header is refused (403).
Optional settings (all environment variables):

| Variable | Effect |
| --- | --- |
| `HDD_ORIGIN_SECRET` | The secret HDD sends in `X-HDD-Origin-Secret`. Setting it turns the lock on. (`ORIGIN_SECRET_VALUE` is the older name and loses to this one.) |
| `HDD_GATE_URL` | Front-door mode: a request without the secret is passed to HDD at this URL, so the visitor stays on the shop's own address and HDD's mode (off, monitor, block) decides. If HDD cannot be reached the request gets a 503: the shop is never served uninspected. Add an HDD site whose host is this URL's host and whose origin is another alias of the same Vercel project. |
| `HDD_PUBLIC_URL` | Only a link on the refusal page ("Open the shop through HDD"). |
| `ORIGIN_LOCKDOWN=0` | Manual escape hatch: turns the lock off. The shop is then not protected by HDD. |

Never add a `middleware.ts` to this project: it needs Next.js and fails every request here.

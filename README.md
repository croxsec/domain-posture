# domain-posture

Passive external security posture scan. Measures **only what an unauthenticated observer can see** — nothing touches the target beyond what any visitor's browser would do.

Built by [CROX Sec](https://croxsec.com) after auditing 84 web agencies in 14 countries with it. Aggregate findings: 51% DMARC at `p=none`, 67% no HSTS, 26% `/wp-login.php` answering 200. [Full study](https://croxsec.surge.sh/estudio-2026.html).

## What it checks

| Area | Checks |
|---|---|
| DNS | SPF, DMARC (policy + reporting), CAA, MX |
| TLS | protocol versions offered, cert validity window |
| HTTP | redirect to HTTPS, HSTS header, security headers |
| Exposure | `/wp-login.php` reachable, `/.git/HEAD`, `/server-status`, common backup files |

## Requirements

Python 3.9+ and standard UNIX tools: `dig`, `openssl`, `curl`. No pip install, no API keys.

## Usage

```bash
# scan a list of domains (one per line)
python3 domainposture.py domains.txt > report.json

# render a client-facing HTML report
python3 domainposture.py --html report.json > report.html
```

Example `domains.txt`:

```
example.com
client-site.net
```

## What the output looks like

Each domain becomes a record like:

```json
{
  "domain": "example.com",
  "spf": true,
  "dmarc": "p=none",
  "dmarc_enforced": false,
  "caa": false,
  "tls": ["TLSv1.2", "TLSv1.3"],
  "hsts": false,
  "redirects_to_https": true,
  "wp_login_200": false,
  "notes": []
}
```

## Methodology (why this is safe to run anywhere)

- Only DNS queries, TLS handshakes, and plain HTTPS GETs of public paths.
- No crawling beyond a fixed short list, no payloads, no rate stress (serial per domain, ~4 rps max across workers).
- Suitable for auditing your own infrastructure, or demonstrating posture gaps to a client before they sign anything.

## License

MIT — see [LICENSE](LICENSE).

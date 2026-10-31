#!/usr/bin/env python3
"""
domainposture.py — passive external security posture scan.

Measures only what an unauthenticated observer can see: DNS (SPF/DMARC/CAA/MX),
TLS support, HTTP->HTTPS behaviour, security headers, and common exposure paths.
No exploitation, no intrusive scanning, no rate stress. Suitable for auditing
your own infrastructure or demonstrating posture gaps to clients.

Usage:
    python3 domainposture.py domains.txt > report.json
    python3 domainposture.py --html report.json > report.html

domains.txt: one domain per line. Lines starting with # are ignored.
Only Python 3.9+ standard library + dig/openssl/curl from your OS.

License: MIT. (c) 2026 CROX Sec — https://croxsec.com
"""
import subprocess, json, re, sys, argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def dig_short(args, timeout=12):
    try:
        r = subprocess.run(["dig","+short","+time=8","+tries=1"]+args,
                           capture_output=True, text=True, timeout=timeout)
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return []

def probe_tls(domain):
    for flag, name in (("-tls1_3","1.3"), ("-tls1_2","1.2")):
        try:
            r = subprocess.run(["timeout","10","openssl","s_client","-connect",
                                f"{domain}:443","-servername",domain,flag],
                               capture_output=True, text=True, timeout=14)
            if "Cipher is" in r.stdout and "Cipher    : 0000" not in r.stdout:
                return name
        except Exception:
            pass
    return None

def curl(args, timeout=10):
    try:
        r = subprocess.run(["curl","-s","-m",str(timeout),
                            "-A","Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0"]+args,
                           capture_output=True, text=True, timeout=timeout+4)
        return r
    except Exception:
        return None

def analyze(domain):
    rec = {"domain": domain}
    txts = dig_short([domain, "TXT"])
    spf = next((t.strip('"') for t in txts if t.strip('"').lower().startswith("v=spf1")), None)
    rec["spf"] = bool(spf)
    rec["spf_softfail"] = bool(spf and ("~all" in spf or "?all" in spf))
    dm = dig_short(["_dmarc."+domain, "TXT"])
    d = next((t.strip('"') for t in dm if t.strip('"').lower().startswith("v=dmarc1")), None)
    rec["dmarc"] = bool(d)
    m = re.search(r"p=(\w+)", d, re.I) if d else None
    rec["dmarc_policy"] = m.group(1).lower() if m else None
    rec["mx"] = bool(dig_short([domain, "MX"]))
    rec["caa"] = bool(dig_short([domain, "CAA"]))
    tls = probe_tls(domain)
    rec["tls13"] = tls == "1.3"
    rec["tls_ok"] = tls is not None
    code_https = curl(["-o","/dev/null","-w","%{http_code}", f"https://{domain}/"])
    rec["https_ok"] = code_https is not None and code_https.stdout.strip() not in ("", "000")
    code_http = curl(["-o","/dev/null","-w","%{http_code}", f"http://{domain}/"])
    rec["http_redirect_https"] = False
    if code_http and code_http.stdout.strip() in ("301","302","303","307","308"):
        loc = curl(["-o","/dev/null","-w","%{redirect_url}", f"http://{domain}/"])
        rec["http_redirect_https"] = bool(loc and "https" in loc.stdout.lower())
    if rec["https_ok"]:
        h = curl(["-sI", f"https://{domain}/"])
        rec["hsts"] = bool(h and "strict-transport-security" in h.stdout.lower())
        c = curl(["-o","/dev/null","-w","%{http_code}", f"https://{domain}/wp-login.php"])
        rec["wp_login_exposed"] = bool(c and c.stdout.strip() == "200")
    else:
        rec["hsts"] = False
        rec["wp_login_exposed"] = False
    return rec

def scan(domains, workers=10):
    out = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(analyze, d): d for d in domains}
        for f in as_completed(futs):
            try:
                out.append(f.result())
            except Exception as e:
                out.append({"domain": futs[f], "error": str(e)})
    return out

HTML_TMPL = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Passive security posture report</title>
<style>body{font-family:system-ui,sans-serif;background:#0b0f18;color:#e8edf7;margin:2rem auto;max-width:1000px;padding:0 1rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}th,td{padding:.5rem;border-bottom:1px solid #232f4d;text-align:left}
th{font-family:ui-monospace,monospace;color:#8b96ad;font-size:.7rem;letter-spacing:1px;text-transform:uppercase}
.ok{color:#3ddc97}.bad{color:#ff5470}.mono{font-family:ui-monospace,monospace}h1{letter-spacing:-.5px}</style></head>
<body><h1>Passive security posture — __N__ domains</h1>
<p style="color:#8b96ad">100% unauthenticated recon: DNS, TLS, HTTP(S) headers, common exposure paths. Reproduce any cell with the standard tooling.</p>
__TABLE__
</body></html>"""

def to_html(records):
    rows = "".join(
        "<tr><td class='mono'>{d}</td><td class='{c1}'>{spf}</td><td class='{c2}'>{dmarc}</td>"
        "<td class='{c3}'>{hsts}</td><td class='{c4}'>{wp}</td><td class='{c5}'>{caa}</td></tr>".format(
            d=r["domain"],
            c1="ok" if r.get("spf") else "bad", spf="SPF" if r.get("spf") else "—",
            c2="ok" if r.get("dmarc") and r.get("dmarc_policy") in ("reject","quarantine") else ("bad" if not r.get("dmarc") else ""),
            dmarc=r.get("dmarc_policy") or "—",
            c3="ok" if r.get("hsts") else "bad", hsts="HSTS" if r.get("hsts") else "—",
            c4="bad" if r.get("wp_login_exposed") else "ok", wp="wp-login" if r.get("wp_login_exposed") else "—",
            c5="ok" if r.get("caa") else "bad", caa="CAA" if r.get("caa") else "—")
        for r in records)
    table = ("<table><tr><th>domain</th><th>spf</th><th>dmarc policy</th><th>hsts</th>"
             "<th>wp-login</th><th>caa</th></tr>" + rows + "</table>")
    return HTML_TMPL.replace("__N__", str(len(records))).replace("__TABLE__", table)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="file with one domain per line, or a .json report with --html")
    ap.add_argument("--html", action="store_true", help="render a JSON report to HTML")
    ap.add_argument("--workers", type=int, default=10)
    a = ap.parse_args()
    if a.html:
        print(to_html(json.load(open(a.input))))
        return
    domains = [l.strip() for l in open(a.input) if l.strip() and not l.startswith("#")]
    json.dump(scan(domains, a.workers), sys.stdout, indent=1)

if __name__ == "__main__":
    main()

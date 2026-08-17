# nmap-recon.sh

Automated Nmap reconnaissance wrapper that runs a full recon workflow against a single target — DNS/WHOIS lookups, proxy/CDN fingerprinting, host discovery, a full port scan, service/version detection, OS detection, SSL/TLS inspection, an optional UDP scan, and optional vulnerability scripts — and writes it all into one consolidated report plus machine-readable CSVs.

> ⚠️ **This tool is for authorized security testing only.** See [Legal / Ethical Notice](#legal--ethical-notice) below before you run it.

---

## What it does

The script runs in 8 phases against a target you specify:

| Phase | What happens |
|---|---|
| 1 | DNS records (A/AAAA/MX/NS/TXT/SOA/CNAME) + WHOIS (domain and IP/ASN) + passive proxy/CDN fingerprinting |
| 2 | Host discovery (`nmap -sn`) |
| 3 | Full TCP port scan across the requested port range |
| 4 | Service/version detection, default NSE scripts, OS detection, traceroute (only on ports found open in phase 3) |
| 5 | SSL/TLS certificate & cipher inspection on any open SSL/TLS ports |
| 6 | *(optional, `-u`)* UDP scan of the top 100 ports |
| 7 | Extended NSE scripts — safe scripts always, `vuln`/`vulners` CVE scripts if `-v` is passed |
| 8 | Consolidated summary + CSV reports + optional HTML report |

Every phase's raw output is kept, and everything is stitched into one human-readable report plus two CSVs.

## Requirements

- Linux or macOS with `bash`
- `nmap` (required — everything else is optional but recommended)
- `whois`, `dig` (or `host`), `curl`, `python3`, `xsltproc` — all optional; missing ones just disable that specific piece (WHOIS lookups, proxy detection, the full CSV, or the HTML report, respectively)
- `sudo`/root — not required, but unlocks SYN scanning (`-sS`), OS detection (`-O`), and the UDP scan

**You don't need to install anything yourself.** On startup the script checks for all of the above and auto-installs whatever's missing, using whichever package manager it finds (`apt`, `dnf`, `yum`, `pacman`, or `brew`), invoking `sudo` automatically if needed. Pass `--no-auto-install` if you'd rather manage packages yourself.

## Quick start

```bash
chmod +x nmap-recon.sh

# Simple scan, asks for authorization confirmation interactively
./nmap-recon.sh -t example.com

# Full scan: root privileges, full port range, UDP, vuln scripts, skip the prompt
sudo ./nmap-recon.sh -t https://example.com -p 1-65535 -u -v -y --timing 4
```

## Options

| Flag | Description |
|---|---|
| `-t`, `--target <target>` | Target IP, hostname, or URL (**required**) |
| `-o`, `--output <dir>` | Output directory (default: auto-generated, `./nmap_recon_<target>_<timestamp>/`) |
| `-p`, `--ports <range>` | Port range, e.g. `1-1000` (default: `1-65535`) |
| `-u`, `--udp` | Also run a top-100 UDP scan (slow, needs root) |
| `-v`, `--vuln` | Also run NSE `vuln` (+ `vulners` if installed) scripts and build a severity-sorted CVE triage table |
| `-6`, `--ipv6` | Resolve and scan the target over IPv6 |
| `--timing <0-5>` | Nmap timing template — `T0` (slowest/stealthiest) to `T5` (fastest/noisiest). Default: `4` |
| `--no-whois` | Skip the WHOIS / DNS reconnaissance phase |
| `--no-auto-install` | Don't auto-install missing dependencies — just warn and skip the phases that need them |
| `-y`, `--yes-i-am-authorized` | Skip the interactive authorization prompt (you're still asserting you're authorized) |
| `-h`, `--help` | Show help |

## Output

Everything lands in the output directory (`-o`, or auto-generated as `./nmap_recon_<target>_<timestamp>/`):

```
nmap_recon_example.com_20260817_143000/
├── consolidated_report.txt   # Full human-readable report — every phase + a
│                              # "CONSOLIDATED SUMMARY" section
├── summary.csv                # One row: target, IP, open ports, proxy/CDN,
│                              # DNS expiry, registrant email, hosting org & country
├── ports.csv                  # One row per open port: port,protocol,state,
│                              # service,product,version
├── report.html                # Optional pretty HTML (only if xsltproc is installed)
└── raw/                       # Raw output per phase
    ├── 01_whois_target.txt
    ├── 01_whois_ip.txt
    ├── 01_dns_records.txt
    ├── proxy_headers.txt
    ├── 02_host_discovery.{nmap,xml,gnmap}
    ├── 03_port_scan.{nmap,xml,gnmap}
    ├── 04_deep_scan.{nmap,xml,gnmap}
    ├── 05_ssl_scan.{nmap,xml,gnmap}
    ├── 06_udp_scan.{nmap,xml,gnmap}       (if -u)
    └── 07_nse_extended.{nmap,xml,gnmap}
```

### `consolidated_report.txt` — CONSOLIDATED SUMMARY section

This is the "just tell me the important stuff" section, at the end of the report and also printed to your terminal:

- **Target & resolved IP address**
- **Open ports** found in the scanned range
- **SSL/TLS ports** (if any)
- **Proxy/CDN detected** — e.g. Cloudflare, Akamai, Fastly, CloudFront (passive HTTP-header + hosting-org check — see note below)
- **Domain DNS expiry** — pulled from WHOIS
- **Registrant email** — pulled from WHOIS (often redacted, see note below)
- **Registrant organization** and **hosting org/country** — from domain and IP WHOIS

## Notes on the newer fields

- **Proxy/CDN detection is passive and best-effort.** It checks HTTP response headers and the hosting org's WHOIS name against known signatures for Cloudflare, Akamai, Fastly, Imperva/Incapsula, Sucuri, CloudFront, Azure Front Door, and Google Cloud. A "not detected" result means no known signature matched — it doesn't prove the target has no proxy in front of it.
- **Registrant email is frequently redacted.** Most registrars have hidden WHOIS contact emails by default since GDPR (2018). Seeing "not disclosed" or "REDACTED FOR PRIVACY" is expected, normal behavior — not a bug in the script.
- **CSV quality depends on `python3`.** With `python3` available, `ports.csv` includes full service/product/version detail parsed from nmap's XML output. Without it, the script falls back to a plain-text parse and leaves the product/version columns blank.

## Legal / Ethical Notice

This script performs **active network reconnaissance**: port scans, service/version probing, OS fingerprinting, default/vuln NSE scripts, and traceroute — all of which are detectable on the network you're scanning.

**Only run it against systems, networks, or URLs you own, or for which you hold explicit written authorization to test** (e.g. a signed penetration-testing engagement, or a bug-bounty program's in-scope assets).

Unauthorized scanning may violate laws such as the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent legislation elsewhere — even if no damage is caused.

This script gathers information only. It does not exploit, brute-force, or attack anything. You are solely responsible for how you use it — the script will ask you to confirm authorization interactively unless you pass `-y`/`--yes-i-am-authorized`, which only skips the prompt, not the requirement.

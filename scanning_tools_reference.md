# PentestBot v2 — Scanning Tools Reference

## Pipeline Stages & Tools Overview

The scan pipeline runs **10 active scanning stages** sequentially. The dashboard also exposes additional post-processing stages such as `Aggregation`, `AIAnalysis`, `Report`, and `Done`.

| # | Stage | Tool(s) | Purpose |
|---|-------|---------|---------|
| 1 | **Recon** | `subfinder`, `assetfinder`, `anew`, `amass`* | Subdomain enumeration — discovers all subdomains of the target via passive sources (cert transparency, APIs, DNS databases). `anew` deduplicates results. |
| 2 | **Resolver** | `dnsx` | DNS resolution — resolves all discovered subdomains to A, CNAME, MX, TXT, NS records. Builds an IP-to-hostname map. Falls back to Python `socket` if dnsx is missing. |
| 3 | **OriginIP** | `curl` (to crt.sh & HackerTarget APIs) | Origin IP discovery — tries to find the real server IP behind CDN/WAF proxies using DNS, certificate transparency, DNS history, and common bypass subdomains. |
| 4 | **PortScan** | `naabu` | Fast TCP port scanning — scans all resolved IPs for open ports. Uses rate-limiting and JSON output. Falls back to a Python socket scan if naabu is missing. |
| 5 | **ServiceScan** | `nmap` | Service detection & banner grabbing — runs versioned service detection (`-sV`), default scripts (`-sC`), and targeted NSE scripts (SSL, HTTP, FTP, SMTP, RDP, MongoDB, Redis, etc.). |
| 6 | **HTTPProbe** | `httpx` (ProjectDiscovery) | HTTP probing — probes all candidate web URLs for liveness, status code, page title, technologies, and web server headers. Falls back to `curl` if httpx is missing. |
| 7 | **Fingerprint** | `whatweb`, `wafw00f`, `webanalyze` | Technology fingerprinting & WAF detection — identifies CMS, frameworks, libraries, and WAFs running on the target. |
| 8 | **WebDiscovery** | `gau`, `katana` | Web attack surface expansion — `gau` pulls historical URLs from passive sources; `katana` crawls live endpoints to find additional paths and parameterized URLs. |
| 9 | **VulnScan** | `nuclei`, `nikto`, `sqlmap`*, `dalfox`*, `wpscan`*, `joomscan`* | Vulnerability scanning — template-based scanning (Nuclei), web server misconfiguration checks (Nikto), SQL injection checks (SQLMap), XSS checks on parameterized URLs (Dalfox), and CMS-specific scanners when detected. |
| 10 | **TLSScan** | `testssl.sh`, `sslyze`, `openssl` | TLS/SSL analysis — checks certificate validity, cipher suites, protocol versions, and known TLS vulnerabilities (BEAST, POODLE, Heartbleed, etc.). |

> [!NOTE]
> Tools marked with `*` are only enabled conditionally (deep mode or CMS detection).

---

## Quick Mode vs Deep Mode

The scan mode defaults to **Quick (fast)**. Deep mode applies overrides from [scan_profiles.py](file:///c:/Users/DELL/OneDrive/Dokumen/22.NarendraYudhistiraBagaskoro_XISIJA1/projectdashboard/backend/scan_profiles.py) on top of the base [config.py](file:///c:/Users/DELL/OneDrive/Dokumen/22.NarendraYudhistiraBagaskoro_XISIJA1/projectdashboard/backend/config.py).

### Parameter Comparison

| Parameter | Quick Mode (Default) | Deep Mode | Impact |
|-----------|---------------------|-----------|--------|
| **Port Scanning** ||||
| `naabu_top_ports` | `1000` | `"full"` (all 65535) | Deep scans every TCP port |
| `naabu_rate` | `1000` pps | `2000` pps | Faster packet rate in deep |
| `naabu_timeout` | `300s` (5 min) | `600s` (10 min) | Longer timeout for full scan |
| **Service Detection (nmap)** ||||
| `nmap_flags` | `-sV -sC` | `-sV -sC --script vuln` | Deep adds NSE vuln scripts |
| `nmap_timing` | `T4` (aggressive) | `T3` (normal) | Deep is more thorough, slower |
| `nmap_max_ports` | `50` | `200` | Deep fingerprints 4× more ports |
| `nmap_timeout` | `1800s` (30 min) | `3600s` (60 min) | Longer timeout for deep nmap |
| **HTTP Probing** ||||
| `httpx_threads` | `50` | `80` | Higher concurrency in deep |
| `httpx_rate_limit` | `150` req/s | `250` req/s | Faster probing in deep |
| **Web Discovery** ||||
| `katana_depth` | `2` levels | `4` levels | Deep crawls twice as deep |
| `katana_timeout` | `180s` | `360s` | Double crawl time budget |
| `gau_timeout` | `120s` | `240s` | Double passive URL collection time |
| `max_discovered_urls` | `150` | `500` | Deep retains 3.3× more URLs |
| **Nuclei (Vuln Scanner)** ||||
| `nuclei_severity` | `critical,high,medium` | `critical,high,medium,low` | Deep executes a broader nuclei template set |
| `nuclei_rate_limit` | `150` req/s | `250` req/s | Faster template scanning |
| `nuclei_timeout` | `1000s` | `1800s` (30 min) | 80% more scanning time |
| Max nuclei targets | `4` URLs | `12` URLs | 3× more endpoints scanned |
| **Pipeline Timeouts** ||||
| `stage_timeout` | `300s` (5 min) | `600s` (10 min) | Each stage gets double the time |
| `total_scan_timeout` | `3600s` (~60 min) | `14400s` (4 hours) | Entire scan can run significantly longer |

### Tools Only Enabled in Deep Mode

| Tool | Purpose | Timeout |
|------|---------|---------|
| `amass` | Comprehensive subdomain enumeration (heavier than subfinder) | 1800s |
| `nikto` | Web server misconfiguration & vulnerability scanner | 3600s |
| `dirsearch` | Directory & file brute-forcing | 480s |
| `s3scanner` | AWS S3 bucket misconfiguration scanning | 480s |

### Conditionally Enabled Tools

| Tool | Trigger Condition | Purpose |
|------|-------------------|---------|
| `wpscan` | WordPress detected in fingerprint stage (deep mode only) | WordPress-specific vulnerability scanning |
| `joomscan` | Joomla detected in fingerprint stage (deep mode only) | Joomla-specific vulnerability scanning |
| `dalfox` | `ENABLE_DALFOX=true` and parameterized URLs discovered | XSS scanning for query parameters discovered by WebDiscovery |

> [!IMPORTANT]
> WPScan and Joomscan are not force-enabled by deep mode alone. They are only queued when the relevant CMS is detected and the scan is already running in deep mode.

---

## What Gets Filtered

### 1. Nuclei Finding Filters

Nuclei results are filtered in [vuln_scan.py](file:///c:/Users/DELL/OneDrive/Dokumen/22.NarendraYudhistiraBagaskoro_XISIJA1/projectdashboard/backend/pipeline/vuln_scan.py) via `_is_reportable_nuclei_finding()`:

**Severity filter:** Only `critical`, `high`, and `medium` findings are currently retained as reportable findings. Deep mode still expands execution coverage and target count, but `low` findings are filtered before reporting.

**Excluded Template IDs** — these informational templates are always removed:

| Excluded Template ID | Reason |
|----------------------|--------|
| `rdap-whois` | WHOIS/RDAP lookup — informational only |
| `dns-waf-detect` | WAF detection — handled by wafw00f separately |
| `dns-caa` | CAA DNS record — informational |
| `dns-ns` | NS record — informational |
| `dns-mx` | MX record — informational |
| `dns-soa` | SOA record — informational |
| `ssl-dns-names` | SSL certificate DNS names — informational |
| `ssl-issuer` | SSL certificate issuer — informational |
| `tls-version` | TLS version detection — handled by testssl.sh |
| `http-missing-security-headers` | Missing headers — noisy, often low-value |

**Excluded Name Fragments** — findings with these in their name are dropped:

| Fragment | Reason |
|----------|--------|
| `rdap whois` | WHOIS lookup noise |
| `ns record` / `mx record` / `soa record` / `caa record` | DNS record enumeration — informational |
| `ssl dns names` / `detect ssl certificate issuer` | Certificate info — covered by TLS stage |
| `tls version` | Duplicate of TLS scan stage |
| `http missing security headers` | Low-signal, noisy |
| `dns waf detection` | Duplicate of wafw00f |

**Excluded Description Markers** — findings containing these phrases are dropped:

| Description Marker | Reason |
|--------------------|--------|
| `registration data access protocol` | RDAP informational |
| `an ns record was detected` | DNS info |
| `an mx record was detected` | DNS info |
| `a caa record was discovered` | DNS info |
| `extract the issuer` | Certificate info (covered by TLS stage) |
| `subject alternative name` | Certificate info (covered by TLS stage) |
| `tls version detection` | Duplicate of TLS stage |

---

### 2. Nikto Noise Filters

Nikto output is filtered in `_parse_nikto()`. Lines matching these markers are **discarded as noise**:

| Noise Marker | What It Catches |
|--------------|-----------------|
| `no cgi directories found` | Standard scanner metadata |
| `cgi tests skipped` | Scanner metadata |
| `scan terminated:` | Scanner status line |
| `host(s) tested` | Summary footer |
| `start time:` / `end time:` | Timestamp metadata |
| `target ip:` / `target hostname:` / `target port:` | Target info echo |
| `platform:` / `server:` | Server identification (covered by fingerprint stage) |
| `multiple ips found:` | Informational |
| `error:` | Scanner errors |
| `consider using mitmproxy` | Nikto suggestion noise |
| `cannot test http/3 over quic` | Unsupported protocol notice |
| `uncommon header` | Very low severity observation |
| `allowed http methods` | Informational |
| `strict-transport-security` | Header presence check (low value) |
| `x-frame-options` | Header presence check (low value) |
| `content-security-policy` | Header presence check (low value) |

Additionally, only Nikto findings classified as `medium` or `high` severity are reported — `info`-level lines are dropped. Severity is assigned by keyword matching:

- **High**: `critical`, `arbitrary`, `remote code execution`, `authentication bypass`, `sql injection`
- **Medium**: `vuln`, `xss`, `sql inject`, `rce`, `remote code`, `cve-`, `command injection`, `path traversal`, `file disclosure`

---

### 3. TLS Scan Filters

In [tls_scan.py](file:///c:/Users/DELL/OneDrive/Dokumen/22.NarendraYudhistiraBagaskoro_XISIJA1/projectdashboard/backend/pipeline/tls_scan.py), testssl.sh JSON results are filtered:

| Filter | What's Removed |
|--------|----------------|
| Severity `OK` or `INFO` | Passing checks and informational notes |
| `"not vulnerable"` in finding | Checks that explicitly passed |
| `scan_time` / `target` IDs | Scanner metadata |
| Certificate fields (`cert_*`) | Extracted separately into `cert_info` (not dropped, just categorized) |
| Inconclusive findings (`not tested`, `terminated`, `stalled`, `timed out`, `test failed`) | Logged as limitations instead of findings |

**Ignorable Inconclusive Checks** — these inconclusive results are silently dropped (not even added as limitations):

| Check ID | Reason |
|----------|--------|
| `quic` | HTTP/3 support — not actionable |
| `dns_caarecord` / `dns_caa` | CAA record — informational |
| `ipv6` | IPv6 support — not a vulnerability |
| `rp_banner` | Reverse proxy banner — low value |
| `trust` | Trust chain (usually inconclusive behind CDN) |
| `caa_rr` | CAA resource record — informational |

---

### 4. WhatWeb Filters

In [fingerprint.py](file:///c:/Users/DELL/OneDrive/Dokumen/22.NarendraYudhistiraBagaskoro_XISIJA1/projectdashboard/backend/pipeline/fingerprint.py), WhatWeb plugin results skip these generic plugins:

| Skipped Plugin | Reason |
|----------------|--------|
| `IP` | Raw IP address — not a technology |
| `Country` | Geolocation — not a technology |
| `HTTPServer` | Generic server header — captured by httpx already |

---

### 5. Web Discovery Scope Filter

In [web_discovery.py](file:///c:/Users/DELL/OneDrive/Dokumen/22.NarendraYudhistiraBagaskoro_XISIJA1/projectdashboard/backend/pipeline/web_discovery.py), discovered URLs are filtered to stay in scope:

| Filter | Rule |
|--------|------|
| Scheme | Only `http://` and `https://` URLs kept |
| Hostname scope | Must be the target domain or a subdomain of it (`*.target.com`) |
| Deduplication | Fragment removed, trailing slash stripped, exact duplicates collapsed |
| URL cap | Quick: max **150** URLs retained; Deep: max **500** |
| Priority sorting | Parameterized URLs (`?key=val`) and deep paths ranked first |

---

### Summary: Quick vs Deep at a Glance

```
┌─────────────────────────────────────────────────────────────┐
│                    QUICK MODE (Fast)                        │
│                                                             │
│  • Top 1000 ports scanned                                   │
│  • Reportable nuclei findings: critical + high + medium     │
│  • 4 nuclei target URLs max                                 │
│  • Crawl depth: 2 levels                                    │
│  • 150 discovered URLs kept                                 │
│  • Nikto, Amass, Dirsearch, S3Scanner: DISABLED             │
│  • ~60 min total timeout                                    │
├─────────────────────────────────────────────────────────────┤
│                    DEEP MODE (Thorough)                     │
│                                                             │
│  • All 65535 ports scanned                                  │
│  • Broader nuclei execution coverage                        │
│  • 12 nuclei target URLs max                                │
│  • Crawl depth: 4 levels                                    │
│  • 500 discovered URLs kept                                 │
│  • Nikto, Amass, Dirsearch, S3Scanner: ENABLED              │
│  • Nmap adds --script vuln                                  │
│  • ~240 min total timeout                                   │
└─────────────────────────────────────────────────────────────┘
```

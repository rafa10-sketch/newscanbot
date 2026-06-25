"""
PentestBot v2 — Origin IP Stage (UPGRADED v2)
Multi-method real IP discovery with 10 techniques:
  1.  Direct DNS resolution
  2.  crt.sh certificate transparency search
  3.  HackerTarget DNS history
  4.  Common bypass subdomain probing (50+ wordlist)
  5.  MX / SPF / TXT record analysis
  6.  ViewDNS.info historical IP lookup
  7.  Direct TLS certificate grab (bypass CDN SNI)
  8.  Shodan / InternetDB passive lookup
  9.  DNS Zone Transfer attempt (AXFR)
  10. Realtime Cloudflare + AWS CloudFront IP range detection
"""

import asyncio
import ipaddress
import json
import re
import socket
import ssl
import struct
from pipeline.base_stage import BaseStage

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    import urllib.request
    import urllib.error


# ── CDN Signatures ─────────────────────────────────────────────────────────────
_CDN_SIGNATURES = [
    "cloudflare", "akamai", "fastly", "cloudfront", "incapsula",
    "sucuri", "stackpath", "imperva", "arbor", "ddos-guard",
    "azure", "amazonaws", "googleusercontent", "edgecastcdn",
    "limelight", "maxcdn", "belugacdn", "cdn77", "keycdn",
    "bunnycdn", "verizonmedia", "zscaler", "radware",
]

# ── Fallback CDN IP Ranges (used if realtime fetch fails) ─────────────────────
_FALLBACK_CDN_NETWORKS = list(
    ipaddress.ip_network(cidr) for cidr in (
        # Cloudflare
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22",   "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15",  "104.16.0.0/13",
        "104.24.0.0/14",   "172.64.0.0/13",   "131.0.72.0/22",
        # Akamai
        "23.32.0.0/11", "23.64.0.0/14",
        # Fastly
        "23.235.32.0/20", "43.249.72.0/22",
        # AWS CloudFront (fallback)
        "13.32.0.0/15", "54.182.0.0/16",
    )
)

# Runtime CDN networks — populated by _fetch_cdn_ranges() at scan start
_KNOWN_CDN_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_AWS_CLOUDFRONT_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

# ── Expanded Bypass Subdomain Wordlist ─────────────────────────────────────────
_BYPASS_PREFIXES = [
    # Common server subdomains
    "direct", "origin", "real", "backend", "www2", "www1",
    "mail", "ftp", "cpanel", "webmail", "dev", "staging",
    "admin", "api", "app", "shop", "store", "portal",
    "secure", "vpn", "ssh", "remote", "old", "beta",
    "test", "demo", "preview", "static", "media",
    "cdn", "assets", "img", "images", "video",
    "smtp", "pop", "imap", "mx", "ns1", "ns2",
    "autodiscover", "autoconfig", "exchange", "owa",
    # Common internal/infra
    "internal", "intranet", "corp", "server", "host",
    "db", "database", "sql", "mongo", "redis", "cache",
    "git", "gitlab", "jenkins", "jira", "confluence",
    "monitoring", "grafana", "kibana", "elastic",
]


def _is_cdn(ptr: str) -> bool:
    ptr_lower = ptr.lower()
    return any(sig in ptr_lower for sig in _CDN_SIGNATURES)


def _is_known_cdn_ip(ip: str) -> bool:
    networks = _KNOWN_CDN_NETWORKS or _FALLBACK_CDN_NETWORKS
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in network for network in networks)


def _is_aws_cloudfront_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in network for network in _AWS_CLOUDFRONT_NETWORKS)


def _is_valid_public_ip(ip: str) -> bool:
    """Return True if the IP is a valid, non-private, non-loopback IP."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or
                    addr.is_multicast or addr.is_reserved or
                    addr.is_link_local or str(addr) == "0.0.0.0")
    except ValueError:
        return False


# Well-known DNS resolvers and APNIC/Cloudflare research IPs that frequently
# appear as false-positive origin candidates.
_FALSE_POSITIVE_NETWORKS = [
    ipaddress.ip_network("1.0.0.0/24"),     # Cloudflare+APNIC DNS (1.0.0.1)
    ipaddress.ip_network("1.1.1.0/24"),     # Cloudflare DNS (1.1.1.1)
    ipaddress.ip_network("1.2.1.0/24"),     # APNIC research range
    ipaddress.ip_network("8.8.8.0/24"),     # Google DNS
    ipaddress.ip_network("8.8.4.0/24"),     # Google DNS
    ipaddress.ip_network("9.9.9.0/24"),     # Quad9 DNS
]
_FALSE_POSITIVE_IPS = frozenset([
    "1.0.0.1", "1.1.1.1", "1.0.1.1", "1.2.1.1",
    "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "208.67.222.222", "208.67.220.220",  # OpenDNS
])


def _is_false_positive_origin(ip: str) -> bool:
    """Filter known false-positive IPs (DNS resolvers, APNIC research ranges)."""
    if ip in _FALSE_POSITIVE_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _FALSE_POSITIVE_NETWORKS)
    except ValueError:
        return False


class OriginIPStage(BaseStage):
    """
    Stage 3: Origin IP Discovery (Upgraded — 9 Methods)

    Runs all discovery methods concurrently to find the real server IP
    behind CDN/WAF proxies like Cloudflare.

    Populates:
      ctx['origin_data']       → dict with all discovered IP data
      ctx['cdn_detected']      → bool
      ctx['origin_candidates'] → list[str] of likely real IPs
    """

    NAME = "OriginIP"

    async def run(self) -> None:
        self.log.info(f"[OriginIP] Starting 11-method origin IP discovery for {self.target}")

        # ── Fetch realtime CDN IP ranges first ───────────────────────────────
        await self._fetch_cdn_ranges()

        discovered: dict[str, dict] = {}

        # ── Run ALL methods concurrently ──────────────────────────────────────
        results = await asyncio.gather(
            self._method_direct_dns(),
            self._method_crtsh(),
            self._method_hackertarget(),
            self._method_bypass_subs(),
            self._method_mx_spf_records(),
            self._method_viewdns(),
            self._method_tls_cert_grab(),
            self._method_zone_transfer(),
            self._method_shodan(),
            self._method_global_dns(),
            self._method_recon_subdomains(),
            return_exceptions=True,
        )


        # ── Merge all results ─────────────────────────────────────────────────
        for result in results:
            if isinstance(result, dict):
                for ip, info in result.items():
                    if not _is_valid_public_ip(ip):
                        continue
                    if _is_false_positive_origin(ip):
                        continue
                    if ip not in discovered:
                        discovered[ip] = info
                    else:
                        discovered[ip]["methods"] = list(set(
                            discovered[ip].get("methods", []) +
                            info.get("methods", [])
                        ))

        # ── Enrich with PTR records & CDN classification ──────────────────────
        for ip, info in discovered.items():
            ptr = info.get("ptr", "")
            if not ptr:
                try:
                    ptr = socket.gethostbyaddr(ip)[0]
                except Exception:
                    ptr = ""
            info["ptr"] = ptr
            info["is_cloudfront"] = _is_aws_cloudfront_ip(ip)
            info["is_cdn"] = _is_cdn(ptr) or _is_known_cdn_ip(ip)

        cdn_ips = [ip for ip, d in discovered.items() if d.get("is_cdn")]
        cloudfront_ips = [ip for ip, d in discovered.items() if d.get("is_cloudfront")]
        origin_candidates = [
            ip for ip, d in discovered.items()
            if not d.get("is_cdn") and not d.get("is_cloudfront")
        ]

        # ── Active Origin Verification ────────────────────────────────────────
        verified_candidates = []
        unverified_candidates = []

        if origin_candidates:
            self.log.info(f"[OriginIP] Establishing target baseline for {self.target}...")
            baseline = await self._get_target_baseline()
            
            self.log.info(f"[OriginIP] Verifying {len(origin_candidates)} non-CDN origin candidates actively...")
            
            async def verify_and_rank(ip: str):
                res = await self._verify_candidate(ip, baseline)
                if ip in discovered:
                    discovered[ip]["verification"] = res
                    if res["verified"]:
                        discovered[ip]["methods"].append(f"verified_origin (score: {res['score']})")
                
                if res["verified"]:
                    verified_candidates.append((ip, res["score"]))
                else:
                    unverified_candidates.append((ip, res["score"]))
                    
            await asyncio.gather(*[verify_and_rank(ip) for ip in origin_candidates])
            
            # Sort verified candidates by score (descending)
            verified_candidates = sorted(verified_candidates, key=lambda x: x[1], reverse=True)
            
            # Sort unverified candidates by legacy method count / verification score
            def unverified_score(item):
                ip, active_score = item
                legacy_count = len(discovered[ip].get("methods", []))
                return (legacy_count, active_score)
            
            unverified_candidates = sorted(unverified_candidates, key=unverified_score, reverse=True)
            
            # Combined list: verified candidates ALWAYS take priority!
            origin_candidates = [ip for ip, _ in verified_candidates] + [ip for ip, _ in unverified_candidates]

        self.ctx["origin_data"] = {
            "all_ips": list(discovered.keys()),
            "details": discovered,
            "cdn_ips": cdn_ips,
            "cloudfront_ips": cloudfront_ips,
            "origin_candidates": origin_candidates,
        }
        self.ctx["cdn_detected"]        = len(cdn_ips) > 0 or len(cloudfront_ips) > 0
        self.ctx["origin_candidates"]   = origin_candidates

        self.log.info(
            f"[OriginIP] Total IPs: {len(discovered)} | "
            f"Cloudflare: {len(cdn_ips)} | "
            f"CloudFront: {len(cloudfront_ips)} | "
            f"Origin candidates: {len(origin_candidates)} → {origin_candidates[:5]}"
        )

    # ── Fetch Realtime CDN IP Ranges ─────────────────────────────────────────
    async def _fetch_cdn_ranges(self) -> None:
        """
        Fetch Cloudflare and AWS CloudFront IP ranges in realtime.
        Falls back to hardcoded ranges if fetch fails.
        """
        global _KNOWN_CDN_NETWORKS, _AWS_CLOUDFRONT_NETWORKS

        async def fetch_cloudflare():
            if not self.runner.which("curl"):
                return
            r4 = await self.runner.run(
                cmd=["curl", "-s", "--max-time", "10",
                     "https://www.cloudflare.com/ips-v4"],
                timeout=12,
            )
            r6 = await self.runner.run(
                cmd=["curl", "-s", "--max-time", "10",
                     "https://www.cloudflare.com/ips-v6"],
                timeout=12,
            )
            networks = []
            for result in [r4, r6]:
                if result.success and result.stdout:
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if line:
                            try:
                                networks.append(ipaddress.ip_network(line, strict=False))
                            except ValueError:
                                pass
            if networks:
                _KNOWN_CDN_NETWORKS.clear()
                _KNOWN_CDN_NETWORKS.extend(networks)
                self.log.info(f"[OriginIP] Loaded {len(networks)} Cloudflare IP ranges (realtime)")

        async def fetch_aws_cloudfront():
            if not self.runner.which("curl"):
                return
            result = await self.runner.run(
                cmd=["curl", "-s", "--max-time", "15",
                     "https://ip-ranges.amazonaws.com/ip-ranges.json"],
                timeout=20,
            )
            if result.success and result.stdout:
                try:
                    import json as _json
                    data = _json.loads(result.stdout)
                    networks = [
                        ipaddress.ip_network(p["ip_prefix"], strict=False)
                        for p in data.get("prefixes", [])
                        if p.get("service") == "CLOUDFRONT"
                    ]
                    _AWS_CLOUDFRONT_NETWORKS.clear()
                    _AWS_CLOUDFRONT_NETWORKS.extend(networks)
                    self.log.info(f"[OriginIP] Loaded {len(networks)} AWS CloudFront IP ranges (realtime)")
                except Exception:
                    pass

        await asyncio.gather(
            fetch_cloudflare(),
            fetch_aws_cloudfront(),
            return_exceptions=True,
        )

        # Fallback if fetch failed
        if not _KNOWN_CDN_NETWORKS:
            _KNOWN_CDN_NETWORKS.extend(_FALLBACK_CDN_NETWORKS)
            self.log.warning("[OriginIP] Using fallback Cloudflare IP ranges")

    # ── Method 1: Direct DNS ──────────────────────────────────────────────────
    async def _method_direct_dns(self) -> dict:
        out = {}
        try:
            ips = socket.gethostbyname_ex(self.target)[2]
            for ip in ips:
                out[ip] = {"methods": ["direct_dns"], "ptr": "", "is_cdn": False}
        except Exception:
            pass
        return out

    # ── Method 2: crt.sh Certificate Transparency ─────────────────────────────
    async def _method_crtsh(self) -> dict:
        """Query crt.sh for hostnames leaked via SSL certificates and resolve them."""
        out = {}
        if not self.runner.which("curl"):
            return out
        result = await self.runner.run(
            cmd=[
                "curl", "-s", "--max-time", "15",
                f"https://crt.sh/?q=%25.{self.target}&output=json",
            ],
            timeout=20,
        )
        if not result.success or not result.stdout:
            return out
            
        hostnames = set()
        try:
            entries = json.loads(result.stdout)
            for entry in entries[:500]:
                name_value = entry.get("name_value", "")
                for part in name_value.split("\n"):
                    part = part.strip().lstrip("*.")
                    if part and part != self.target:
                        hostnames.add(part)
        except (json.JSONDecodeError, Exception):
            pass

        async def resolve_host(host: str) -> None:
            try:
                ip = socket.gethostbyname(host)
                if _is_valid_public_ip(ip):
                    out[ip] = {"methods": [f"crt_sh:{host}"], "ptr": "", "is_cdn": False}
            except Exception:
                pass

        if hostnames:
            await asyncio.gather(*[resolve_host(h) for h in list(hostnames)[:100]])
            
        return out

    # ── Method 3: HackerTarget DNS History ────────────────────────────────────
    async def _method_hackertarget(self) -> dict:
        """Query HackerTarget for historical DNS A records."""
        out = {}
        if not self.runner.which("curl"):
            return out
        result = await self.runner.run(
            cmd=[
                "curl", "-s", "--max-time", "10",
                f"https://api.hackertarget.com/hostsearch/?q={self.target}",
            ],
            timeout=15,
        )
        if not result.success or not result.stdout:
            return out
        for line in result.stdout.splitlines():
            parts = line.split(",")
            if len(parts) == 2:
                ip = parts[1].strip()
                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
                    out[ip] = {"methods": ["hackertarget"], "ptr": "", "is_cdn": False}
        return out

    # ── Method 4: Bypass Subdomain Probing ───────────────────────────────────
    async def _method_bypass_subs(self) -> dict:
        """Probe subdomains that commonly bypass CDN protection."""
        out = {}
        targets = [f"{prefix}.{self.target}" for prefix in _BYPASS_PREFIXES]

        async def probe(host: str) -> None:
            try:
                ip = socket.gethostbyname(host)
                out[ip] = {
                    "methods": [f"bypass_sub:{host}"],
                    "ptr": "",
                    "is_cdn": False,
                }
            except Exception:
                pass

        await asyncio.gather(*[probe(t) for t in targets])
        return out

    # ── Method 5: MX / SPF / TXT Records ─────────────────────────────────────
    async def _method_mx_spf_records(self) -> dict:
        """
        Extract IPs from MX and SPF/TXT DNS records.
        Mail servers often bypass CDN and reveal real IPs or subnets.
        """
        out = {}
        if not self.runner.which("curl"):
            return out

        # Query MX records via HackerTarget
        mx_result = await self.runner.run(
            cmd=[
                "curl", "-s", "--max-time", "10",
                f"https://api.hackertarget.com/dnslookup/?q={self.target}",
            ],
            timeout=15,
        )
        if mx_result.success and mx_result.stdout:
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', mx_result.stdout)
            for ip in ips:
                out[ip] = {"methods": ["mx_spf_record"], "ptr": "", "is_cdn": False}

        # Also resolve MX hostnames directly
        try:
            import dns.resolver  # type: ignore
            try:
                mx_records = dns.resolver.resolve(self.target, "MX")
                for mx in mx_records:
                    mx_host = str(mx.exchange).rstrip(".")
                    try:
                        ip = socket.gethostbyname(mx_host)
                        out[ip] = {"methods": ["mx_direct"], "ptr": "", "is_cdn": False}
                    except Exception:
                        pass

                txt_records = dns.resolver.resolve(self.target, "TXT")
                for txt in txt_records:
                    txt_str = str(txt)
                    # Extract IPs from SPF records (ip4:x.x.x.x)
                    spf_ips = re.findall(r'ip4:(\d{1,3}(?:\.\d{1,3}){3})', txt_str)
                    for ip in spf_ips:
                        out[ip] = {"methods": ["spf_record"], "ptr": "", "is_cdn": False}
                    # Extract IP ranges from SPF
                    spf_cidrs = re.findall(r'ip4:(\d{1,3}(?:\.\d{1,3}){3}/\d+)', txt_str)
                    for cidr in spf_cidrs:
                        try:
                            network = ipaddress.ip_network(cidr, strict=False)
                            # Take the first usable host as candidate
                            first_ip = str(next(network.hosts()))
                            out[first_ip] = {"methods": ["spf_cidr"], "ptr": "", "is_cdn": False}
                        except Exception:
                            pass
            except Exception:
                pass
        except ImportError:
            # dnspython not installed, skip
            pass

        return out

    # ── Method 6: ViewDNS Historical IP ──────────────────────────────────────
    async def _method_viewdns(self) -> dict:
        """Scrape ViewDNS.info for historical A record IPs."""
        out = {}
        if not self.runner.which("curl"):
            return out
        result = await self.runner.run(
            cmd=[
                "curl", "-s", "--max-time", "15",
                "-H", "User-Agent: Mozilla/5.0 (X11; Linux x86_64)",
                f"https://viewdns.info/iphistory/?domain={self.target}",
            ],
            timeout=20,
        )
        if not result.success or not result.stdout:
            return out
        # Extract IPs from HTML table
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', result.stdout)
        for ip in ips:
            if not ip.startswith(("0.", "255.", "127.", "192.168.", "10.")):
                out[ip] = {"methods": ["viewdns_history"], "ptr": "", "is_cdn": False}
        return out

    # ── Method 7: Direct TLS Certificate Grab ────────────────────────────────
    async def _method_tls_cert_grab(self) -> dict:
        """
        Directly connect to port 443 and read the TLS certificate.
        Sometimes the cert reveals the real hostname/IP even behind CDN.
        Also tries common alternative IPs if the main one is CDN.
        """
        out = {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()

            def grab_cert(host: str, port: int = 443) -> dict | None:
                try:
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            cert = ssock.getpeercert(binary_form=False)
                            peer_ip = sock.getpeername()[0]
                            return {"ip": peer_ip, "cert": cert}
                except Exception:
                    return None

            result = await loop.run_in_executor(None, grab_cert, self.target)
            if result:
                ip = result["ip"]
                out[ip] = {"methods": ["tls_direct_grab"], "ptr": "", "is_cdn": False}

                # Also check SANs in certificate for other hostnames
                cert = result.get("cert", {})
                sans = cert.get("subjectAltName", [])
                for san_type, san_value in sans:
                    if san_type == "IP Address":
                        out[san_value] = {
                            "methods": ["tls_san_ip"],
                            "ptr": "",
                            "is_cdn": False,
                        }
                    elif san_type == "DNS" and san_value != self.target:
                        try:
                            resolved = socket.gethostbyname(san_value)
                            out[resolved] = {
                                "methods": [f"tls_san_dns:{san_value}"],
                                "ptr": "",
                                "is_cdn": False,
                            }
                        except Exception:
                            pass
        except Exception as e:
            self.log.debug(f"[OriginIP] TLS grab failed: {e}")
        return out

    # ── Method 8: DNS Zone Transfer (AXFR) ───────────────────────────────────
    async def _method_zone_transfer(self) -> dict:
        """
        Attempt DNS zone transfer (AXFR) which, if misconfigured,
        reveals ALL internal DNS records including real IPs.
        This is a common misconfiguration on older servers.
        """
        out = {}
        if not self.runner.which("dig"):
            return out

        # First get nameservers for the domain
        ns_result = await self.runner.run(
            cmd=["dig", "+short", "NS", self.target],
            timeout=10,
        )
        if not ns_result.success or not ns_result.stdout:
            return out

        nameservers = [
            ns.strip().rstrip(".")
            for ns in ns_result.stdout.splitlines()
            if ns.strip()
        ]

        for ns in nameservers[:3]:  # Try first 3 nameservers
            axfr_result = await self.runner.run(
                cmd=["dig", "AXFR", self.target, f"@{ns}"],
                timeout=15,
            )
            if axfr_result.success and axfr_result.stdout:
                # Parse IPs from AXFR response
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', axfr_result.stdout)
                for ip in ips:
                    if not ip.startswith(("0.", "255.", "127.")):
                        out[ip] = {
                            "methods": [f"zone_transfer:{ns}"],
                            "ptr": "",
                            "is_cdn": False,
                        }
                if ips:
                    self.log.info(f"[OriginIP] Zone transfer SUCCESS via {ns}! Found {len(ips)} IPs")
                    break  # Zone transfer succeeded, no need to try others

        return out

    # ── Method 9: Shodan (if API key configured) ──────────────────────────────
    async def _method_shodan(self) -> dict:
        """
        Use Shodan API to find historical IPs serving this domain.
        Requires SHODAN_API_KEY in configuration.
        Falls back to free Shodan InternetDB if no key provided.
        """
        out = {}
        if not self.runner.which("curl"):
            return out

        shodan_key = getattr(self.config, "shodan_api_key", None) or ""

        if shodan_key:
            # Full Shodan API search
            result = await self.runner.run(
                cmd=[
                    "curl", "-s", "--max-time", "15",
                    f"https://api.shodan.io/dns/resolve?hostnames={self.target}&key={shodan_key}",
                ],
                timeout=20,
            )
            if result.success and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for host, ip in data.items():
                        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', str(ip)):
                            out[ip] = {"methods": ["shodan_api"], "ptr": "", "is_cdn": False}
                except Exception:
                    pass
        else:
            # Free Shodan InternetDB (no key required, limited info)
            try:
                direct_ip = socket.gethostbyname(self.target)
                result = await self.runner.run(
                    cmd=[
                        "curl", "-s", "--max-time", "10",
                        f"https://internetdb.shodan.io/{direct_ip}",
                    ],
                    timeout=15,
                )
                if result.success and result.stdout:
                    try:
                        data = json.loads(result.stdout)
                        # InternetDB returns hostnames - resolve them
                        for hostname in data.get("hostnames", []):
                            try:
                                resolved = socket.gethostbyname(hostname)
                                out[resolved] = {
                                    "methods": ["shodan_internetdb"],
                                    "ptr": hostname,
                                    "is_cdn": False,
                                }
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass

        return out

    # ── Method 11: Global DNS Resolution (Anycast Bypass) ───────────────────
    async def _method_global_dns(self) -> dict:
        """Resolve the target from multiple global public DNS resolvers to catch anycast inconsistencies."""
        out = {}
        if not self.runner.which("dnsx"):
            return out

        # Create a temporary file with global resolvers from various regions
        resolvers = [
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
            "149.112.112.112", "208.67.222.222", "208.67.220.220",
            "8.26.56.26", "8.20.247.20", "199.85.126.10", "199.85.127.10",
            "81.218.119.11", "209.244.0.3", "209.244.0.4", "64.6.64.6",
            "64.6.65.6", "77.88.8.8", "77.88.8.1"
        ]
        res_file = self.temp_file("global_resolvers.txt")
        self.write_lines(res_file, resolvers)

        result = await self.runner.run(
            cmd=[
                "dnsx", "-r", str(res_file), "-silent", "-a", "-resp",
                "-d", self.target
            ],
            timeout=20,
        )
        if result.success and result.stdout:
            for line in result.stdout.splitlines():
                # dnsx format with -resp: target.com [1.2.3.4]
                match = re.search(r'\[(.*?)\]', line)
                if match:
                    ip = match.group(1).strip()
                    if _is_valid_public_ip(ip):
                        out[ip] = {"methods": ["global_dns"], "ptr": "", "is_cdn": False}
        return out

    # ── Method 12: Stage 1 Recon Subdomain Resolution ───────────────────────
    async def _method_recon_subdomains(self) -> dict:
        """Resolve all subdomains discovered in Stage 1 Recon to find origin IP leaks."""
        out = {}
        subdomains = self.ctx.get("subdomains", [])
        if not subdomains:
            self.log.debug("[OriginIP] No Stage 1 subdomains found in context.")
            return out

        self.log.info(f"[OriginIP] Resolving {len(subdomains)} subdomains from Stage 1 Recon...")

        async def resolve_sub(sub: str) -> None:
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, sub)
                if _is_valid_public_ip(ip):
                    out[ip] = {
                        "methods": [f"recon_sub:{sub}"],
                        "ptr": "",
                        "is_cdn": False,
                    }
            except Exception:
                pass

        # Concurrently resolve subdomains with a semaphore to prevent network clogging
        sem = asyncio.Semaphore(50)
        async def resolve_with_sem(sub: str):
            async with sem:
                await resolve_sub(sub)

        await asyncio.gather(*[resolve_with_sem(sub) for sub in subdomains])
        return out

    # ── Active Origin Verification ──────────────────────────────────────────
    async def _get_target_baseline(self) -> dict:
        """Get baseline response characteristics from the target domain."""
        baseline = {
            "status_code": None,
            "title": None,
            "content_length": None,
            "headers": {},
        }
        
        urls = [f"https://{self.target}", f"http://{self.target}"]
        for url in urls:
            try:
                if HAS_HTTPX:
                    async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
                        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
                        status_code = resp.status_code
                        text = resp.text
                        headers = resp.headers
                else:
                    # Fallback to urllib
                    def fetch_urllib():
                        req = urllib.request.Request(url)
                        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        try:
                            with urllib.request.urlopen(req, timeout=5.0, context=ctx) as r:
                                return r.status, r.read().decode("utf-8", errors="ignore"), dict(r.headers)
                        except urllib.error.HTTPError as e:
                            try:
                                return e.code, e.read().decode("utf-8", errors="ignore"), dict(e.headers)
                            except Exception:
                                return e.code, "", dict(e.headers)
                    
                    loop = asyncio.get_event_loop()
                    status_code, text, headers = await loop.run_in_executor(None, fetch_urllib)

                baseline["status_code"] = status_code
                baseline["content_length"] = len(text)
                
                title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    baseline["title"] = title_match.group(1).strip()
                
                for h in ["Server", "X-Powered-By"]:
                    h_val = headers.get(h) or headers.get(h.lower())
                    if h_val:
                        baseline["headers"][h] = h_val
                
                self.log.info(f"[OriginIP] Baseline fetched ({url}) -> Status={status_code}, Title='{baseline['title']}', Length={baseline['content_length']}")
                break
            except Exception as e:
                self.log.debug(f"[OriginIP] Baseline fetch failed for {url}: {e}")
                
        return baseline

    async def _verify_candidate(self, ip: str, baseline: dict) -> dict:
        """Verify if a candidate IP actually hosts the target site by making direct requests with Host header."""
        res = {
            "verified": False,
            "status": "unverified",
            "score": 0,
            "title": None,
            "status_code": None,
            "content_length": None,
            "error": None,
        }
        
        schemes = ["https", "http"]
        for scheme in schemes:
            url = f"{scheme}://{ip}/"
            try:
                if HAS_HTTPX:
                    async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
                        headers = {
                            "Host": self.target,
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        }
                        resp = await client.get(url, headers=headers)
                        status_code = resp.status_code
                        text = resp.text
                        resp_headers = resp.headers
                else:
                    # Fallback to urllib
                    def verify_urllib():
                        req = urllib.request.Request(url)
                        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                        req.add_header("Host", self.target)
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        try:
                            with urllib.request.urlopen(req, timeout=5.0, context=ctx) as r:
                                return r.status, r.read().decode("utf-8", errors="ignore"), dict(r.headers)
                        except urllib.error.HTTPError as e:
                            try:
                                return e.code, e.read().decode("utf-8", errors="ignore"), dict(e.headers)
                            except Exception:
                                return e.code, "", dict(e.headers)
                    
                    loop = asyncio.get_event_loop()
                    status_code, text, resp_headers = await loop.run_in_executor(None, verify_urllib)

                title = None
                title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title = title_match.group(1).strip()
                    
                res["status_code"] = status_code
                res["content_length"] = len(text)
                res["title"] = title
                
                # Detect Cloudflare edge signatures on candidate IP
                cf_sig = any(sig in text.lower() for sig in ["cloudflare", "direct ip access", "error 1003", "error 1000", "error 1016"])
                cf_headers = any(h in resp_headers or h.lower() in resp_headers for h in ["cf-ray", "cf-cache-status"]) or "cloudflare" in str(resp_headers.get("Server", "") or resp_headers.get("server", "")).lower()
                
                if cf_sig or cf_headers:
                    res["status"] = "cloudflare_edge_error"
                    continue
                
                score = 0
                if baseline["status_code"] and status_code == baseline["status_code"]:
                    score += 20
                if baseline["title"] and title and title.lower() == baseline["title"].lower():
                    score += 50
                elif baseline["title"] and title and (baseline["title"].lower() in title.lower() or title.lower() in baseline["title"].lower()):
                    score += 30
                if baseline["content_length"] and len(text) > 0:
                    ratio = min(len(text), baseline["content_length"]) / max(len(text), baseline["content_length"])
                    if ratio > 0.85:
                        score += 30
                    elif ratio > 0.60:
                        score += 15
                        
                res["score"] = score
                if score >= 50:
                    res["verified"] = True
                    res["status"] = "verified"
                    self.log.info(f"[OriginIP] ✅ Verified Origin IP: {ip} (Score={score}, Title='{title}')")
                    break
                else:
                    res["status"] = "unmatching"
            except Exception as e:
                res["error"] = str(e)
                
        return res



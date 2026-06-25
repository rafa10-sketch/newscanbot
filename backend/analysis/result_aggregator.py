"""
PentestBot v2 — Result Aggregator
Merges all pipeline context fields into a single typed AggregatedResult.
This is the boundary between raw pipeline data and clean analysis/report data.
"""

import hashlib
import ipaddress
from dataclasses import dataclass, field
from typing import Optional


# ── Risk scoring weights ──────────────────────────────────────────────────────

SEVERITY_WEIGHT = {
    "critical": 15.0,
    "high":     7.0,
    "medium":   2.5,
    "low":      0.5,
    "info":     0.05,
    "unknown":  0.1,
}

DANGEROUS_PORTS = {
    21:    ("FTP",           "high",
           "The FTP service is reachable from the Internet and transmits credentials in cleartext. "
           "An attacker on the same network segment can passively capture usernames and passwords. "
           "Even when not actively exploited, FTP exposure signals weak perimeter controls."),
    22:    ("SSH",           "medium",
           "The SSH service is directly reachable. While SSH itself is encrypted, public exposure "
           "invites automated brute-force attacks against password-based authentication. "
           "Weak credentials or outdated SSH versions could allow unauthorized remote access."),
    23:    ("Telnet",        "critical",
           "Telnet transmits all data, including credentials, in cleartext without any encryption. "
           "This service is considered obsolete and any Internet-facing exposure represents an "
           "immediate, critical risk of credential theft and unauthorized system access."),
    25:    ("SMTP",          "medium",
           "The SMTP service is externally accessible. If misconfigured as an open relay, it can be "
           "abused to send spam or phishing emails on behalf of the target domain. Exposed SMTP "
           "also reveals mail infrastructure details useful for targeted social engineering."),
    53:    ("DNS",           "low",
           "A DNS service is publicly reachable. If recursive queries are enabled for external clients, "
           "this server could be leveraged for DNS amplification attacks or cache poisoning. "
           "Public DNS also exposes internal naming conventions."),
    110:   ("POP3",          "medium",
           "The POP3 mail retrieval service is exposed. Unless upgraded to POP3S, credentials are "
           "transmitted in cleartext, allowing passive interception of email account passwords."),
    143:   ("IMAP",          "medium",
           "The IMAP mail service is publicly reachable. Without STARTTLS or IMAPS, credentials "
           "and email contents may be intercepted in transit by an attacker."),
    389:   ("LDAP",          "high",
           "An LDAP directory service is externally accessible. If anonymous binding is permitted, "
           "attackers can enumerate users, groups, and organizational structure. LDAP exposure "
           "frequently enables credential attacks and internal reconnaissance."),
    445:   ("SMB",           "high",
           "The SMB file sharing service is reachable from the Internet. SMB has a history of critical "
           "remote code execution vulnerabilities (e.g., EternalBlue/MS17-010). Public SMB exposure "
           "is a high-value target for ransomware operators and worm propagation."),
    1433:  ("MSSQL",         "high",
           "Microsoft SQL Server is directly accessible from the Internet. Database services should "
           "never be publicly exposed. Attackers routinely scan for MSSQL to attempt brute-force "
           "authentication, execute stored procedures, or exfiltrate data."),
    1521:  ("Oracle",        "high",
           "Oracle Database listener is externally reachable. Direct database exposure allows attackers "
           "to probe for default credentials, enumerate database instances, and attempt exploitation "
           "of known Oracle vulnerabilities."),
    3306:  ("MySQL",         "high",
           "MySQL is accessible from the Internet. Direct database exposure allows brute-force "
           "attacks against database credentials. If compromised, an attacker gains full access to "
           "stored data and potentially command execution via SQL capabilities."),
    3389:  ("RDP",           "critical",
           "Remote Desktop Protocol is directly reachable from the Internet. RDP is the single most "
           "common initial access vector for ransomware gangs. Public RDP exposure, even with NLA "
           "enabled, invites credential brute-forcing and exploitation of known RDP vulnerabilities."),
    5432:  ("PostgreSQL",    "high",
           "PostgreSQL is externally accessible. Database services exposed to the Internet are "
           "routinely targeted for credential brute-forcing. A compromised PostgreSQL instance "
           "can lead to full data exfiltration and, via COPY or extensions, potential command execution."),
    5900:  ("VNC",           "critical",
           "The VNC remote desktop service is reachable from the Internet. Many VNC implementations "
           "have weak or absent authentication by default. Public VNC exposure typically allows "
           "attackers to gain full graphical desktop access with minimal effort."),
    6379:  ("Redis",         "critical",
           "Redis is accessible from the Internet. Redis ships without authentication by default, "
           "meaning any external client can read, modify, or delete all stored data. Unauthenticated "
           "Redis is also trivially exploitable for remote code execution via crafted payloads."),
    8080:  ("HTTP-Alt",      "low",
           "An alternative HTTP service is running on port 8080. This commonly hosts development "
           "servers, management panels, or proxy interfaces that may not have the same security "
           "hardening as the primary web service."),
    9200:  ("Elasticsearch", "critical",
           "Elasticsearch is directly accessible from the Internet. By default, Elasticsearch has no "
           "authentication, meaning all indexed data is publicly readable and modifiable. This is "
           "one of the most common causes of large-scale data breaches involving search infrastructure."),
    27017: ("MongoDB",       "critical",
           "MongoDB is reachable from the Internet. Historically, many MongoDB deployments lack "
           "authentication, exposing entire databases to unauthenticated read and write access. "
           "Public MongoDB exposure is a leading cause of data breach incidents."),
}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ExposedPort:
    port:         int
    host:         str
    service_name: str     = ""
    version:      str     = ""
    is_dangerous: bool    = False
    risk_level:   str     = "info"
    risk_note:    str     = ""
    cpe:          list    = field(default_factory=list)


@dataclass
class Finding:
    id:          str
    title:       str
    severity:    str
    description: str
    affected:    list[str]     = field(default_factory=list)
    source:      str           = ""
    remediation: str           = ""
    references:  list[str]     = field(default_factory=list)
    cvss:        Optional[float] = None
    cve_ids:     list[str]     = field(default_factory=list)
    tags:        list[str]     = field(default_factory=list)
    extra:       dict          = field(default_factory=dict)
    evidence_status: str       = "Observed condition"
    exploitability: str        = "Needs manual validation"
    impact:        str         = "Requires contextual validation"
    priority:      str         = "Review in context"
    validated:     bool        = False
    confidence:    str         = "needs_manual_validation"
    confidence_score: int      = 40
    confidence_reason: str     = "Automated observation requires analyst validation."


@dataclass
class AggregatedResult:
    """Complete normalized picture of a finished scan."""

    # Identifiers
    scan_id:       str
    target:        str
    target_type:   str
    scan_started:  str
    scan_completed: str
    scan_duration:  float
    scan_mode:      str = "fast"

    # Asset inventory
    subdomains:      list[str]        = field(default_factory=list)
    resolved_ips:    list[str]        = field(default_factory=list)
    ip_to_hosts:     dict             = field(default_factory=dict)
    dns_records:     dict             = field(default_factory=dict)
    origin_data:     dict             = field(default_factory=dict)
    cdn_detected:    bool             = False
    origin_candidates: list[str]      = field(default_factory=list)

    # Network surface
    open_ports:      list[ExposedPort]  = field(default_factory=list)
    dangerous_ports: list[ExposedPort]  = field(default_factory=list)
    services:        list[dict]         = field(default_factory=list)
    os_matches:      list[dict]         = field(default_factory=list)

    # Web surface
    live_hosts:    list[dict]         = field(default_factory=list)
    technologies:  list[str]          = field(default_factory=list)
    web_servers:   list[str]          = field(default_factory=list)
    discovered_urls: list[str]        = field(default_factory=list)

    # TLS
    cert_info:     dict               = field(default_factory=dict)
    tls_findings:  list[dict]         = field(default_factory=list)
    tls_protocols: dict               = field(default_factory=dict)

    # Findings (unified, deduped, sorted)
    findings:         list[Finding]   = field(default_factory=list)
    severity_summary: dict            = field(default_factory=dict)
    observed_findings_count: int      = 0
    excluded_findings_count: int      = 0
    total_findings:   int             = 0

    # Risk
    risk_score:   float = 0.0
    risk_level:   str   = "Unknown"

    # Metadata
    tool_errors:  list[str]  = field(default_factory=list)
    limitations:  list[str]  = field(default_factory=list)
    notes:        list[str]  = field(default_factory=list)
    nmap_scripts: dict       = field(default_factory=dict)
    tools_used:   list[str]  = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "scan_id":          self.scan_id,
            "target":           self.target,
            "target_type":      self.target_type,
            "scan_started":     self.scan_started,
            "scan_completed":   self.scan_completed,
            "scan_duration":    self.scan_duration,
            "scan_mode":        self.scan_mode,
            "subdomains":       self.subdomains,
            "resolved_ips":     self.resolved_ips,
            "ip_to_hosts":      self.ip_to_hosts,
            "dns_records":      self.dns_records,
            "origin_data":      self.origin_data,
            "cdn_detected":     self.cdn_detected,
            "origin_candidates":self.origin_candidates,
            "open_ports":       [p.__dict__ for p in self.open_ports],
            "dangerous_ports":  [p.__dict__ for p in self.dangerous_ports],
            "services":         self.services,
            "os_matches":       self.os_matches,
            "live_hosts":       self.live_hosts,
            "technologies":     self.technologies,
            "web_servers":      self.web_servers,
            "discovered_urls":  self.discovered_urls,
            "cert_info":        self.cert_info,
            "tls_findings":     self.tls_findings,
            "findings":         [f.__dict__ for f in self.findings],
            "severity_summary": self.severity_summary,
            "observed_findings_count": self.observed_findings_count,
            "excluded_findings_count": self.excluded_findings_count,
            "total_findings":   self.total_findings,
            "risk_score":       self.risk_score,
            "risk_level":       self.risk_level,
            "tool_errors":      self.tool_errors,
            "limitations":      self.limitations,
            "notes":            self.notes,
            "nmap_scripts":     self.nmap_scripts,
            "tools_used":       self.tools_used,
        }
        return d


# ── Aggregator ────────────────────────────────────────────────────────────────

class ResultAggregator:
    """
    Takes the raw pipeline ctx dict and returns an AggregatedResult.
    All merging, deduplication, and port enrichment happens here.
    """

    def __init__(self, ctx: dict):
        self.ctx = ctx

    def aggregate(self) -> AggregatedResult:
        ctx = self.ctx
        from datetime import datetime

        result = AggregatedResult(
            scan_id        = ctx.get("scan_id", ""),
            target         = ctx.get("target", ""),
            target_type    = _target_type(ctx.get("target", "")),
            scan_started   = str(ctx.get("scan_started", datetime.utcnow().isoformat())),
            scan_completed = datetime.utcnow().isoformat(),
            scan_duration  = ctx.get("scan_duration", 0.0),
            scan_mode      = str(ctx.get("scan_mode", "fast")),
        )

        # ── Asset inventory ───────────────────────────────────────────────
        result.subdomains        = ctx.get("subdomains", [result.target])
        result.resolved_ips      = ctx.get("live_ips", [])
        result.ip_to_hosts       = ctx.get("ip_to_hosts", {})
        result.dns_records       = ctx.get("resolved_hosts", {})
        result.origin_data       = ctx.get("origin_data", {})
        result.cdn_detected      = ctx.get("cdn_detected", False)
        result.origin_candidates = ctx.get("origin_candidates", [])

        # ── Network surface ───────────────────────────────────────────────
        raw_ports  = ctx.get("open_ports", [])
        services   = ctx.get("services", [])
        service_by_host_port = {
            (str(s.get("host", "")).strip(), s["port"]): s
            for s in services
            if "port" in s
        }
        service_by_port = {s["port"]: s for s in services if "port" in s}

        exposed: list[ExposedPort] = []
        dangerous: list[ExposedPort] = []

        for entry in raw_ports:
            port    = entry.get("port", 0)
            host    = entry.get("host", result.target)
            svc_row = service_by_host_port.get((str(host).strip(), port), service_by_port.get(port, {}))

            ep = ExposedPort(
                port         = port,
                host         = host,
                service_name = svc_row.get("service", ""),
                version      = svc_row.get("version", ""),
                cpe          = svc_row.get("cpe", []),
            )

            if port in DANGEROUS_PORTS:
                svc_label, risk, note = DANGEROUS_PORTS[port]
                ep.service_name = ep.service_name or svc_label
                ep.is_dangerous = True
                ep.risk_level   = risk
                ep.risk_note    = note
                dangerous.append(ep)

            exposed.append(ep)

        result.open_ports      = sorted(exposed,   key=lambda p: p.port)
        result.dangerous_ports = sorted(dangerous, key=lambda p: p.port)
        result.services        = services
        result.os_matches      = ctx.get("os_matches", [])
        result.nmap_scripts    = ctx.get("nmap_scripts", {})

        # ── Web surface ───────────────────────────────────────────────────
        result.live_hosts   = _dedupe_live_hosts(ctx.get("live_hosts", []))
        result.technologies = _dedupe_strs(ctx.get("technologies", []))
        result.web_servers  = _dedupe_strs(ctx.get("web_servers", []))
        result.discovered_urls = _dedupe_strs(ctx.get("discovered_urls", []))

        # ── TLS ───────────────────────────────────────────────────────────
        result.cert_info    = ctx.get("cert_info", {})
        result.tls_findings = _dedupe_tls_findings(ctx.get("tls_findings", []))

        # ── Unified Findings ──────────────────────────────────────────────
        all_findings: list[Finding] = []
        seen_ids: set[str] = set()

        def add_finding(f: Finding) -> None:
            if f.id not in seen_ids:
                seen_ids.add(f.id)
                all_findings.append(f)

        # Nuclei findings
        for nf in ctx.get("nuclei_findings", []):
            fid = f"nuclei-{nf.get('template_id') or _finding_fingerprint(nf)}"
            severity = nf.get("severity", "info")
            is_validated = severity in {"critical", "high"}
            raw_name = nf.get("name", "Nuclei Finding")
            raw_desc = nf.get("description", "")
            add_finding(Finding(
                id          = fid,
                title       = _clean_nuclei_title(raw_name, nf.get("template_id", "")),
                severity    = severity,
                description = raw_desc or f"Nuclei template '{nf.get('template_id', 'unknown')}' matched at the target. This indicates a known pattern was detected that warrants further investigation.",
                affected    = [nf.get("matched_at", nf.get("host", result.target))],
                source      = "nuclei",
                references  = nf.get("references", []),
                cvss        = nf.get("cvss_score"),
                cve_ids     = nf.get("cve_ids", []),
                tags        = nf.get("tags", []),
                extra       = {"template_id": nf.get("template_id", ""), "kind": "nuclei", "raw_description": raw_desc},
                evidence_status="Structured scanner evidence",
                exploitability="Likely exploitable" if is_validated else "Needs manual validation",
                impact="Direct security weakness",
                priority="Immediate Fix (0-7 days)" if severity in {"critical", "high"} else "Short-Term Fix (7-30 days)",
                validated=is_validated,
            ))

        # Nikto findings
        for nf in ctx.get("nikto_findings", []):
            fid = f"nikto-{_finding_fingerprint(nf)}"
            raw_desc = nf.get("description", "Nikto Finding")
            title, description = _clean_nikto_finding(raw_desc)
            add_finding(Finding(
                id          = fid,
                title       = title,
                severity    = nf.get("severity", "info"),
                description = description,
                affected    = [result.target],
                source      = "nikto",
                evidence_status="Single-tool heuristic evidence",
                exploitability="Needs manual validation",
                impact="Potential web application weakness",
                priority="Short-Term Fix (7-30 days)",
                extra={"kind": "nikto", "raw_description": raw_desc},
            ))

        # SQLMap findings
        for smf in ctx.get("sqlmap_findings", []):
            fid = f"sqlmap-{_finding_fingerprint(smf)}"
            add_finding(Finding(
                id          = fid,
                title       = "SQL Injection Vulnerability",
                severity    = smf.get("severity", "high"),
                description = smf.get("description", "SQLMap detected a potential SQL injection."),
                affected    = [result.target],
                source      = "sqlmap",
                evidence_status="Active exploitation evidence",
                exploitability="Confirmed exploitable",
                impact="Database compromise and data exfiltration",
                priority="Immediate Fix (0-7 days)",
                validated   = True,
                extra       = {"kind": "sqlmap"},
            ))

        # Dalfox findings
        for dxf in ctx.get("dalfox_findings", []):
            fid = f"dalfox-{_finding_fingerprint(dxf)}"
            severity = dxf.get("severity", "high")
            add_finding(Finding(
                id          = fid,
                title       = dxf.get("title", "Cross-Site Scripting Finding"),
                severity    = severity,
                description = dxf.get(
                    "description",
                    "Dalfox identified a potential cross-site scripting issue that should be manually validated.",
                ),
                affected    = dxf.get("affected", [dxf.get("url", result.target)]),
                source      = "dalfox",
                evidence_status="Specialized XSS scanner evidence",
                exploitability="Likely exploitable" if severity in {"critical", "high"} else "Needs manual validation",
                impact="Client-side script execution, session theft, or user action manipulation",
                priority="Immediate Fix (0-7 days)" if severity in {"critical", "high"} else "Short-Term Fix (7-30 days)",
                validated   = severity in {"critical", "high"},
                extra       = dxf.get("extra", {"kind": "dalfox"}),
            ))

        # S3 bucket exposure findings
        for s3f in ctx.get("s3_findings", []):
            fid = f"s3scanner-{_finding_fingerprint(s3f)}"
            severity = s3f.get("severity", "medium")
            add_finding(Finding(
                id          = fid,
                title       = s3f.get("title", "Potentially Exposed S3 Bucket"),
                severity    = severity,
                description = s3f.get("description", "S3Scanner identified a possible cloud storage exposure."),
                affected    = s3f.get("affected", [result.target]),
                source      = "s3scanner",
                evidence_status="Cloud storage scanner evidence",
                exploitability="Needs manual validation",
                impact="Potential public access to object storage data",
                priority="Immediate Fix (0-7 days)" if severity in {"critical", "high"} else "Short-Term Fix (7-30 days)",
                validated=False,
                extra       = s3f.get("extra", {"kind": "s3scanner"}),
            ))

        # CMS scanner findings
        for cms_key, source, default_title in (
            ("wpscan_findings", "wpscan", "WordPress Security Finding"),
            ("joomscan_findings", "joomscan", "Joomla Security Finding"),
        ):
            for cmsf in ctx.get(cms_key, []):
                severity = cmsf.get("severity", "medium")
                add_finding(Finding(
                    id          = f"{source}-{_finding_fingerprint(cmsf)}",
                    title       = cmsf.get("title", default_title),
                    severity    = severity,
                    description = cmsf.get("description", default_title),
                    affected    = cmsf.get("affected", [result.target]),
                    source      = source,
                    references  = cmsf.get("references", []),
                    evidence_status="CMS scanner evidence",
                    exploitability="Needs manual validation",
                    impact="Potential CMS compromise or information exposure",
                    priority="Immediate Fix (0-7 days)" if severity in {"critical", "high"} else "Short-Term Fix (7-30 days)",
                    validated=False,
                    extra       = cmsf.get("extra", {"kind": source}),
                ))

        # API scan findings
        for af in ctx.get("api_findings", []):
            fid = f"api-{af.get('id') or _finding_fingerprint(af)}"
            severity = af.get("severity", "info")
            add_finding(Finding(
                id          = fid,
                title       = af.get("title", "API Security Finding"),
                severity    = severity,
                description = af.get("description", "The API scanner identified an application-layer security condition that should be validated manually."),
                affected    = af.get("affected", [af.get("url", result.target)]),
                source      = af.get("source", "api-scan"),
                evidence_status="Application-layer scanner evidence",
                exploitability="Needs manual validation",
                impact="Potential API access control or data exposure weakness",
                priority="Immediate Fix (0-7 days)" if severity in {"critical", "high"} else "Short-Term Fix (7-30 days)",
                validated=False,
                extra       = af.get("extra", {"kind": "api-scan"}),
            ))

        # TLS findings
        for tf in result.tls_findings:
            fid = f"tls-{_finding_fingerprint(tf)}"
            raw_id = tf.get('id', 'Issue')
            human_title = _humanize_tls_id(raw_id)
            add_finding(Finding(
                id          = fid,
                title       = human_title,
                severity    = tf.get("severity", "info"),
                description = tf.get("description", "") or f"The TLS scanner identified a transport security observation: {raw_id}. Review the server's TLS configuration for alignment with current best practices.",
                affected    = [f"{result.target}:443"],
                source      = "testssl.sh",
                evidence_status="Transport-layer observation",
                exploitability="Configuration weakness",
                impact="Transport security weakness",
                priority="Hardening / Best Practice",
                extra={"kind": "tls", "raw_id": raw_id},
            ))

        # Dangerous port findings
        for dp in result.dangerous_ports:
            if dp.risk_level not in {"critical", "high"}:
                continue
            fid = f"port-{dp.port}"
            add_finding(Finding(
                id          = fid,
                title       = f"Exposed {dp.service_name} Service (Port {dp.port})",
                severity    = dp.risk_level,
                description = dp.risk_note,
                affected    = [f"{dp.host}:{dp.port}"],
                source      = "naabu/nmap",
                evidence_status="Confirmed service exposure",
                exploitability="Directly reachable service exposure",
                impact="Remote attack surface expansion",
                priority="Short-Term Fix (7-30 days)",
                validated=True,
                extra={"kind": "exposed-service"},
            ))

        # Sort by severity
        sev_rank = {s: i for i, s in enumerate(
            ["critical", "high", "medium", "low", "info", "unknown"]
        )}
        all_findings.sort(key=lambda f: sev_rank.get(f.severity, 99))

        result.findings       = all_findings
        result.observed_findings_count = len(all_findings)
        result.total_findings = len(all_findings)

        # Severity summary
        sev_counts: dict = {}
        for f in all_findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        result.severity_summary = sev_counts

        # Tool errors
        result.tool_errors = ctx.get("tool_errors", [])
        result.limitations = _dedupe_strs(ctx.get("limitations", []))
        result.tools_used = _derive_tools_used(ctx, result.findings)

        return result


def _truncate(s: str, n: int) -> str:
    return s[:n - 3] + "..." if len(s) > n else s


def _clean_nikto_finding(raw: str) -> tuple[str, str]:
    """Clean Nikto output into (title, description). Strips OSVDB prefixes and tool formatting."""
    import re
    text = raw.strip()
    # Strip OSVDB prefix like "OSVDB-3092: "
    text = re.sub(r'^OSVDB-\d+:\s*', '', text)
    # Strip Nikto ID prefix like "+ /path: "
    text = re.sub(r'^\+\s*', '', text)
    # Clean path prefix used as pseudo-title
    text = re.sub(r'^/\S+:\s*', '', text).strip()

    if not text:
        return "Web Server Finding (Nikto)", raw

    # Generate a clean title from first sentence
    first_sentence = text.split('. ')[0].strip().rstrip('.')
    title = _truncate(first_sentence, 90)

    # If the raw text is very short, expand it
    if len(text) < 60:
        description = (
            f"{text} This was identified by the Nikto web server scanner during automated "
            f"testing. Manual verification is recommended to confirm exploitability."
        )
    else:
        description = text

    return title, description


def _clean_nuclei_title(name: str, template_id: str) -> str:
    """Clean Nuclei template names into readable titles."""
    # Nuclei names like "http-missing-security-headers:x-frame-options" → "Missing Security Header: X-Frame-Options"
    title = name.strip()
    if not title or title == template_id:
        # Template ID fallback: convert kebab-case to title case
        title = template_id.replace('-', ' ').replace('_', ' ').replace(':', ': ').title()
    return title


# TLS ID to human-readable title mapping
_TLS_HUMAN_TITLES: dict[str, str] = {
    "heartbleed":      "Heartbleed Vulnerability (CVE-2014-0160)",
    "ccs":             "CCS Injection Vulnerability (CVE-2014-0224)",
    "ticketbleed":     "Ticketbleed Vulnerability (CVE-2016-9244)",
    "robot":           "ROBOT Attack (RSA Key Exchange Vulnerability)",
    "secure_renego":   "Insecure TLS Renegotiation",
    "secure_client_renego": "Client-Initiated Renegotiation Allowed",
    "crime":           "CRIME Attack (TLS Compression Enabled)",
    "breach":          "BREACH Attack (HTTP Compression over TLS)",
    "poodle_ssl":      "POODLE Attack (SSLv3 Vulnerability)",
    "sweet32":         "Sweet32 Attack (64-bit Block Cipher Weakness)",
    "freak":           "FREAK Attack (Export Cipher Downgrade)",
    "drown":           "DROWN Attack (SSLv2 Cross-Protocol)",
    "logjam":          "Logjam Attack (Weak Diffie-Hellman Parameters)",
    "beast":           "BEAST Attack (CBC Mode in TLS 1.0)",
    "lucky13":         "Lucky13 Timing Attack",
    "rc4":             "RC4 Cipher Suite in Use",
    "fallback_scsv":   "TLS Fallback SCSV Not Supported",
    "cipher_order":    "TLS Cipher Suite Ordering Issue",
    "protocol":        "Deprecated TLS/SSL Protocol Version",
    "sslv2":           "SSLv2 Protocol Enabled (Obsolete)",
    "sslv3":           "SSLv3 Protocol Enabled (Deprecated)",
    "tls1":            "TLS 1.0 Protocol Enabled (Deprecated)",
    "tls1_1":          "TLS 1.1 Protocol Enabled (Deprecated)",
    "cert_valid":      "Certificate Validity Issue",
    "cert_chain":      "Certificate Chain Issue",
    "cert_trust":      "Certificate Trust Issue",
    "hsts":            "HSTS Header Not Set via TLS",
    "ocsp_stapling":   "OCSP Stapling Not Enabled",
}


def _humanize_tls_id(raw_id: str) -> str:
    """Convert raw testssl.sh finding ID to a human-readable title."""
    lowered = raw_id.lower().strip()
    # Direct match
    if lowered in _TLS_HUMAN_TITLES:
        return _TLS_HUMAN_TITLES[lowered]
    # Partial match
    for key, title in _TLS_HUMAN_TITLES.items():
        if key in lowered:
            return title
    # Fallback: clean up the raw ID
    cleaned = raw_id.replace('_', ' ').replace('-', ' ').strip().title()
    return f"TLS Configuration: {cleaned}"


def _target_type(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def _finding_fingerprint(finding: dict) -> str:
    payload = "|".join([
        str(finding.get("id", "")),
        str(finding.get("name", "")),
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("matched_at", "")),
        str(finding.get("host", "")),
        str(finding.get("url", "")),
    ])
    return hashlib.sha1(payload.encode("utf-8", errors="replace")).hexdigest()[:10]


def _dedupe_strs(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        out.append(text)
    return out


def _dedupe_live_hosts(hosts: list[dict]) -> list[dict]:
    by_url: dict[str, dict] = {}
    for host in hosts:
        if not isinstance(host, dict):
            continue
        url = str(host.get("final_url") or host.get("url") or "").strip()
        if not url:
            continue
        current = dict(host)
        current["url"] = url
        existing = by_url.get(url)
        if existing is None or _host_quality(current) > _host_quality(existing):
            by_url[url] = current
    return sorted(by_url.values(), key=lambda item: item.get("url", ""))


def _host_quality(host: dict) -> tuple[int, int, int, int]:
    return (
        1 if int(host.get("status_code", 0) or 0) > 0 else 0,
        len(host.get("technologies") or []),
        len(host.get("headers") or {}),
        len(str(host.get("title") or "")),
    )


def _dedupe_tls_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = (
            str(finding.get("id", "")).strip().lower(),
            str(finding.get("severity", "")).strip().lower(),
            str(finding.get("description", "")).strip(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def _derive_tools_used(ctx: dict, findings: list[Finding]) -> list[str]:
    if str(ctx.get("scan_mode", "")).lower() == "api":
        return ["PentestBot API checks"]

    names: list[str] = []

    stage_defaults = {
        "subdomains": ["subfinder", "assetfinder"],
        "resolved_hosts": ["dnsx"],
        "open_ports": ["naabu"],
        "services": ["nmap"],
        "live_hosts": ["httpx"],
        "fingerprint_technologies": ["whatweb", "wafw00f", "webanalyze"],
        "tls_findings": ["testssl.sh"],
    }
    for key, tool_names in stage_defaults.items():
        if ctx.get(key):
            names.extend(tool_names)

    for raw in ctx.get("raw_outputs", []):
        if not isinstance(raw, dict):
            continue
        tool = str(raw.get("tool_name", "")).strip()
        if tool and raw.get("status") == "success":
            names.append(tool)

    for finding in findings:
        if finding.source:
            names.append(finding.source)

    aliases = {
        "naabu/nmap": "naabu, nmap",
        "api-scan": "PentestBot API checks",
    }
    expanded: list[str] = []
    for name in names:
        mapped = aliases.get(name, name)
        expanded.extend(part.strip() for part in mapped.split(",") if part.strip())

    return _dedupe_strs(expanded)

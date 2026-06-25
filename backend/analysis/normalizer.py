"""
PentestBot v2 — Normalizer
Enriches an AggregatedResult with:
  - Computed risk score (0–100)
  - Risk level classification
  - Per-finding remediation advice
  - Missing security header analysis
  - Deduplication pass
"""

from analysis.result_aggregator import (
    AggregatedResult, Finding, SEVERITY_WEIGHT,
)


# ── Remediation knowledge base ────────────────────────────────────────────────

_PORT_REMEDIATION: dict[int, str] = {
    21:    "Disable FTP. Use SFTP or SCP instead. If FTP is required, enforce TLS (FTPS) and restrict by IP.",
    22:    "Restrict SSH to key-based authentication. Disable password login. Use fail2ban and restrict to trusted IPs.",
    23:    "Disable Telnet immediately. Replace with SSH. Remove or block the service at the firewall.",
    25:    "Restrict SMTP to authenticated relaying only. Test for open relay. Enforce SPF, DKIM, DMARC.",
    53:    "Disable DNS recursion for external queries. Restrict zone transfers. Use DNSSEC.",
    389:   "Disable anonymous LDAP bind. Enforce LDAPS (port 636). Restrict access to internal networks.",
    445:   "Block SMB at the perimeter firewall. Apply MS17-010 patches. Disable SMBv1.",
    1433:  "Restrict MSSQL to internal networks. Enforce strong passwords. Audit login events.",
    1521:  "Restrict Oracle DB access to application servers only. Disable default accounts.",
    3306:  "Bind MySQL to 127.0.0.1 or use firewall rules. Revoke remote root access.",
    3389:  "Move RDP behind VPN. Enable Network Level Authentication. Apply latest patches. Monitor for brute-force.",
    5432:  "Restrict PostgreSQL via pg_hba.conf. Disable remote root. Use SSL connections.",
    5900:  "Restrict VNC to localhost or VPN only. Enable strong authentication. Prefer SSH tunneling.",
    6379:  "Bind Redis to 127.0.0.1. Enable requirepass. Use firewall rules. Never expose publicly.",
    9200:  "Restrict Elasticsearch to internal networks. Enable X-Pack security or open-distro security plugin.",
    27017: "Enable MongoDB authentication. Bind to localhost. Use TLS connections. Audit access logs.",
}

_TLS_REMEDIATION: dict[str, str] = {
    "sslv2":      "Disable SSLv2 on all services; it is cryptographically broken.",
    "sslv3":      "Disable SSLv3 to prevent POODLE. Use TLS 1.2 as the minimum.",
    "tls1":       "Disable TLS 1.0; deprecated since 2021. Enforce TLS 1.2+.",
    "tls1_1":     "Disable TLS 1.1; deprecated. Configure TLS 1.2 as the minimum.",
    "heartbleed": "CRITICAL: Upgrade OpenSSL immediately. This leaks private key material.",
    "poodle":     "Disable SSLv3 and enable TLS_FALLBACK_SCSV.",
    "beast":      "Disable TLS 1.0. Prioritize non-CBC cipher suites.",
    "sweet32":    "Disable 3DES cipher suites. Use AES-GCM alternatives.",
    "rc4":        "Disable all RC4 cipher suites; they are broken.",
    "robot":      "Disable RSA key exchange. Use ECDHE for forward secrecy.",
    "drown":      "Disable SSLv2 on all services. Avoid sharing private keys.",
    "logjam":     "Disable DHE or increase DH key size to 2048+ bits.",
    "freak":      "Disable export-grade cipher suites.",
    "crime":      "Disable TLS compression.",
}

# Nuclei template-specific remediation
_NUCLEI_REMEDIATION: dict[str, str] = {
    "x-frame-options": (
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header to all HTTP responses. "
        "This prevents the page from being embedded in iframes, mitigating clickjacking attacks."
    ),
    "x-content-type-options": (
        "Set 'X-Content-Type-Options: nosniff' on all HTTP responses. "
        "This prevents browsers from MIME-sniffing the content type, reducing content injection risk."
    ),
    "content-security-policy": (
        "Implement a Content-Security-Policy header starting with a restrictive baseline: "
        "'default-src self; script-src self'. Iterate to allow legitimate sources."
    ),
    "strict-transport-security": (
        "Enable HSTS by adding 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' "
        "to all HTTPS responses. This prevents SSL stripping attacks."
    ),
    "permissions-policy": (
        "Add a Permissions-Policy header to control which browser features the page can use. "
        "Restrict access to camera, microphone, geolocation, and other sensitive APIs."
    ),
    "cors-misconfig": (
        "Review CORS configuration to ensure Access-Control-Allow-Origin does not use wildcard (*) "
        "with credentials. Restrict allowed origins to specific trusted domains."
    ),
    "open-redirect": (
        "Validate and sanitize all redirect URLs server-side. Use an allowlist of permitted redirect "
        "destinations. Never redirect to user-controlled URLs without validation."
    ),
    "subdomain-takeover": (
        "Remove the dangling DNS record pointing to the unclaimed service. If the service is still "
        "needed, reclaim it immediately. Monitor DNS records for orphaned CNAME entries."
    ),
    "exposed-panels": (
        "Restrict administrative panels to internal networks or VPN-only access. "
        "Implement strong authentication and IP whitelisting for management interfaces."
    ),
    "directory-listing": (
        "Disable directory listing in the web server configuration. For Apache, add "
        "'Options -Indexes' to the relevant Directory directive. For Nginx, remove 'autoindex on'."
    ),
    "server-header": (
        "Remove or minimize the Server response header to avoid disclosing web server software "
        "and version information. This reduces the information available for targeted exploitation."
    ),
    "x-powered-by": (
        "Remove the X-Powered-By response header. Disclosing the application framework and version "
        "helps attackers identify known vulnerabilities for that specific technology stack."
    ),
    "waf-detect": (
        "This is an informational finding. A Web Application Firewall was detected, which is a "
        "positive security control. Ensure WAF rules are kept current and bypass techniques are tested."
    ),
    "tech-detect": (
        "This is an informational detection of technologies in use. Review whether any detected "
        "technology versions have known vulnerabilities and apply patches as needed."
    ),
}

# Nikto pattern-specific remediation
_NIKTO_REMEDIATION: dict[str, str] = {
    "server banner": (
        "Configure the web server to suppress version information in the Server header. "
        "For Apache: 'ServerTokens Prod'. For Nginx: 'server_tokens off'."
    ),
    "x-xss-protection": (
        "While X-XSS-Protection is deprecated in modern browsers, set it to '1; mode=block' for "
        "legacy browser support. Prefer Content-Security-Policy for XSS mitigation."
    ),
    "options method": (
        "Disable unnecessary HTTP methods (OPTIONS, TRACE, PUT, DELETE) on the web server. "
        "Only allow GET, POST, and HEAD unless other methods are required by the application."
    ),
    "directory indexing": (
        "Disable directory indexing on the web server. This prevents attackers from browsing "
        "directory contents and discovering sensitive files."
    ),
    "default file": (
        "Remove default installation files and example pages from the web server. "
        "These files may contain sensitive information or known vulnerabilities."
    ),
    "backup file": (
        "Remove backup files (.bak, .old, .swp, ~) from the web server document root. "
        "These files may expose source code or configuration details."
    ),
}

_DALFOX_REMEDIATION = (
    "Encode untrusted input according to output context before rendering it in HTML, "
    "JavaScript, attributes, URLs, or CSS. Add server-side validation for the affected "
    "parameter, avoid unsafe DOM sinks such as innerHTML, and deploy a restrictive "
    "Content-Security-Policy as defense in depth. Re-test the exact Dalfox payload after fixing."
)

_S3_REMEDIATION = (
    "Review the bucket policy, ACLs, and public access block settings. Disable public read/write "
    "unless explicitly required, enable account-level S3 Block Public Access, and validate object "
    "access with an unauthenticated request after remediation."
)

_CMS_REMEDIATION = (
    "Update the CMS core, themes, plugins, and extensions to patched versions. Remove unused "
    "components, restrict administrative access, and re-run the CMS-specific scanner after patching."
)

_GENERIC_REMEDIATION: dict[str, str] = {
    "critical": (
        "Remediate immediately. Treat this as an active incident. "
        "Apply vendor patches, isolate the affected component, and "
        "implement emergency compensating controls within 24 hours."
    ),
    "high": (
        "Remediate urgently within 7 days. Assess for active exploitation. "
        "Apply available patches and implement firewall rules or WAF rules "
        "as temporary mitigation."
    ),
    "medium": (
        "Schedule remediation within 30 days. Apply hardening guidelines "
        "and review related configurations for similar issues."
    ),
    "low": (
        "Address in the next maintenance cycle. Apply defense-in-depth "
        "measures and document the accepted risk if not remediated."
    ),
    "info": (
        "Review this informational finding. While not directly exploitable, "
        "it may provide useful context for an attacker. Assess risk in context."
    ),
}

_MISSING_HEADER_FINDINGS: list[dict] = [
    {
        "header": "strict-transport-security",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "severity": "medium",
        "description": (
            "The Strict-Transport-Security header is not set. "
            "This allows attackers to downgrade HTTPS connections to HTTP."
        ),
        "remediation": (
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' "
            "to all HTTPS responses."
        ),
    },
    {
        "header": "x-frame-options",
        "title": "Missing X-Frame-Options Header",
        "severity": "medium",
        "description": (
            "The X-Frame-Options header is absent. "
            "This may allow the page to be embedded in iframes, enabling clickjacking attacks."
        ),
        "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' on all responses.",
    },
    {
        "header": "content-security-policy",
        "title": "Missing Content-Security-Policy Header",
        "severity": "medium",
        "description": (
            "No Content-Security-Policy header detected. "
            "This increases risk from cross-site scripting (XSS) and data injection."
        ),
        "remediation": (
            "Implement a strict CSP policy. Start with "
            "'Content-Security-Policy: default-src \\'self\\'; script-src \\'self\\'' "
            "and tighten iteratively."
        ),
    },
    {
        "header": "x-content-type-options",
        "title": "Missing X-Content-Type-Options Header",
        "severity": "low",
        "description": (
            "The X-Content-Type-Options header is not set. "
            "Browsers may MIME-sniff responses, enabling content-type confusion attacks."
        ),
        "remediation": "Set 'X-Content-Type-Options: nosniff' on all responses.",
    },
]


# ── Normalizer ────────────────────────────────────────────────────────────────

class Normalizer:
    """
    Post-aggregation enrichment:
    1. Inject remediation advice into every finding
    2. Add missing security header findings
    3. Calculate final risk score
    4. Classify risk level
    """

    def __init__(self, scan_mode: str = "fast"):
        self.scan_mode = scan_mode

    def normalize(self, result: AggregatedResult) -> AggregatedResult:
        self._inject_remediations(result)
        self._assign_confidence(result)
        self._record_header_hardening_notes(result)
        self._dedupe_findings(result)
        self._filter_findings(result)
        result.risk_score = self._calculate_risk_score(result)
        result.risk_level = self._classify_risk(result.risk_score)

        # Re-sort after adding header findings
        sev_rank = {s: i for i, s in enumerate(
            ["critical", "high", "medium", "low", "info", "unknown"]
        )}
        result.findings.sort(key=lambda f: sev_rank.get(f.severity, 99))

        # Update summary counts after normalization
        sev_counts: dict = {}
        for f in result.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        result.severity_summary = sev_counts
        result.total_findings   = len(result.findings)
        result.limitations = list(dict.fromkeys(result.limitations))

        return result

    def _inject_remediations(self, result: AggregatedResult) -> None:
        for f in result.findings:
            if f.remediation:
                continue  # Already has remediation

            # TLS-specific
            if f.source == "testssl.sh":
                f.remediation = self._tls_remediation(f.id)
                continue

            # Port-specific
            if f.source in ("naabu/nmap",):
                port = self._extract_port(f.id)
                if port and port in _PORT_REMEDIATION:
                    f.remediation = _PORT_REMEDIATION[port]
                    continue

            # Nuclei template-specific
            if f.source == "nuclei":
                template_id = f.extra.get("template_id", "").lower()
                text = f"{template_id} {f.title} {f.description}".lower()
                for key, remediation in _NUCLEI_REMEDIATION.items():
                    if key in text:
                        f.remediation = remediation
                        break
                if f.remediation:
                    continue

            # Nikto pattern-specific
            if f.source == "nikto":
                text = f"{f.title} {f.description}".lower()
                for key, remediation in _NIKTO_REMEDIATION.items():
                    if key in text:
                        f.remediation = remediation
                        break
                if f.remediation:
                    continue

            # Dalfox XSS-specific
            if f.source == "dalfox":
                f.remediation = _DALFOX_REMEDIATION
                continue

            if f.source == "s3scanner":
                f.remediation = _S3_REMEDIATION
                continue

            if f.source in {"wpscan", "joomscan"}:
                f.remediation = _CMS_REMEDIATION
                continue

            # Generic by severity
            f.remediation = _GENERIC_REMEDIATION.get(f.severity, _GENERIC_REMEDIATION["info"])

    def _record_header_hardening_notes(self, result: AggregatedResult) -> None:
        """Record missing security headers as hardening notes, not findings."""
        if not result.live_hosts:
            return

        for header_def in _MISSING_HEADER_FINDINGS:
            hname = header_def["header"]
            affected = {
                host["url"]
                for host in result.live_hosts
                if self._header_check_applies(host, hname)
                if hname not in {hdr.lower() for hdr in (host.get("headers") or {}).keys()}
            }
            if not affected:
                continue

            result.limitations.append(
                f"Hardening note: {header_def['title']} on {len(affected)} endpoint(s)."
            )

    def _dedupe_findings(self, result: AggregatedResult) -> None:
        deduped: list[Finding] = []
        seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
        for finding in result.findings:
            finding.affected = sorted(dict.fromkeys(finding.affected))
            key = (
                finding.source.strip().lower(),
                finding.title.strip().lower(),
                finding.description.strip().lower(),
                tuple(item.strip().lower() for item in finding.affected),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        result.findings = deduped

    def _filter_findings(self, result: AggregatedResult) -> None:
        filtered: list[Finding] = []
        excluded = 0
        result.observed_findings_count = len(result.findings)
        if self.scan_mode == "deep":
            keep_fn = self._should_keep_finding_deep
        elif self.scan_mode == "api":
            keep_fn = self._should_keep_finding_api
        else:
            keep_fn = self._should_keep_finding
        for finding in result.findings:
            if keep_fn(finding):
                filtered.append(finding)
            else:
                excluded += 1

        result.excluded_findings_count = excluded
        if excluded:
            result.notes.append(
                f"{excluded} low-signal or hardening-only finding(s) were excluded from the final report."
            )
        result.findings = filtered

    @staticmethod
    def _header_check_applies(host: dict, header_name: str) -> bool:
        url = str(host.get("url", "")).lower()
        if header_name == "strict-transport-security":
            return url.startswith("https://")
        return True

    def _assign_confidence(self, result: AggregatedResult) -> None:
        for finding in result.findings:
            confidence, score, reason = self._confidence_for_finding(finding)
            finding.confidence = confidence
            finding.confidence_score = score
            finding.confidence_reason = reason

    def _confidence_for_finding(self, finding: Finding) -> tuple[str, int, str]:
        kind = str(finding.extra.get("kind", "")).lower()
        severity = str(finding.severity or "info").lower()
        text = " ".join([
            finding.title or "",
            finding.description or "",
            finding.evidence_status or "",
            finding.exploitability or "",
            " ".join(finding.tags or []),
        ]).lower()

        if finding.source == "sqlmap":
            return (
                "confirmed",
                95,
                "SQLMap reported active exploitation evidence for the affected parameter.",
            )

        if kind == "exposed-service":
            return (
                "confirmed",
                90,
                "The service exposure was directly observed during port and service scanning.",
            )

        if finding.source == "api-scan":
            return self._api_confidence(finding)

        if finding.source == "dalfox":
            if severity in {"critical", "high"}:
                return (
                    "probable",
                    80,
                    "A specialized XSS scanner identified a high-impact payload condition, but browser-context validation is still recommended.",
                )
            return (
                "needs_manual_validation",
                55,
                "The XSS signal should be replayed manually before it is treated as confirmed.",
            )

        if finding.source == "nuclei":
            if severity in {"critical", "high"}:
                score = 82 if finding.cve_ids else 76
                return (
                    "probable",
                    score,
                    "A structured Nuclei template matched the target; manual validation is recommended before treating it as confirmed exploitation.",
                )
            if severity == "medium" and any(marker in text for marker in ("cve-", "auth", "takeover", "rce", "sql injection", "ssrf", "xss")):
                return (
                    "probable",
                    68,
                    "The finding matched a security-relevant template and keyword pattern, but needs analyst confirmation.",
                )
            return (
                "needs_manual_validation",
                45,
                "The template match is lower-signal or hardening-oriented and should be reviewed in context.",
            )

        if finding.source in {"s3scanner", "wpscan", "joomscan"}:
            return (
                "probable" if severity in {"critical", "high", "medium"} else "needs_manual_validation",
                72 if severity in {"critical", "high"} else 60,
                "A specialized scanner produced the observation; validate affected asset ownership and exploitability manually.",
            )

        if finding.source == "testssl.sh":
            if any(marker in text for marker in ("heartbleed", "robot", "drown", "logjam", "sweet32", "freak", "poodle", "rc4")):
                return (
                    "probable",
                    75,
                    "The TLS scanner identified a named transport security weakness.",
                )
            return (
                "needs_manual_validation",
                45,
                "The TLS observation is configuration-oriented and should be prioritized with service context.",
            )

        if getattr(finding, "validated", False):
            return (
                "confirmed",
                85,
                "The finding was marked as validated by the aggregation layer.",
            )

        if severity in {"critical", "high"}:
            return (
                "probable",
                65,
                "The issue is high impact, but the available automated evidence still needs analyst validation.",
            )

        return (
            "needs_manual_validation",
            40,
            "The automated signal is not enough to confirm exploitability without manual review.",
        )

    def _api_confidence(self, finding: Finding) -> tuple[str, int, str]:
        kind = str(finding.extra.get("kind", "")).lower()
        similarity = float(finding.extra.get("response_similarity", 0) or 0)
        has_financial_fields = bool(finding.extra.get("has_financial_fields"))
        is_key_swap = bool(finding.extra.get("is_key_swap"))
        status = int(finding.extra.get("status", 0) or 0)

        if kind == "api-negative-control-accepted":
            if has_financial_fields or is_key_swap:
                return (
                    "confirmed",
                    92,
                    "A negative-control request unexpectedly returned a successful business response with financial fields or key-swap evidence.",
                )
            return (
                "probable",
                78,
                "A request designed to fail returned HTTP success; validate the business impact manually.",
            )

        if kind == "api-invalid-auth-accepted":
            if similarity >= 0.85:
                return (
                    "confirmed",
                    90,
                    "Replacing authentication material produced a successful response that closely matched the authenticated response.",
                )
            return (
                "probable",
                76,
                "Invalid authentication was accepted, but response similarity should be reviewed manually.",
            )

        if kind == "api-signature-bypass-candidate":
            if similarity >= 0.85:
                return (
                    "confirmed",
                    88,
                    "Removing or corrupting signature material produced a successful response similar to the signed request.",
                )
            return (
                "probable",
                74,
                "Signature enforcement appears weak, but the response difference needs manual validation.",
            )

        if kind == "api-idor-candidate":
            if similarity >= 0.85:
                return (
                    "probable",
                    72,
                    "Identifier tampering returned a successful, similar response; object ownership must be confirmed manually.",
                )
            return (
                "needs_manual_validation",
                58,
                "Identifier tampering returned success, but the response does not yet prove cross-object access.",
            )

        if kind == "api-sensitive-data":
            return (
                "probable",
                72,
                "The API returned patterns consistent with sensitive data in a successful response.",
            )

        if kind == "api-public-authenticated-resource":
            return (
                "needs_manual_validation",
                55,
                "The endpoint succeeded anonymously and with authentication, but it may be intentionally public.",
            )

        if status >= 500:
            return (
                "probable",
                62,
                "The API returned a server-side error condition that should be reviewed for exploitable behavior.",
            )

        return (
            "needs_manual_validation",
            50,
            "The API scanner produced an application-layer signal that needs manual review.",
        )

    def _calculate_risk_score(self, result: AggregatedResult) -> float:
        score = 0.0

        # Findings weight
        for f in result.findings:
            multiplier = max(0.25, min(getattr(f, "confidence_score", 40) / 100, 1.0))
            score += SEVERITY_WEIGHT.get(f.severity, 0.1) * multiplier

        # Dangerous ports bonus
        score += len(result.dangerous_ports) * 2.0

        # Large attack surface penalty
        if len(result.subdomains) > 20:
            score += min((len(result.subdomains) - 20) * 0.1, 5.0)

        # CDN bypass found
        if result.origin_candidates:
            score += 1.5

        # Many live hosts
        if len(result.live_hosts) > 30:
            score += 2.0

        return min(round(score, 1), 100.0)

    @staticmethod
    def _classify_risk(score: float) -> str:
        if score >= 25:  return "Critical"
        if score >= 12:  return "High"
        if score >= 5:   return "Medium"
        if score >= 1:   return "Low"
        return "Informational"

    @staticmethod
    def _tls_remediation(finding_id: str) -> str:
        fid_lower = finding_id.lower()
        for key, rem in _TLS_REMEDIATION.items():
            if key in fid_lower:
                return rem
        return (
            "Review TLS configuration using Mozilla SSL Configuration Generator. "
            "Enforce TLS 1.2+ and disable legacy protocols and weak cipher suites."
        )

    @staticmethod
    def _extract_port(finding_id: str) -> int | None:
        # finding_id format: "port-XXXX"
        parts = finding_id.split("-")
        if len(parts) >= 2 and parts[-1].isdigit():
            return int(parts[-1])
        return None

    @staticmethod
    def _should_keep_finding(finding: Finding) -> bool:
        kind = str(finding.extra.get("kind", "")).lower()
        text = " ".join(
            [
                finding.title or "",
                finding.description or "",
                " ".join(finding.tags or []),
                " ".join(finding.cve_ids or []),
            ]
        ).lower()

        if kind == "exposed-service":
            return finding.severity in {"critical", "high"}

        if kind == "tls":
            return any(
                marker in text
                for marker in (
                    "heartbleed",
                    "robot",
                    "drown",
                    "logjam",
                    "sweet32",
                    "freak",
                    "poodle",
                    "rc4",
                )
            )

        if finding.source == "nikto":
            return any(
                marker in text
                for marker in (
                    "sql injection",
                    "remote code execution",
                    "command injection",
                    "xss",
                    "path traversal",
                    "file disclosure",
                    "cve-",
                )
            )

        if finding.source == "dalfox":
            return finding.severity in {"critical", "high", "medium"}

        if finding.source in {"s3scanner", "wpscan", "joomscan"}:
            return finding.severity in {"critical", "high", "medium"}

        if finding.source == "nuclei":
            if finding.severity in {"critical", "high"}:
                return True
            if finding.severity != "medium":
                return False
            return any(
                marker in text
                for marker in (
                    "cve-",
                    "auth",
                    "takeover",
                    "rce",
                    "remote code execution",
                    "sql injection",
                    "ssrf",
                    "deserialization",
                    "lfi",
                    "rfi",
                    "traversal",
                    "xss",
                )
            )

        return finding.severity in {"critical", "high"}

    @staticmethod
    def _should_keep_finding_deep(finding: Finding) -> bool:
        """Relaxed filter for deep scan mode — keeps more findings in the report."""
        kind = str(finding.extra.get("kind", "")).lower()

        # Keep all nuclei findings of medium+ severity (no keyword gating)
        if finding.source == "nuclei":
            return finding.severity in {"critical", "high", "medium"}

        # Keep all TLS findings (not just named attacks)
        if kind == "tls":
            return True

        # Keep exposed-service findings of ALL risk levels
        if kind == "exposed-service":
            return True

        # Keep nikto findings with medium+ severity
        if finding.source == "nikto":
            return finding.severity in {"critical", "high", "medium"}

        # Keep specialized XSS findings
        if finding.source == "dalfox":
            return finding.severity in {"critical", "high", "medium"}

        if finding.source in {"s3scanner", "wpscan", "joomscan"}:
            return finding.severity in {"critical", "high", "medium"}

        # Default: keep if medium or higher
        return finding.severity in {"critical", "high", "medium"}

    @staticmethod
    def _should_keep_finding_api(finding: Finding) -> bool:
        """API mode keeps application-layer API findings at medium+ severity."""
        if finding.source == "api-scan":
            return finding.severity in {"critical", "high", "medium"}
        return Normalizer._should_keep_finding(finding)

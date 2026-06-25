"""
PentestBot v2 - Groq AI Analyzer
Generates concise, engineering-focused narrative sections for the PDF report.
"""

import asyncio
import json
import re
import textwrap
from dataclasses import dataclass, field

import httpx

from analysis.result_aggregator import AggregatedResult
from config import GroqConfig
from utils.logger import get_logger

logger = get_logger("analysis.groq")

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


@dataclass
class AIAnalysis:
    executive_summary: str = ""
    scope_and_coverage: str = ""
    attack_surface: str = ""
    vulnerability_analysis: str = ""
    network_exposure: str = ""
    tls_analysis: str = ""
    realistic_risk_summary: str = ""
    attack_path_simulation: str = ""
    remediation_plan: str = ""
    conclusion: str = ""
    initial_recommendations: str = ""
    error_sections: list[str] = field(default_factory=list)

    def all_sections(self) -> dict[str, str]:
        return {
            "executive_summary": self.executive_summary,
            "scope_and_coverage": self.scope_and_coverage,
            "attack_surface": self.attack_surface,
            "vulnerability_analysis": self.vulnerability_analysis,
            "network_exposure": self.network_exposure,
            "tls_analysis": self.tls_analysis,
            "realistic_risk_summary": self.realistic_risk_summary,
            "attack_path_simulation": self.attack_path_simulation,
            "remediation_plan": self.remediation_plan,
            "conclusion": self.conclusion,
            "initial_recommendations": self.initial_recommendations,
        }


class GroqAI:
    SECTION_BATCH_SIZE = 1
    INTER_SECTION_DELAY_SECONDS = 5.0
    SECTION_MAX_TOKENS = {
        "executive_summary": 800,
        "scope_and_coverage": 800,
        "attack_surface": 800,
        "vulnerability_analysis": 1000,
        "network_exposure": 800,
        "tls_analysis": 800,
        "realistic_risk_summary": 800,
        "attack_path_simulation": 800,
        "remediation_plan": 1000,
        "conclusion": 800,
        "initial_recommendations": 1200,
    }

    SYSTEM_PROMPT = textwrap.dedent("""
        You are a senior security engineer writing sections for an automated security assessment report.

        Rules:
        - Write in clear, direct, professional English.
        - Assume the reader is a security engineer or IT professional. Do NOT define basic concepts like HSTS, TLS, or Cross-Site Scripting.
        - Be concise. Focus purely on observations and practical impacts.
        - Avoid repeating the same points across multiple sections (e.g., if a TLS issue is covered in the TLS section, do not artificially emphasize it again elsewhere).
        - Be conservative and evidence-driven.
        - Do not invent findings, exploit paths, CVEs, versions, or business impact.
        - Clearly distinguish directly observed conditions from inferred risk.
        - Avoid numerical scoring, percentages, and generic "HIGH RISK" style language.
        - Avoid hype. Do not exaggerate theoretical TLS or header issues.
        - Use realistic attacker language and practical remediation advice.
        - Do not use markdown, headings, or bullet points.
        - Write short, well-structured prose paragraphs only.
        - Always finish your text with a complete sentence. Never cut off midway.
    """).strip()

    def __init__(self, config: GroqConfig):
        self.config = config
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(config.timeout))
        logger.info(f"[GroqAI] Initialized with {len(config.api_keys)} API key(s) (round-robin)")

    async def analyze(self, result: AggregatedResult) -> AIAnalysis:
        logger.info(f"[GroqAI] Starting analysis for scan {result.scan_id}")
        ctx = self._build_context(result)
        analysis = AIAnalysis()

        sections = [
            ("executive_summary", self._prompt_executive(result, ctx)),
            ("scope_and_coverage", self._prompt_scope(result, ctx)),
            ("attack_surface", self._prompt_attack_surface(result, ctx)),
            ("vulnerability_analysis", self._prompt_vulnerabilities(result, ctx)),
            ("network_exposure", self._prompt_network(result, ctx)),
            ("tls_analysis", self._prompt_tls(result, ctx)),
            ("realistic_risk_summary", self._prompt_realistic_risk(result, ctx)),
            ("attack_path_simulation", self._prompt_attack_paths(result, ctx)),
            ("remediation_plan", self._prompt_remediation(result, ctx)),
            ("conclusion", self._prompt_conclusion(result, ctx)),
            ("initial_recommendations", self._prompt_initial_recommendations(result, ctx)),
        ]

        for start in range(0, len(sections), self.SECTION_BATCH_SIZE):
            batch = sections[start:start + self.SECTION_BATCH_SIZE]
            tasks = [self._fetch_section(name, prompt) for name, prompt in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for (name, _), outcome in zip(batch, results):
                if isinstance(outcome, Exception):
                    logger.error(f"[GroqAI] Section '{name}' failed: {outcome}")
                    setattr(analysis, name, self._fallback(name, result))
                    analysis.error_sections.append(name)
                else:
                    setattr(analysis, name, outcome)

            if start + self.SECTION_BATCH_SIZE < len(sections):
                await asyncio.sleep(self.INTER_SECTION_DELAY_SECONDS)

        logger.info(f"[GroqAI] Done. Failed sections: {analysis.error_sections or 'none'}")
        return analysis

    async def _fetch_section(self, name: str, prompt: str) -> str:
        for attempt in range(1, self.config.retry_attempts + 1):
            try:
                max_tokens = self.SECTION_MAX_TOKENS.get(name, self.config.max_tokens)
                return await self._call(prompt, max_tokens=max_tokens)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 429 and attempt < self.config.retry_attempts:
                    wait = self._rate_limit_wait_seconds(exc, attempt)
                    logger.warning(f"[GroqAI] Rate limited on '{name}'. Retry {attempt} in {wait}s")
                    await asyncio.sleep(wait)
                else:
                    raise
            except Exception:
                if attempt < self.config.retry_attempts:
                    await asyncio.sleep(2 ** attempt)
                else:
                    raise
        raise RuntimeError(f"All retries failed for section '{name}'")

    async def _call(self, user_prompt: str, max_tokens: int) -> str:
        payload = {
            "model": self.config.model,
            "max_completion_tokens": min(max_tokens, self.config.max_tokens),
            "temperature": self.config.temperature,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        }
        api_key = self.config.next_key()
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        logger.debug(f"[GroqAI] Using key ...{api_key[-6:]}")
        response = await self._client.post(GROQ_URL, json=payload, headers=headers)
        if response.is_error:
            detail = response.text[:500].replace("\n", " ").strip()
            raise httpx.HTTPStatusError(
                f"{response.status_code} error from Groq: {detail}",
                request=response.request,
                response=response,
            )
        data = response.json()
        return data["choices"][0]["message"]["content"].strip()

    def _build_context(self, result: AggregatedResult) -> str:
        top_findings = []
        for finding in result.findings[:6]:
            top_findings.append({
                "title": finding.title,
                "severity": finding.severity,
                "confidence": getattr(finding, "confidence", "needs_manual_validation"),
                "confidence_score": getattr(finding, "confidence_score", 40),
                "affected": finding.affected[:2],
                "source": finding.source,
                "validated": getattr(finding, "validated", False),
            })

        service_summary = []
        for service in result.services[:8]:
            host = str(service.get("host", "")).strip()
            port = service.get("port", "")
            name = str(service.get("service", "")).strip()
            version = str(service.get("version", "")).strip()
            parts = [str(part) for part in (host, port, name, version) if str(part).strip()]
            if parts:
                service_summary.append(" | ".join(parts))

        live_host_summary = []
        for host in result.live_hosts[:8]:
            url = str(host.get("url", "")).strip()
            status = host.get("status_code", "")
            title = str(host.get("title", "")).strip()
            server = str(host.get("web_server", "")).strip()
            if url:
                suffix = " ".join(str(part) for part in (status, server, title[:60]) if str(part).strip())
                live_host_summary.append(f"{url} {suffix}".strip())

        tls_summary = []
        for finding in result.tls_findings[:6]:
            fid = str(finding.get("id", "")).strip()
            desc = str(finding.get("description", "")).strip()[:120]
            sev = str(finding.get("severity", "")).strip()
            tls_summary.append(" | ".join(part for part in (fid, sev, desc) if part))

        ctx = {
            "target": result.target,
            "target_type": result.target_type,
            "scan_duration_seconds": int(result.scan_duration),
            "subdomains": result.subdomains[:8],
            "resolved_ips": result.resolved_ips[:6],
            "cdn_detected": result.cdn_detected,
            "origin_candidates": result.origin_candidates[:3],
            "open_ports": [port.port for port in result.open_ports[:20]],
            "dangerous_ports": [
                {
                    "port": port.port,
                    "service": port.service_name,
                    "risk_level": port.risk_level,
                    "risk_note": port.risk_note,
                }
                for port in result.dangerous_ports[:10]
            ],
            "services": service_summary,
            "live_hosts": live_host_summary,
            "discovered_urls": result.discovered_urls[:10],
            "technologies": result.technologies[:8],
            "web_servers": result.web_servers[:5],
            "certificate": result.cert_info,
            "tls_findings": tls_summary,
            "severity_summary": result.severity_summary,
            "total_findings": result.total_findings,
            "observed_findings": getattr(result, "observed_findings_count", result.total_findings),
            "excluded_findings": getattr(result, "excluded_findings_count", 0),
            "top_findings": top_findings,
            "limitations": result.limitations[:8],
            "tool_errors": result.tool_errors[:6],
            "scan_mode": getattr(result, "scan_mode", "fast"),
            "tools_used": result.tools_used,
        }
        return json.dumps(ctx, indent=2, default=str)

    def _prompt_executive(self, result: AggregatedResult, ctx: str) -> str:
        return f"""
Write the Executive Summary for an automated security assessment report.

Target: {result.target}
Findings: {result.total_findings}
Severity summary: {result.severity_summary}
Observed indicators: {getattr(result, "observed_findings_count", result.total_findings)}
Excluded observations: {getattr(result, "excluded_findings_count", 0)}

Scan data:
{ctx}

Requirements:
- Do not use numeric scores or percentage-based language.
- Replace generic "high risk" phrasing with realistic statements such as
  "No immediate critical exploit was confirmed" or
  "Multiple misconfigurations increase attack surface."
- State what was actually exposed, what was directly exploitable, and what remains uncertain.
- Keep it concise and leadership-friendly without becoming vague.

Write 3 to 4 short paragraphs.
""".strip()

    def _prompt_scope(self, result: AggregatedResult, ctx: str) -> str:
        if getattr(result, "scan_mode", "") == "api":
            tools_ran = "PentestBot API checks against operator-supplied API endpoints and payloads."
            mode_requirement = (
                "- Clearly state that infrastructure recon, DNS resolution, port scanning, web crawling, "
                "Nuclei/Nikto vulnerability scanning, and TLS analysis were not executed in API-only mode."
            )
        else:
            tools_ran = (
                "subdomain discovery, DNS resolution, port scanning, service detection, HTTP probing, "
                "technology fingerprinting, web discovery, vulnerability scanning (Nuclei/Nikto), TLS analysis."
            )
            mode_requirement = "- State which scanning phases were executed and what was covered."

        return f"""
Write the Scope & Coverage section for an automated security assessment report.

Target: {result.target}
Tools ran: {tools_ran}
Tool errors: {result.tool_errors[:8]}
Limitations: {result.limitations[:8]}
Observed indicators: {getattr(result, "observed_findings_count", result.total_findings)}
Excluded observations: {getattr(result, "excluded_findings_count", 0)}
Scan duration: {int(result.scan_duration)} seconds

Requirements:
{mode_requirement}
- Note any tools that failed or produced partial results.
- Explain what was excluded from the final findings set and why.
- Clarify that this is an automated scan, not manual testing.
- State known limitations of the methodology honestly.

Write 3 to 4 short paragraphs.
""".strip()

    def _prompt_attack_surface(self, result: AggregatedResult, ctx: str) -> str:
        return f"""
Write the Attack Surface Overview section for an automated security assessment report.

Target: {result.target}
Subdomains: {len(result.subdomains)}
Resolved IPs: {len(result.resolved_ips)}
Open ports: {[port.port for port in result.open_ports[:20]]}
Technologies: {result.technologies[:10]}

Scan data:
{ctx}

Requirements:
- Focus on what was externally reachable.
- Explain what the exposed ports, services, hosts, and technology stack mean in practice.
- Mention CDN or origin exposure if relevant.
- Stay factual and avoid severity inflation.

Write 3 to 4 short paragraphs.
""".strip()

    def _prompt_vulnerabilities(self, result: AggregatedResult, ctx: str) -> str:
        findings_detail = json.dumps([
            {
                "title": finding.title,
                "severity": finding.severity,
                "description": finding.description[:260],
                "affected": finding.affected[:3],
                "source": finding.source,
            }
            for finding in result.findings[:10]
        ], indent=2, default=str)

        return f"""
Write the Vulnerability Review section for an automated security assessment report.

Target: {result.target}
Representative findings:
{findings_detail}

Requirements:
- Group findings by practical significance, not by score.
- Clearly mark when an item is a directly observed weakness versus a lower-confidence indicator.
- Reduce false-positive impact by calling out uncertainty when appropriate.
- Do not overstate informational detections.
- Assume low-signal hardening notes were already filtered out of the main findings set.

Write 4 to 5 short paragraphs.
""".strip()

    def _prompt_network(self, result: AggregatedResult, ctx: str) -> str:
        return f"""
Write the Network Exposure section for an automated security assessment report.

Target: {result.target}
Open ports: {[port.port for port in result.open_ports[:20]]}
Dangerous ports: {[f"{port.port}/{port.service_name}" for port in result.dangerous_ports[:10]]}
Services: {result.services[:10]}

Scan data:
{ctx}

Requirements:
- Explain which network services matter most from an attacker perspective.
- Call out directly reachable administrative or legacy services if present.
- Be conservative when service evidence is incomplete.

Write 3 to 4 short paragraphs.
""".strip()

    def _prompt_tls(self, result: AggregatedResult, ctx: str) -> str:
        return f"""
Write the TLS and Transport Security section for an automated security assessment report.

Target: {result.target}
Certificate info: {json.dumps(result.cert_info, indent=2, default=str)}
TLS findings: {json.dumps(result.tls_findings[:10], indent=2, default=str)}

Requirements:
- Avoid exaggerated references to legacy TLS attacks unless there is direct evidence.
- Explain what the observed TLS and certificate state means operationally.
- If data is partial or came from fallback tooling, state that clearly.

Write 3 to 4 short paragraphs.
""".strip()

    def _prompt_realistic_risk(self, result: AggregatedResult, ctx: str) -> str:
        return f"""
Write the Realistic Risk Summary section for an automated security assessment report.

Target: {result.target}
Findings: {result.total_findings}
Tool errors: {result.tool_errors[:8]}
Observed indicators: {getattr(result, "observed_findings_count", result.total_findings)}

Scan data:
{ctx}

Requirements:
- Do not use scores, percentages, or blanket overall labels.
- Clearly state whether the system appears directly exploitable based on current evidence.
- State what type of attacker would realistically care about these findings.
- State whether the issues could be chained into a stronger attack path.
- Distinguish confirmed attack paths from plausible but unconfirmed chains.
- If no validated chain is present, say that explicitly and avoid inventing one.

Write 3 to 4 short paragraphs.
""".strip()

    def _prompt_attack_paths(self, result: AggregatedResult, ctx: str) -> str:
        return f"""
Write the Attack Path Simulation section for an automated security assessment report.

Target: {result.target}
Top findings: {json.dumps([finding.title for finding in result.findings[:10]], indent=2)}
Observed indicators: {getattr(result, "observed_findings_count", result.total_findings)}

Scan data:
{ctx}

Requirements:
- Describe 1 or 2 realistic attack scenarios only if they are supported by the findings.
- Each scenario should explain preconditions, attacker capability, and likely outcome.
- Clearly state when a chain is hypothetical rather than confirmed.
- Avoid dramatic language.

Write 3 to 4 paragraphs.
""".strip()

    def _prompt_remediation(self, result: AggregatedResult, ctx: str) -> str:
        return f"""
Write the Remediation Priorities section for an automated security assessment report.

Target: {result.target}
Top findings: {json.dumps([
    {
        "title": finding.title,
        "severity": finding.severity,
        "remediation": finding.remediation,
        "source": finding.source,
    }
    for finding in result.findings[:10]
], indent=2, default=str)}

Requirements:
- Organize recommendations as immediate fixes, short-term fixes, and hardening actions.
- Keep the recommendations practical and implementation-oriented.
- Avoid compliance-style filler.

Write 4 to 5 short paragraphs.
""".strip()

    def _prompt_conclusion(self, result: AggregatedResult, ctx: str) -> str:
        return f"""
Write the Conclusion for an automated security assessment report.

Target: {result.target}
Findings: {result.total_findings}
Severity summary: {result.severity_summary}
Open ports: {[port.port for port in result.open_ports[:10]]}
Technologies: {result.technologies[:5]}

Requirements:
- Summarize the overall security posture based on what was observed during this assessment.
- Highlight the most significant risk areas and whether they represent immediate, short-term, or long-term concerns.
- State the most important next actions the organization should take.
- Recommend whether follow-up manual testing, periodic reassessment, or deeper investigation is warranted.
- Close with a forward-looking statement about maintaining security hygiene.

Write 3 to 4 well-developed paragraphs.
""".strip()

    def _prompt_initial_recommendations(self, result: AggregatedResult, ctx: str) -> str:
        return f"""
Write an "Initial Security Recommendations for Developers" note for the end of a automated security assessment report.

Target: {result.target}
Findings: {result.total_findings}
Severity summary: {result.severity_summary}
Technologies detected: {result.technologies[:10]}
Open ports: {[port.port for port in result.open_ports[:20]]}
TLS findings count: {len(result.tls_findings)}
CDN detected: {result.cdn_detected}

Full scan data:
{ctx}

Requirements:
- Based on ALL available scan data, provide practical, prioritized security recommendations that developers should implement first to secure this specific website.
- Tailor the recommendations to the actual technologies, services, and weaknesses discovered during the scan.
- Cover areas such as: HTTPS and transport security, security headers, input validation, dependency management, access control, logging, server hardening, and ongoing security practices.
- Do not repeat the remediation section verbatim; instead focus on foundational developer-level actions that apply as an initial security baseline informed by what the scan revealed.
- Be specific where the data supports it (e.g., if a particular header is missing or a specific service is exposed, mention it).
- Write in clear, direct prose paragraphs without markdown formatting, bullet points, or headings.
- Keep the tone constructive and actionable.

Write 4 to 6 short paragraphs.
""".strip()

    @staticmethod
    def _rate_limit_wait_seconds(exc: httpx.HTTPStatusError, attempt: int) -> int:
        detail = ""
        try:
            detail = exc.response.text
        except Exception:
            detail = str(exc)

        match = re.search(r"try again in\s+([0-9]+(?:\.[0-9]+)?)s", detail, re.IGNORECASE)
        if match:
            return max(2, int(float(match.group(1)) + 1))
        return min(20, 3 * attempt + 2)

    @staticmethod
    def _fallback(section: str, result: AggregatedResult) -> str:
        has_serious = any(f.severity in {"critical", "high"} for f in result.findings)
        likely_exposed = bool(result.dangerous_ports) or has_serious

        fallbacks = {
            "executive_summary": (
                f"The automated assessment of {result.target} identified {result.total_findings} observed issues. "
                f"No numerical risk score is presented in this report. "
                + (
                    "The current evidence suggests directly actionable weaknesses may be present and should be reviewed promptly. "
                    if likely_exposed else
                    "No immediate critical exploit was confirmed during automated testing, although several conditions may still expand attack surface. "
                )
                + "Manual validation remains important before treating any detection as confirmed compromise risk."
            ),
            "attack_surface": (
                f"The exposed surface for {result.target} included {len(result.subdomains)} discovered subdomains, "
                f"{len(result.resolved_ips)} resolved IP addresses, and {len(result.open_ports)} open ports. "
                f"Technology fingerprinting identified {len(result.technologies)} technologies and {len(result.live_hosts)} reachable web endpoints."
            ),
            "vulnerability_analysis": (
                f"The scan produced {result.total_findings} normalized findings. "
                "These findings should be interpreted as a mix of directly observed weaknesses, configuration indicators, and lower-confidence informational detections."
            ),
            "network_exposure": (
                f"Network enumeration exposed {len(result.open_ports)} reachable ports and {len(result.services)} identified services. "
                "Administrative or legacy services should be reviewed first because they typically provide the fastest attacker path to meaningful access."
            ),
            "tls_analysis": (
                f"TLS review identified {len(result.tls_findings)} transport-security observations. "
                "Where tooling produced partial output, the report should be read as a best-effort view rather than a complete cryptographic assessment."
            ),
            "realistic_risk_summary": (
                "This report favors practical risk over numeric scoring. "
                + (
                    "Based on the observed exposure, a motivated external attacker would likely focus on exposed services and web-facing misconfigurations. "
                    if likely_exposed else
                    "The current evidence does not confirm an immediate critical exploit path, but multiple weaknesses may still support reconnaissance or follow-on attacks. "
                )
                + "Any chained attack scenario should be validated manually before it is treated as a confirmed compromise path."
            ),
            "attack_path_simulation": (
                "A realistic attack path would begin with externally reachable services or web application behavior already visible from the Internet, "
                "then attempt to combine configuration weaknesses with application-specific flaws. "
                "Where no confirmed exploit chain is present, the scenario should be treated as plausible rather than proven."
            ),
            "remediation_plan": (
                "Prioritize remediation by practical attacker value: first remove or harden directly reachable services and security-sensitive web misconfigurations, "
                "then address broader hardening items and informational findings during the next maintenance cycle."
            ),
            "scope_and_coverage": (
                f"This assessment was conducted as an automated external reconnaissance scan of {result.target}. "
                f"The scan pipeline executed subdomain discovery, DNS resolution, port scanning, service detection, "
                f"HTTP probing, technology fingerprinting, web crawling, Nuclei-based vulnerability scanning, and TLS analysis. "
                f"{len(result.tool_errors)} tool errors were recorded and "
                f"{getattr(result, 'excluded_findings_count', 0)} low-signal observations were excluded from the final report. "
                "As an automated assessment, results should be validated through manual testing before drawing definitive security conclusions."
            ),
            "conclusion": (
                f"The automated review of {result.target} is complete. "
                "The result should be used as an engineering-oriented starting point for remediation and targeted manual verification, not as a final statement that the environment is secure."
            ),
            "initial_recommendations": (
                f"Based on the automated assessment of {result.target}, developers should prioritize the following baseline security measures. "
                "Enforce HTTPS across all endpoints using TLS 1.2 or higher and enable HSTS with includeSubDomains. "
                "Deploy essential security headers including Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy. "
                "Validate and sanitize all user input on the server side using parameterized queries and context-aware output encoding. "
                "Keep all software dependencies current and monitor for known vulnerabilities using automated tools. "
                "Implement strong authentication with multi-factor authentication for administrative accounts and apply least-privilege access control. "
                "Suppress server version banners and technology fingerprints that aid attacker reconnaissance. "
                "Enable centralized logging for authentication events and access control failures. "
                "Schedule periodic security assessments combining automated scanning with manual security reviews."
            ),
        }
        return fallbacks.get(section, "Analysis unavailable for this section.")

    # ── Per-Finding AI Enrichment ─────────────────────────────────────────────

    ENRICHMENT_MAX_FINDINGS = 10
    ENRICHMENT_MAX_TOKENS = 200
    ENRICHMENT_DELAY_SECONDS = 3.0

    async def enrich_findings(self, findings: list) -> list:
        """
        Enrich the top N findings with AI-rewritten descriptions.
        Each finding gets a contextual, analyst-grade description replacing
        the raw tool output. Failures fall back silently to the original text.
        """
        from analysis.result_aggregator import Finding

        to_enrich = findings[:self.ENRICHMENT_MAX_FINDINGS]
        if not to_enrich:
            return findings

        logger.info(f"[GroqAI] Enriching {len(to_enrich)} findings with AI descriptions")
        enriched_count = 0

        for i, finding in enumerate(to_enrich):
            try:
                prompt = self._prompt_enrich_finding(finding)
                enriched_text = await self._call(prompt, max_tokens=self.ENRICHMENT_MAX_TOKENS)
                if enriched_text and len(enriched_text) > 30:
                    # Store original as raw, replace with enriched
                    finding.extra["original_description"] = finding.description
                    finding.description = enriched_text.strip()
                    enriched_count += 1

                if i < len(to_enrich) - 1:
                    await asyncio.sleep(self.ENRICHMENT_DELAY_SECONDS)

            except Exception as exc:
                logger.warning(f"[GroqAI] Finding enrichment failed for '{finding.title[:40]}': {exc}")
                # Keep original description — no change

        logger.info(f"[GroqAI] Enrichment complete: {enriched_count}/{len(to_enrich)} findings improved")
        return findings

    @staticmethod
    def _prompt_enrich_finding(finding) -> str:
        cve_str = ", ".join(finding.cve_ids[:3]) if finding.cve_ids else "none"
        affected_str = ", ".join(finding.affected[:3]) if finding.affected else "unknown"
        return f"""
Rewrite this scanner finding description for a professional automated security assessment report.

Finding title: {finding.title}
Severity: {finding.severity}
Source tool: {finding.source}
Affected: {affected_str}
CVEs: {cve_str}
Original scanner output: {finding.description[:500]}

Rules:
- Write 2-3 sentences explaining what was ACTUALLY OBSERVED on the target.
- Explain WHY this matters from a realistic attacker's perspective.
- Distinguish between confirmed weakness and informational detection.
- Do not describe how the scanning tool works. Focus on what it found.
- Do not use markdown, headings, or bullet points.
- Do not invent data, CVEs, or versions not present in the original output.
- Be precise and factual. If the severity is low/info, do not overstate the risk.
- Write professional, concise prose.
""".strip()

    async def close(self) -> None:
        await self._client.aclose()

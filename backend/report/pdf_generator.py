"""
ScanBot - PDF Generator
Produces a professional, engineering-focused automated security assessment report PDF.
"""

import html
import random
import string
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import CondPageBreak, HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer

from analysis.result_aggregator import Finding
from report.report_builder import ReportData
from utils.logger import get_logger

logger = get_logger("report.pdf")

PAGE_WIDTH, PAGE_HEIGHT = A4


class PDFGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.styles = self._build_styles()

    def generate(self, report: ReportData) -> Path:
        target_safe = report.metadata.target.replace(".", "_").replace("/", "_")
        rand_chars = ''.join(random.choices(string.ascii_uppercase + string.digits, k=3))
        filename = f"{rand_chars}_{target_safe}.pdf"
        out_path = self.output_dir / filename

        doc = SimpleDocTemplate(
            str(out_path),
            pagesize=A4,
            leftMargin=2.2 * cm,
            rightMargin=2.2 * cm,
            topMargin=2.2 * cm,
            bottomMargin=2.0 * cm,
            title=f"ScanBot Report - {report.metadata.target}",
            author="ScanBot",
            subject="Automated Scan Report",
            creator="ScanBot",
        )

        story = self._build_story(report)
        doc.build(story, onFirstPage=self._draw_first_page, onLaterPages=self._draw_page)

        size_kb = out_path.stat().st_size // 1024
        logger.info(f"PDF generated: {out_path} ({size_kb} KB)")
        return out_path

    def _draw_first_page(self, canvas: Canvas, doc) -> None:
        self._draw_page(canvas, doc, include_header=False)

    def _draw_page(self, canvas: Canvas, doc, include_header: bool = True) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#BDBDBD"))
        if include_header:
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#444444"))
            canvas.drawString(doc.leftMargin, PAGE_HEIGHT - 1.2 * cm, "Security Assessment Report")
            canvas.drawRightString(
                PAGE_WIDTH - doc.rightMargin,
                PAGE_HEIGHT - 1.2 * cm,
                getattr(doc, "title", ""),
            )
            canvas.line(doc.leftMargin, PAGE_HEIGHT - 1.35 * cm, PAGE_WIDTH - doc.rightMargin, PAGE_HEIGHT - 1.35 * cm)

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.line(doc.leftMargin, 1.2 * cm, PAGE_WIDTH - doc.rightMargin, 1.2 * cm)
        canvas.drawString(doc.leftMargin, 0.8 * cm, "ScanBot")
        canvas.drawRightString(PAGE_WIDTH - doc.rightMargin, 0.8 * cm, f"Page {doc.page}")
        canvas.restoreState()

    def _build_story(self, report: ReportData) -> list:
        story: list = []
        story.extend(self._cover(report))
        story.extend(self._section_executive_summary(report))
        story.extend(self._section_scope(report))
        story.extend(self._section_attack_surface(report))
        story.extend(self._section_network_exposure(report))
        story.extend(self._section_web_observations(report))
        story.extend(self._section_tls(report))
        story.extend(self._section_realistic_risk(report))
        story.extend(self._section_attack_paths(report))
        story.extend(self._section_findings(report))
        story.extend(self._section_remediation(report))
        story.extend(self._section_conclusion(report))
        story.extend(self._section_appendix(report))
        story.extend(self._section_ai_attribution(report))
        story.extend(self._section_initial_recommendations(report))
        return story

    def _cover(self, report: ReportData) -> list:
        story = [
            Spacer(1, 2.2 * cm),
            Paragraph("ScanBot Report", self.styles["title"]),
            Spacer(1, 0.2 * cm),
            Paragraph(self._escape(report.metadata.target), self.styles["subtitle"]),
            Spacer(1, 0.8 * cm),
            Paragraph(
                "This report summarizes externally observable exposure, detected weaknesses, and practical remediation priorities. "
                "It avoids numerical risk scoring and focuses on realistic attacker value and evidence quality.",
                self.styles["lead"],
            ),
            Spacer(1, 0.8 * cm),
        ]
        story.extend(self._kv_list([
            ("Assessment Date", report.metadata.generated_at.split(" ")[0]),
            ("Target", report.metadata.target),
            ("Target Type", report.metadata.target_type.title()),
            ("Scan Duration", report.metadata.scan_duration),
            ("Validated Findings", str(report.metadata.total_findings)),
            ("Observed Indicators", str(report.metadata.observed_findings)),
            ("Excluded Observations", str(report.metadata.excluded_findings)),
            ("Version", report.metadata.version),
            ("Classification", "CONFIDENTIAL"),
        ]))
        story.extend([
            Spacer(1, 0.8 * cm),
            Paragraph(
                "Important: automated findings should be validated before being treated as confirmed compromise paths. "
                "Informational detections and heuristic matches are included for engineering follow-up, not as proof of exploitation.",
                self.styles["small"],
            ),
            PageBreak(),
        ])
        return story

    def _section_executive_summary(self, report: ReportData) -> list:
        story = self._section_header("1. Executive Summary")
        story.extend(self._kv_list([
            ("Assessment Date", report.metadata.generated_at.split(" ")[0]),
            ("Target", report.metadata.target),
            ("Duration", report.metadata.scan_duration),
            ("Validated Findings", str(report.metadata.total_findings)),
            ("Observed Indicators", str(report.metadata.observed_findings)),
            ("Excluded Observations", str(report.metadata.excluded_findings)),
        ]))
        story.append(Spacer(1, 0.3 * cm))
        story.extend(self._prose(report.analysis.executive_summary))
        return story

    def _section_scope(self, report: ReportData) -> list:
        result = report.result
        story = self._section_header("2. Scope and Coverage")
        scope_text = getattr(report.analysis, "scope_and_coverage", "")
        if scope_text:
            story.extend(self._prose(scope_text))
        else:
            methodology = (
                f"The assessment covered the externally reachable surface of {report.metadata.target}. "
                "The workflow included subdomain discovery, DNS resolution, origin detection, port scanning, service fingerprinting, "
                "HTTP probing, technology fingerprinting, vulnerability checks, TLS inspection, result normalization, and AI-assisted report writing. "
                "All actions were non-destructive and designed for reconnaissance, validation, and prioritization rather than active exploitation."
            )
            story.extend(self._prose(methodology))

        limitations = []
        for item in result.limitations[:12]:
            limitations.append(item)
        if result.cdn_detected and not result.origin_candidates:
            limitations.append("CDN or WAF protection reduced direct visibility into origin infrastructure.")
        for error in result.tool_errors[:10]:
            limitations.append(error)

        story.extend(self._section_subheader("Observed Limitations"))
        if limitations:
            story.extend(self._bullet_list(limitations))
        else:
            story.extend(self._bullet_list(["No major tool limitation was recorded for this scan."]))
        return story

    def _section_attack_surface(self, report: ReportData) -> list:
        result = report.result
        story = self._section_header("3. Attack Surface Overview")
        story.extend(self._kv_list(list(report.asset_stats.items())))

        if result.subdomains:
            story.extend(self._section_subheader("Discovered Hosts"))
            story.extend(self._tool_label("Subfinder, Assetfinder"))
            story.extend(self._bullet_list(result.subdomains[:30]))

        if result.resolved_ips:
            story.extend(self._section_subheader("Resolved IP Addresses"))
            story.extend(self._tool_label("dnsx"))
            story.extend(self._bullet_list(result.resolved_ips[:20]))

        if result.origin_candidates:
            story.extend(self._section_subheader("Origin Candidates"))
            story.extend(self._tool_label("Cloudflair"))
            story.extend(self._bullet_list(result.origin_candidates[:10]))

        if result.discovered_urls:
            story.extend(self._section_subheader("Prioritized Discovered URLs"))
            story.extend(self._tool_label("Katana, Gau"))
            story.extend(self._bullet_list(result.discovered_urls[:20]))

        story.extend(self._section_subheader("Assessment Notes"))
        story.extend(self._prose(report.analysis.attack_surface))
        return story

    def _section_network_exposure(self, report: ReportData) -> list:
        result = report.result
        story = self._section_header("4. Network Exposure")

        if result.open_ports:
            story.extend(self._section_subheader("Open Ports and Services"))
            story.extend(self._tool_label("Naabu, Nmap"))
            items = []
            service_by_host_port = {
                (str(service.get("host", "")).strip(), service.get("port")): service
                for service in result.services
                if service.get("port") is not None
            }
            for port in result.open_ports[:40]:
                service = service_by_host_port.get((str(port.host).strip(), port.port), {})
                service_name = port.service_name or service.get("service") or "unknown"
                version = port.version or service.get("version") or ""
                detail = f"{port.host}:{port.port} - {service_name}"
                if version:
                    detail += f" ({version})"
                items.append(detail)
            story.extend(self._bullet_list(items))

        high_value_ports = [
            port for port in result.dangerous_ports
            if port.risk_level in {"critical", "high"}
        ]
        if high_value_ports:
            story.extend(self._section_subheader("Administrative or High-Value Exposure"))
            story.extend(self._tool_label("PentestBot Risk Engine"))
            story.extend(self._bullet_list([
                f"Port {port.port} / {port.service_name or 'unknown'} - {port.risk_note}"
                for port in high_value_ports[:20]
            ]))

        story.extend(self._section_subheader("Assessment Notes"))
        story.extend(self._prose(report.analysis.network_exposure))
        return story

    def _section_web_observations(self, report: ReportData) -> list:
        result = report.result
        story = self._section_header("5. Web and Application Observations")

        if result.live_hosts:
            story.extend(self._section_subheader("Live Web Endpoints"))
            story.extend(self._tool_label("httpx"))
            endpoint_items = []
            for host in result.live_hosts[:20]:
                endpoint = host.get("url", "")
                status = host.get("status_code")
                title = host.get("title") or ""
                tech = ", ".join((host.get("technologies") or [])[:4])
                parts = [endpoint]
                if status:
                    parts.append(f"status {status}")
                if title:
                    parts.append(f"title {title}")
                if tech:
                    parts.append(f"tech {tech}")
                endpoint_items.append(" | ".join(parts))
            story.extend(self._bullet_list(endpoint_items))

        if result.technologies:
            story.extend(self._section_subheader("Detected Technologies"))
            story.extend(self._tool_label("WhatWeb, Wafw00f, Webanalyze"))
            story.extend(self._bullet_list(result.technologies[:20]))

        if result.web_servers:
            story.extend(self._section_subheader("Observed Web Servers"))
            story.extend(self._tool_label("httpx"))
            story.extend(self._bullet_list(result.web_servers[:10]))

        story.extend(self._section_subheader("Vulnerability Review"))
        story.extend(self._prose(report.analysis.vulnerability_analysis))
        return story

    def _section_tls(self, report: ReportData) -> list:
        result = report.result
        story = self._section_header("6. TLS and Transport Security")

        if result.cert_info:
            story.extend(self._section_subheader("Certificate Information"))
            story.extend(self._tool_label("testssl.sh"))
            cert_rows = [(key.replace("_", " ").title(), value) for key, value in result.cert_info.items() if value]
            story.extend(self._kv_list(cert_rows))

        if result.tls_findings:
            story.extend(self._section_subheader("Observed TLS Findings"))
            story.extend(self._tool_label("testssl.sh"))
            story.extend(self._bullet_list([
                f"{finding.get('id', 'tls')} - {finding.get('description', '')}"
                for finding in result.tls_findings[:20]
                if finding.get("description")
            ]))

        story.extend(self._section_subheader("Assessment Notes"))
        story.extend(self._prose(report.analysis.tls_analysis))
        return story

    def _section_realistic_risk(self, report: ReportData) -> list:
        story = self._section_header("7. Realistic Risk Summary")
        story.extend(self._prose(report.analysis.realistic_risk_summary))
        return story

    def _section_attack_paths(self, report: ReportData) -> list:
        story = self._section_header("8. Attack Path Simulation")
        story.extend(self._prose(report.analysis.attack_path_simulation))
        return story

    def _section_findings(self, report: ReportData) -> list:
        story = self._section_header("9. Findings Detail")
        if not report.result.findings:
            story.extend(self._prose(
                f"No validated, reportable findings were carried into the final report. "
                f"{report.metadata.excluded_findings} lower-signal observation(s) were excluded from the main findings section. "
                "This does not prove the absence of weaknesses; it means the scan produced observations, but none met the current validation/reporting threshold."
            ))
            story.append(PageBreak())
            return story

        for index, finding in enumerate(report.result.findings, start=1):
            story.extend(self._finding_block(index, finding))
        return story

    def _section_remediation(self, report: ReportData) -> list:
        story = self._section_header("10. Remediation Priorities")
        story.extend(self._prose(report.analysis.remediation_plan))

        top_actions = []
        for finding in report.result.findings[:10]:
            priority = self._finding_priority(finding)
            top_actions.append(f"{priority}: {finding.title}")
        if top_actions:
            story.extend(self._section_subheader("Top Follow-Up Actions"))
            story.extend(self._bullet_list(top_actions))

        return story

    def _section_conclusion(self, report: ReportData) -> list:
        story = self._section_header("11. Conclusion")
        story.extend(self._prose(report.analysis.conclusion))
        return story

    def _section_appendix(self, report: ReportData) -> list:
        result = report.result
        story = self._section_header("Appendix: Tool Status and Notes")
        story.extend(self._bullet_list([
            f"Validated findings: {report.metadata.total_findings}",
            f"Observed indicators: {report.metadata.observed_findings}",
            f"Excluded observations: {report.metadata.excluded_findings}",
            f"Subdomains discovered: {len(result.subdomains)}",
            f"Resolved IPs: {len(result.resolved_ips)}",
            f"Open ports: {len(result.open_ports)}",
            f"Services identified: {len(result.services)}",
            f"Live web endpoints: {len(result.live_hosts)}",
            f"TLS findings: {len(result.tls_findings)}",
            f"Reportable findings after filtering: {len(result.findings)}",
        ]))

        story.extend(self._section_subheader("Tool Warnings"))
        warnings = list(result.limitations[:20])
        warnings.extend(result.tool_errors[:20])
        if warnings:
            story.extend(self._bullet_list(warnings[:20]))
        else:
            story.extend(self._bullet_list(["No tool warnings were recorded in the final result."]))
        return story

    def _section_initial_recommendations(self, report: ReportData) -> list:
        """AI-generated security recommendations derived from scan data."""
        story = [PageBreak()]
        story.extend(self._section_header("Note: Initial Security Recommendations for Developers"))
        story.extend(self._prose(report.analysis.initial_recommendations))
        return story

    def _section_ai_attribution(self, report: ReportData) -> list:
        """AI Analysis Attribution — records which engine generated each section."""
        ENGINE_LABELS = {
            "PRO-GEMINI":     "Gemini 1.5 Pro (Primary Engine)",
            "GROQ-BACKUP":    "Groq LLaMA-3.3-70B (Backup Engine)",
            "STATIC-FALLBACK": "Static Fallback (API Unavailable)",
        }
        SECTION_NAMES = {
            "executive_summary":      "Executive Summary",
            "scope_and_coverage":     "Scope and Coverage",
            "attack_surface":         "Attack Surface Overview",
            "vulnerability_analysis": "Vulnerability Review",
            "network_exposure":       "Network Exposure",
            "tls_analysis":           "TLS and Transport Security",
            "realistic_risk_summary": "Realistic Risk Summary",
            "attack_path_simulation": "Attack Path Simulation",
            "remediation_plan":       "Remediation Priorities",
            "conclusion":             "Conclusion",
            "initial_recommendations":"Initial Security Recommendations",
        }

        story = self._section_header("Appendix: AI Analysis Attribution")
        overall_label = ENGINE_LABELS.get(
            report.ai_engine_label,
            report.ai_engine_label or "Unknown",
        )
        story.extend(self._prose(
            f"This report's narrative sections were generated by the ScanBot AI analysis "
            f"pipeline. The primary engine is Google Gemini 1.5 Pro; Groq LLaMA-3.3-70B "
            f"serves as the backup engine in the event of rate-limiting or API exhaustion. "
            f"Overall attribution for this report: {overall_label}."
        ))
        story.append(Spacer(1, 0.15 * cm))

        attribution = report.ai_attribution
        if attribution:
            story.extend(self._section_subheader("Per-Section Attribution"))
            rows = []
            for key, engine_code in attribution.items():
                section_name = SECTION_NAMES.get(key, key.replace("_", " ").title())
                engine_name  = ENGINE_LABELS.get(engine_code, engine_code)
                rows.append((section_name, engine_name))
            story.extend(self._kv_list(rows))
        else:
            story.extend(self._prose(
                f"Detailed per-section attribution was not recorded for this scan. "
                f"Overall engine: {overall_label}."
            ))
        return story

    def _finding_block(self, index: int, finding: Finding) -> list:
        story = [
            Paragraph(f"{index}. {self._escape(finding.title)}", self.styles["finding_title"]),
            Spacer(1, 0.1 * cm),
        ]
        story.extend(self._tool_label(finding.source or "Heuristic Analysis"))
        
        lines = [
            ("Evidence Status", self._finding_evidence_status(finding)),
            ("Exploitability", self._finding_exploitability(finding)),
            ("Impact", self._finding_impact(finding)),
            ("Priority", self._finding_priority(finding)),
            ("Description", finding.description or "No description provided."),
            ("Affected", ", ".join(finding.affected) if finding.affected else "Not specified."),
            ("Source", finding.source or "Unknown"),
        ]

        if finding.remediation:
            lines.append(("Remediation", finding.remediation))
        if finding.references:
            lines.append(("References", " | ".join(finding.references[:3])))
        if finding.cve_ids:
            lines.append(("Associated Identifiers", ", ".join(finding.cve_ids[:5])))

        story.extend(self._kv_list(lines, style_name="finding_item"))
        story.extend([
            Spacer(1, 0.15 * cm),
            HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#CFCFCF")),
            Spacer(1, 0.25 * cm),
        ])
        return story

    def _finding_evidence_status(self, finding: Finding) -> str:
        if getattr(finding, "evidence_status", ""):
            return finding.evidence_status
        text = self._finding_text(finding)
        if any(word in text for word in ["possible", "potential", "suspected", "may indicate", "appears to"]):
            return "Potential issue"
        return "Confirmed condition"

    def _finding_exploitability(self, finding: Finding) -> str:
        if getattr(finding, "exploitability", ""):
            return finding.exploitability
        text = self._finding_text(finding)
        if any(word in text for word in ["unauthenticated", "without credentials", "publicly readable", "open relay"]):
            return "Confirmed Exploitable"
        if any(word in text for word in [
            "remote code execution", "rce", "sql injection", "command injection", "auth bypass",
            "account takeover", "xss", "cross site scripting", "path traversal", "ssrf",
        ]):
            return "Likely Exploitable"
        if any(word in text for word in [
            "hsts", "csp", "header", "tls", "ssl", "cipher", "certificate", "dns", "soa",
            "clickjacking", "x-vercel-id", "server banner", "missing header",
        ]):
            return "Configuration Weakness"
        return "Theoretical / Low Practical Risk"

    def _finding_impact(self, finding: Finding) -> str:
        if getattr(finding, "impact", ""):
            return finding.impact
        text = self._finding_text(finding)
        if any(word in text for word in ["clickjacking", "xss", "cross site scripting", "frame-ancestors"]):
            return "Client-Side Attack (XSS, Clickjacking)"
        if any(word in text for word in ["session", "cookie", "jwt", "login", "password", "token", "account", "authentication"]):
            return "Account Takeover"
        if any(word in text for word in ["privilege escalation", "sudo", "admin access", "root access"]):
            return "Privilege Escalation"
        if any(word in text for word in [
            "tls", "ssl", "cipher", "certificate", "hsts", "transport", "https",
        ]):
            return "Transport Security Weakness"
        if any(word in text for word in [
            "redis", "mongodb", "elasticsearch", "data exposure", "directory listing", "file disclosure",
            "private ip", "exposed service", "unauthenticated",
        ]):
            return "Critical Data Exposure"
        return "Informational"

    def _finding_priority(self, finding: Finding) -> str:
        if getattr(finding, "priority", ""):
            return finding.priority
        exploitability = self._finding_exploitability(finding)
        impact = self._finding_impact(finding)
        if exploitability == "Confirmed Exploitable":
            return "Immediate Fix (0-7 days)"
        if exploitability == "Likely Exploitable" and impact in {
            "Critical Data Exposure",
            "Account Takeover",
            "Privilege Escalation",
        }:
            return "Immediate Fix (0-7 days)"
        if exploitability == "Likely Exploitable" or finding.severity in {"critical", "high", "medium"}:
            return "Short-Term Fix (7-30 days)"
        return "Hardening / Best Practice"

    @staticmethod
    def _finding_text(finding: Finding) -> str:
        return " ".join([
            finding.title or "",
            finding.description or "",
            finding.source or "",
            " ".join(finding.tags or []),
            " ".join(finding.affected or []),
        ]).lower()

    def _tool_label(self, tool_name: str) -> list:
        return [
            Spacer(1, 0.1 * cm),
            Paragraph(f"<i>Tool: {self._escape(tool_name)}</i>", self.styles["small"]),
            Spacer(1, 0.05 * cm),
        ]

    def _section_header(self, title: str) -> list:
        return [
            CondPageBreak(6 * cm),
            Paragraph(self._escape(title), self.styles["h1"]),
            HRFlowable(width="100%", thickness=1.0, color=colors.HexColor("#5A5A5A")),
            Spacer(1, 0.25 * cm),
        ]

    def _section_subheader(self, title: str) -> list:
        return [Paragraph(self._escape(title), self.styles["h2"]), Spacer(1, 0.1 * cm)]

    def _prose(self, text: str) -> list:
        if not text or not text.strip():
            return [Paragraph("No narrative content available for this section.", self.styles["body"])]

        story = []
        for part in text.strip().split("\n\n"):
            cleaned = part.strip()
            if cleaned:
                story.append(Paragraph(self._escape(cleaned), self.styles["body"]))
                story.append(Spacer(1, 0.15 * cm))
        return story

    def _kv_list(self, rows: list[tuple[str, str]], style_name: str = "kv") -> list:
        story = []
        for key, value in rows:
            safe_value = self._escape(str(value).strip() or "N/A").replace("\n", "<br/>")
            story.append(
                Paragraph(
                    f"<b>{self._escape(str(key))}:</b> {safe_value}",
                    self.styles[style_name],
                )
            )
            story.append(Spacer(1, 0.08 * cm))
        return story

    def _bullet_list(self, items: list[str]) -> list:
        story = []
        for item in items:
            text = str(item).strip()
            if not text:
                continue
            story.append(Paragraph(f"&bull; {self._escape(text)}", self.styles["list"]))
            story.append(Spacer(1, 0.06 * cm))
        if not story:
            story.append(Paragraph("&bull; No data available.", self.styles["list"]))
        return story

    @staticmethod
    def _escape(value: str) -> str:
        return html.escape(value, quote=False)

    def _build_styles(self) -> dict:
        styles: dict[str, ParagraphStyle] = {}

        def add(name: str, **kwargs) -> None:
            styles[name] = ParagraphStyle(name, **kwargs)

        add(
            "title",
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=28,
            textColor=colors.black,
            alignment=TA_LEFT,
        )
        add(
            "subtitle",
            fontName="Helvetica",
            fontSize=13,
            leading=18,
            textColor=colors.HexColor("#333333"),
        )
        add(
            "lead",
            fontName="Helvetica",
            fontSize=10.5,
            leading=16,
            textColor=colors.black,
            alignment=TA_JUSTIFY,
        )
        add(
            "h1",
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.black,
            spaceBefore=4,
        )
        add(
            "h2",
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=14,
            textColor=colors.black,
            spaceBefore=6,
        )
        add(
            "body",
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.black,
            alignment=TA_JUSTIFY,
            wordWrap="CJK",
            splitLongWords=1,
        )
        add(
            "kv",
            fontName="Helvetica",
            fontSize=9.4,
            leading=13.5,
            textColor=colors.black,
            alignment=TA_LEFT,
            wordWrap="CJK",
            splitLongWords=1,
        )
        add(
            "finding_item",
            fontName="Helvetica",
            fontSize=9.1,
            leading=13.2,
            textColor=colors.black,
            alignment=TA_LEFT,
            wordWrap="CJK",
            splitLongWords=1,
        )
        add(
            "list",
            fontName="Helvetica",
            fontSize=9.3,
            leading=13.2,
            textColor=colors.black,
            alignment=TA_LEFT,
            wordWrap="CJK",
            splitLongWords=1,
        )
        add(
            "finding_title",
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=14,
            textColor=colors.black,
            alignment=TA_LEFT,
            wordWrap="CJK",
            splitLongWords=1,
        )
        add(
            "small",
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#555555"),
            alignment=TA_LEFT,
            wordWrap="CJK",
            splitLongWords=1,
        )
        add(
            "footer",
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#666666"),
            alignment=TA_RIGHT,
        )
        add(
            "center",
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.black,
            alignment=TA_CENTER,
        )
        return styles

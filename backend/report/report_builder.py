"""
ScanBot — Report Builder
Assembles all scan data and AI analysis into a single
ReportData object consumed by the PDF generator.
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from analysis.result_aggregator import AggregatedResult, Finding
from analysis.groq_ai import AIAnalysis
from config import Config
from core.job_manager import ScanJob


@dataclass
class ReportMetadata:
    scan_id:          str
    target:           str
    target_type:      str
    generated_at:     str
    scan_started:     str
    scan_completed:   str
    scan_duration:    str
    risk_level:       str
    risk_score:       float
    total_findings:   int
    observed_findings:int
    excluded_findings:int
    severity_summary: dict
    version:          str


@dataclass
class ReportData:
    """Complete, render-ready data package for the PDF generator."""
    metadata:    ReportMetadata
    result:      AggregatedResult
    analysis:    AIAnalysis

    # Pre-computed sections for quick access
    critical_findings: list[Finding]  = field(default_factory=list)
    high_findings:     list[Finding]  = field(default_factory=list)
    medium_findings:   list[Finding]  = field(default_factory=list)
    low_findings:      list[Finding]  = field(default_factory=list)
    info_findings:     list[Finding]  = field(default_factory=list)

    # Statistics
    asset_stats: dict  = field(default_factory=dict)
    scan_stages: list  = field(default_factory=list)

    # AI Attribution
    ai_engine_label: str  = "GROQ-BACKUP"
    ai_attribution:  dict = field(default_factory=dict)


class ReportBuilder:
    """
    Constructs a ReportData object from scan artifacts.
    Validates data completeness and computes display-ready statistics.
    """

    def __init__(self, config: Config):
        self.config = config

    def build(
        self,
        job: ScanJob,
        result: AggregatedResult,
        analysis: AIAnalysis,
    ) -> ReportData:

        metadata = ReportMetadata(
            scan_id          = job.scan_id,
            target           = job.target,
            target_type      = result.target_type,
            generated_at     = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            scan_started     = job.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                               if job.started_at else "N/A",
            scan_completed   = job.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                               if job.completed_at else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            scan_duration    = job.duration_str(),
            risk_level       = result.risk_level,
            risk_score       = result.risk_score,
            total_findings   = result.total_findings,
            observed_findings= result.observed_findings_count,
            excluded_findings= result.excluded_findings_count,
            severity_summary = result.severity_summary,
            version          = self.config.version,
        )

        # Partition findings by severity
        by_severity: dict[str, list[Finding]] = {}
        for f in result.findings:
            by_severity.setdefault(f.severity, []).append(f)

        # Asset statistics
        asset_stats = {
            "Validated Findings":      result.total_findings,
            "Observed Indicators":     result.observed_findings_count,
            "Excluded Observations":   result.excluded_findings_count,
            "Subdomains Discovered":   len(result.subdomains),
            "Resolved IP Addresses":   len(result.resolved_ips),
            "Live Web Endpoints":       len(result.live_hosts),
            "Discovered URLs":          len(result.discovered_urls),
            "Open Ports":               len(result.open_ports),
            "Dangerous Ports":          len([p for p in result.dangerous_ports if p.risk_level in {"critical", "high"}]),
            "Identified Services":      len(result.services),
            "Detected Technologies":    len(result.technologies),
            "TLS Issues":               len(result.tls_findings),
            "CDN / WAF Detected":       "Yes" if result.cdn_detected else "No",
            "Origin IPs Identified":    len(result.origin_candidates),
        }

        return ReportData(
            metadata          = metadata,
            result            = result,
            analysis          = analysis,
            critical_findings = by_severity.get("critical", []),
            high_findings     = by_severity.get("high", []),
            medium_findings   = by_severity.get("medium", []),
            low_findings      = by_severity.get("low", []),
            info_findings     = by_severity.get("info", []),
            asset_stats       = asset_stats,
            ai_engine_label   = getattr(analysis, "engine_used", "GROQ-BACKUP"),
            ai_attribution    = getattr(analysis, "engine_attribution", {}),
        )

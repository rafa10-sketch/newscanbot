"""
PentestBot v2 — Job Manager
Central coordinator: validates targets, creates scan jobs,
drives the pipeline, and persists all state.
"""

import asyncio
import hashlib
import ipaddress
import json
import random
import re
import socket
import string
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from config import Config
from core.database import Database
from core.queue_manager import QueueManager
from scan_profiles import ScanMode, apply_profile
from utils.logger import get_logger, ScanLogger

logger = get_logger("core.job_manager")


class JobState(str, Enum):
    QUEUED     = "queued"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"
    CANCELLED  = "cancelled"


ProgressCallback = Callable[[str, str, str], None]  # (scan_id, stage, message)


@dataclass
class ScanJob:
    scan_id: str
    user_id: int
    target: str
    scan_mode: str           = "fast"
    state: JobState          = JobState.QUEUED
    created_at: datetime     = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_stage: str       = "Queued"
    error: Optional[str]     = None
    pdf_path: Optional[Path] = None

    def duration_seconds(self) -> float:
        if not self.started_at:
            return 0.0
        end = self.completed_at or datetime.utcnow()
        return (end - self.started_at).total_seconds()

    def duration_str(self) -> str:
        secs = int(self.duration_seconds())
        m, s = divmod(secs, 60)
        h, m = divmod(m, 60)
        if h:
            return f"{h}h {m}m {s}s"
        if m:
            return f"{m}m {s}s"
        return f"{s}s"


# ── Target Validation ─────────────────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

_BLOCKED_HOSTS = frozenset([
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
])
_BLOCKED_TLDS = frozenset([".gov", ".mil"])


def _sanitize(raw: str) -> str:
    t = raw.strip().lower()
    t = re.sub(r"^https?://", "", t, flags=re.I)
    t = t.rstrip("/").split("/")[0]
    return t


def _is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def validate_target(raw: str) -> tuple[bool, str, str]:
    """
    Validate a raw target string.
    Returns (is_valid, cleaned_target, error_message).
    """
    cleaned = _sanitize(raw)

    if not cleaned:
        return False, "", "Empty target."

    if cleaned in _BLOCKED_HOSTS:
        return False, cleaned, "Localhost/loopback targets are not permitted."

    for tld in _BLOCKED_TLDS:
        if cleaned.endswith(tld):
            return False, cleaned, f"Scanning '{tld}' domains is not permitted."

    # IP target
    if _IP_RE.match(cleaned):
        try:
            ipaddress.ip_address(cleaned)
        except ValueError:
            return False, cleaned, f"'{cleaned}' is not a valid IP address."
        if _is_private_ip(cleaned):
            return False, cleaned, "Private/RFC1918 IP addresses are not permitted."
        return True, cleaned, ""

    # Domain target
    if _DOMAIN_RE.match(cleaned):
        try:
            ips = socket.gethostbyname_ex(cleaned)[2]
            for ip in ips:
                if _is_private_ip(ip):
                    return False, cleaned, f"Domain resolves to private IP: {ip}"
        except socket.gaierror:
            pass  # Can't resolve yet — still valid target
        return True, cleaned, ""

    return False, cleaned, f"'{cleaned}' is not a valid domain or IP address."


def make_scan_id(target: str) -> str:
    ts = str(time.time()).encode()
    h = hashlib.sha256(target.encode() + ts).hexdigest()[:12]
    return h


# ── Job Manager ───────────────────────────────────────────────────────────────

class JobManager:
    """
    Manages the full lifecycle of scan jobs.

    submit()  → validates target → creates DB record → enqueues coroutine
    The coroutine drives the full 9-stage pipeline, saves results, generates
    PDF, and notifies the caller via progress callbacks.
    """

    def __init__(self, config: Config, database: Database, queue: QueueManager):
        self.config   = config
        self.db       = database
        self.queue    = queue
        self._jobs: dict[str, ScanJob] = {}

    async def start(self) -> None:
        await self.queue.start()

    async def stop(self) -> None:
        await self.queue.stop()

    # ── Public API ────────────────────────────────────────────────────────

    async def submit(
        self,
        user_id: int,
        raw_target: str,
        on_progress: Optional[ProgressCallback] = None,
        scan_mode: str = "fast",
    ) -> ScanJob:
        """
        Validate target and enqueue a scan.
        Raises ValueError on invalid target.
        Returns ScanJob immediately (may be queued).
        """
        valid, target, err = validate_target(raw_target)
        if not valid:
            raise ValueError(err)

        mode = ScanMode.from_str(scan_mode)
        scan_id = make_scan_id(target)
        job = ScanJob(scan_id=scan_id, user_id=user_id, target=target, scan_mode=mode.value)
        self._jobs[scan_id] = job

        await self.db.create_scan(scan_id, user_id, target, scan_mode=mode.value)
        await self.db.audit("scan_submitted", user_id=user_id, scan_id=scan_id, detail=f"{target} (mode={mode.value})")

        coro = self._execute(job, on_progress)
        await self.queue.enqueue(scan_id, coro)

        logger.info(f"Job {scan_id} submitted for target '{target}' by user {user_id} (mode={mode.value})")
        return job

    async def cancel(self, scan_id: str) -> bool:
        """Cancel a queued or running scan. Supports 'force cancel' for ghost scans."""
        cancelled = await self.queue.cancel(scan_id)
        
        # Even if not in active queue (e.g. after restart), if it's "running" in DB, force cancel it.
        if not cancelled:
            scan = await self.db.get_scan(scan_id)
            if scan and scan.get("state") in ("queued", "running"):
                await self.db.update_scan_state(scan_id, "cancelled")
                logger.info(f"Force-cancelled ghost scan {scan_id} in database.")
                return True
            return False

        # If it was in the queue, also update local job state
        job = self._jobs.get(scan_id)
        if job:
            job.state = JobState.CANCELLED
            job.completed_at = datetime.utcnow()
        
        await self.db.update_scan_state(scan_id, "cancelled")
        return True

    def get_job(self, scan_id: str) -> Optional[ScanJob]:
        return self._jobs.get(scan_id)

    def active_job_for_user(self, user_id: int) -> Optional[ScanJob]:
        for job in self._jobs.values():
            if job.user_id == user_id and job.state in (
                JobState.QUEUED, JobState.RUNNING
            ):
                return job
        return None

    # ── Pipeline Execution ────────────────────────────────────────────────

    async def _execute(
        self,
        job: ScanJob,
        on_progress: Optional[ProgressCallback],
    ) -> None:
        """
        Drives the complete multi-stage scan pipeline for one job.
        Handles all errors gracefully and persists state at each step.
        """
        import asyncio
        from pipeline.recon      import ReconStage
        from pipeline.resolver   import ResolverStage
        from pipeline.originip   import OriginIPStage
        from pipeline.portscan   import PortScanStage
        from pipeline.service_scan import ServiceScanStage
        from pipeline.http_probe import HttpProbeStage
        from pipeline.fingerprint import FingerprintStage
        from pipeline.web_discovery import WebDiscoveryStage
        from pipeline.vuln_scan  import VulnScanStage
        from pipeline.tls_scan   import TLSScanStage
        from pipeline.git_exposure import GitExposureStage
        from analysis.result_aggregator import ResultAggregator
        from analysis.normalizer        import Normalizer
        from analysis.groq_ai           import GroqAI
        from report.report_builder      import ReportBuilder
        from report.pdf_generator       import PDFGenerator

        job.state      = JobState.RUNNING
        job.started_at = datetime.utcnow()
        await self.db.update_scan_state(job.scan_id, "running")

        # Pre-populate all stages as queued so the UI shows them immediately
        all_stages = [
            "Recon", "Resolver", "OriginIP", "PortScan", "ServiceScan",
            "HTTPProbe", "Fingerprint", "WebDiscovery", "TLSScan",
            "VulnScan", "GitExposure", "Aggregation", "AIAnalysis", "Report"
        ]
        for stage in all_stages:
            await self.db.upsert_stage(job.scan_id, stage, "queued")

        scan_log = ScanLogger(
            scan_id=job.scan_id,
            log_dir=self.config.log_dir,
        )

        # Per-scan working directory for temp files
        work_dir = self.config.work_dir / job.scan_id
        work_dir.mkdir(parents=True, exist_ok=True)

        async def notify(stage: str, msg: str) -> None:
            job.current_stage = stage
            scan_log.info(f"[{stage}] {msg}")
            await self.db.upsert_stage(job.scan_id, stage, "running")
            if on_progress:
                try:
                    if asyncio.iscoroutinefunction(on_progress):
                        await on_progress(job.scan_id, stage, msg)
                    else:
                        on_progress(job.scan_id, stage, msg)
                except Exception as e:
                    scan_log.warning(f"Progress callback error: {e}")

        async def complete_stage(stage: str, size: int = 0) -> None:
            await self.db.upsert_stage(job.scan_id, stage, "completed", result_size=size)

        async def fail_stage(stage: str, error: str) -> None:
            await self.db.upsert_stage(job.scan_id, stage, "failed", error=error)

        async def finalize_stage(stage: str, size: int = 0) -> None:
            stage_error = ctx.get("stage_errors", {}).get(stage)
            if stage_error:
                await fail_stage(stage, stage_error)
            else:
                await complete_stage(stage, size)

        # Apply scan profile overrides based on mode
        mode = ScanMode.from_str(job.scan_mode)
        profiled_config = apply_profile(self.config.scan, mode)

        # Shared context dict passed between all pipeline stages
        ctx: dict = {
            "scan_id":      job.scan_id,
            "target":       job.target,
            "work_dir":     work_dir,
            "config":       profiled_config,
            "scan_mode":    mode.value,
            "logger":       scan_log,
            "scan_started": job.started_at.isoformat(),
            "tool_errors":  [],
            "limitations":  [],
            "stage_errors": {},
        }

        try:
            # ── Stage 1: Recon — Subdomain Discovery ─────────────────────
            await notify("Recon", f"Discovering subdomains for {job.target}...")
            recon = ReconStage(ctx)
            recon_timeout = max(
                profiled_config.subfinder_timeout,
                profiled_config.assetfinder_timeout,
                profiled_config.amass_timeout if profiled_config.enable_amass else 0
            ) + 60
            await asyncio.wait_for(recon.run(), timeout=recon_timeout)
            await finalize_stage("Recon", len(ctx.get("subdomains", [])))

            # ── Stage 2: Resolver — DNS Resolution ───────────────────────
            await notify("Resolver", f"Resolving {len(ctx.get('subdomains', []))} hosts...")
            resolver = ResolverStage(ctx)
            await asyncio.wait_for(resolver.run(), timeout=120)
            await finalize_stage("Resolver", len(ctx.get("resolved_hosts", {})))

            # ── Stage 3: Origin IP ────────────────────────────────────────
            await notify("OriginIP", "Detecting origin IPs / CDN bypass...")
            originip = OriginIPStage(ctx)
            await asyncio.wait_for(originip.run(), timeout=90)
            await finalize_stage("OriginIP")

            portscan_done = asyncio.Event()

            # ── Split Pipeline: Infrastructure vs Web ─────────────────────
            async def run_infra_pipeline():
                # ── Stage 4: Port Scanning
                host_count = len(ctx.get("live_ips", [ctx["target"]]))
                await notify("PortScan", f"Scanning ports on {host_count} hosts...")
                portscan = PortScanStage(ctx)
                await asyncio.wait_for(portscan.run(), timeout=profiled_config.naabu_timeout)
                await finalize_stage("PortScan", len(ctx.get("open_ports", [])))
                
                # Signal that PortScan is done so Web pipeline can start
                portscan_done.set()

                # ── Stage 5: Service Detection
                port_count = len(ctx.get("open_ports", []))
                await notify("ServiceScan", f"Detecting services on {port_count} open ports...")
                service_scan = ServiceScanStage(ctx)
                await asyncio.wait_for(service_scan.run(), timeout=profiled_config.nmap_timeout)
                await finalize_stage("ServiceScan", len(ctx.get("services", [])))

            async def run_web_pipeline():
                # Wait for PortScan to find open ports before probing
                await portscan_done.wait()
                
                # ── Stage 6: HTTP Probing
                await notify("HTTPProbe", "Probing HTTP/HTTPS endpoints...")
                http_probe = HttpProbeStage(ctx)
                http_probe_timeout = max(
                    profiled_config.httpx_timeout * 20 + 30,
                    profiled_config.stage_timeout,
                )
                await asyncio.wait_for(http_probe.run(), timeout=http_probe_timeout)
                await finalize_stage("HTTPProbe", len(ctx.get("live_hosts", [])))

                # ── Concurrent Web Stages (7, 8, 10) ──────────────────────
                async def run_fingerprint():
                    await notify("Fingerprint", "Running fingerprinting (WhatWeb, Wafw00f, Webanalyze)...")
                    fingerprint = FingerprintStage(ctx)
                    await asyncio.wait_for(fingerprint.run(), timeout=profiled_config.stage_timeout)
                    await finalize_stage("Fingerprint", len(ctx.get("fingerprint_technologies", [])))

                async def run_web_discovery():
                    await notify("WebDiscovery", "Expanding web attack surface from live endpoints...")
                    web_discovery = WebDiscoveryStage(ctx)
                    web_discovery_timeout = max(
                        profiled_config.katana_timeout + profiled_config.gau_timeout + 30,
                        profiled_config.stage_timeout,
                    )
                    await asyncio.wait_for(web_discovery.run(), timeout=web_discovery_timeout)
                    await finalize_stage("WebDiscovery", len(ctx.get("discovered_urls", [])))

                async def run_tls_scan():
                    await notify("TLSScan", f"Analyzing TLS configuration for {job.target}...")
                    tls_scan = TLSScanStage(ctx)
                    try:
                        await asyncio.wait_for(tls_scan.run(), timeout=profiled_config.testssl_timeout)
                    except asyncio.TimeoutError:
                        scan_log.warning(
                            "[TLSScan] Stage exceeded %ss timeout; continuing with degraded TLS coverage.",
                            profiled_config.testssl_timeout,
                        )
                        await tls_scan.handle_timeout()
                    await finalize_stage("TLSScan")

                # Execute Fingerprint, Web Discovery, and TLS Scan concurrently
                await asyncio.gather(
                    run_fingerprint(),
                    run_web_discovery(),
                    run_tls_scan(),
                )

                # ── Stage 9: Vulnerability Scanning (Depends on 6, 7, 8) ───
                live_count = len(ctx.get("live_hosts", []))
                await notify("VulnScan", f"Running vuln scan on {live_count} endpoints...")
                vuln_scan = VulnScanStage(ctx)
                await asyncio.wait_for(vuln_scan.run(), timeout=profiled_config.nuclei_timeout + profiled_config.nikto_timeout)
                await finalize_stage("VulnScan", ctx.get("nuclei_findings_count", 0))

            # Execute Infrastructure and Web pipelines concurrently
            await notify("System", "Starting parallel execution: Infrastructure and Web Analysis pipelines...")
            await asyncio.gather(
                run_infra_pipeline(),
                run_web_pipeline(),
            )
            
            # ── Stage 11: Git Exposure (Custom Script) ────────────────────
            await notify("GitExposure", f"Checking for Git exposure using custom script...")
            git_exposure = GitExposureStage(ctx)
            await asyncio.wait_for(git_exposure.run(), timeout=300)
            await finalize_stage("GitExposure", len(ctx.get("git_exposure_findings", [])))

            await finalize_stage("System")

            # ── Persist raw tool outputs ──────────────────────────────────
            raw_data = []
            for raw_entry in ctx.get("raw_outputs", []):
                raw_data.append(raw_entry)
                await self.db.save_raw_output(
                    scan_id=job.scan_id,
                    tool_name=raw_entry.get("tool_name", "unknown"),
                    stage_name=raw_entry.get("stage_name", "unknown"),
                    status=raw_entry.get("status", "success"),
                    stdout=raw_entry.get("stdout", ""),
                    stderr=raw_entry.get("stderr", ""),
                    duration=raw_entry.get("duration", 0.0),
                )
            
            # Save Raw JSON file for Task 3
            if raw_data:
                try:
                    # Use the same unique name as the PDF
                    # Note: pdf_gen.generate hasn't run yet, so we need the logic here or wait
                    # Actually, let's create the filename here
                    prefix = "".join(random.choices(string.ascii_uppercase + string.digits, k=3))
                    raw_filename = f"{prefix}_{job.target.replace('.', '_')}.json"
                    raw_path = self.config.reports_dir / raw_filename
                    raw_path.write_text(json.dumps(raw_data, indent=2), encoding="utf-8")
                    ctx["raw_json_path"] = raw_path
                    scan_log.info(f"[System] Raw scan data preserved: {raw_filename}")
                except Exception as e:
                    scan_log.warning(f"[System] Failed to save raw JSON: {e}")

            # ── Stage 11: Aggregation + AI + Report ──────────────────────
            await notify("Aggregation", "Aggregating and normalizing all results...")
            ctx["scan_duration"] = job.duration_seconds()
            aggregator = ResultAggregator(ctx)
            aggregated = aggregator.aggregate()
            ctx["aggregated"] = aggregated

            normalizer = Normalizer(scan_mode=ctx.get("scan_mode", "fast"))
            normalized = normalizer.normalize(aggregated)
            ctx["normalized"] = normalized

            await self.db.save_results(job.scan_id, normalized.to_dict())
            await finalize_stage("Aggregation", 1)

            await notify("AIAnalysis", "Running AI-powered security analysis...")
            ai = GroqAI(self.config.groq)
            try:
                analysis = await ai.analyze(normalized)
                # Enrich top findings with AI-rewritten descriptions
                try:
                    await ai.enrich_findings(normalized.findings)
                except Exception as enrich_err:
                    logger.warning(f"Finding enrichment failed (non-fatal): {enrich_err}")
                    ctx["tool_errors"].append(f"AIAnalysis: Finding enrichment failed: {enrich_err}")
            finally:
                await ai.close()
            ctx["analysis"] = analysis
            if analysis.error_sections:
                message = (
                    f"AI fallback used for {len(analysis.error_sections)} section(s): "
                    f"{', '.join(analysis.error_sections)}"
                )
                ctx["tool_errors"].append(f"AIAnalysis: {message}")
                if len(analysis.error_sections) == len(analysis.all_sections()):
                    ctx["stage_errors"]["AIAnalysis"] = message
            await finalize_stage("AIAnalysis")

            await notify("Report", "Generating professional PDF report...")
            builder = ReportBuilder(config=self.config)
            report_data = builder.build(job, normalized, analysis)

            pdf_gen = PDFGenerator(output_dir=self.config.reports_dir)
            pdf_path = pdf_gen.generate(report_data)
            ctx["pdf_path"] = pdf_path
            await finalize_stage("Report")

            # ── Finalize ──────────────────────────────────────────────────
            job.pdf_path    = pdf_path
            job.state       = JobState.COMPLETED
            job.completed_at = datetime.utcnow()

            summary = {
                "subdomains": len(ctx.get("subdomains", [])),
                "open_ports": len(ctx.get("open_ports", [])),
                "live_hosts": len(ctx.get("live_hosts", [])),
                "discovered_urls": len(ctx.get("discovered_urls", [])),
                "total_findings": normalized.total_findings,
                "observed_findings": normalized.observed_findings_count,
                "excluded_findings": normalized.excluded_findings_count,
                "risk_level": normalized.risk_level,
                "risk_score": normalized.risk_score,
                "duration": job.duration_str(),
                "tool_errors": len(ctx.get("tool_errors", [])),
            }
            await self.db.update_scan_state(
                job.scan_id, "completed",
                pdf_path=str(pdf_path),
                raw_path=str(ctx.get("raw_json_path", "")),
                summary=summary,
            )
            await self.db.audit(
                "scan_completed", user_id=job.user_id,
                scan_id=job.scan_id,
                detail=f"risk={normalized.risk_level}, findings={normalized.total_findings}",
            )
            await notify("Done", f"Scan complete in {job.duration_str()}. Report ready.")
            await complete_stage("Done")

        except asyncio.CancelledError:
            job.state = JobState.CANCELLED
            job.completed_at = datetime.utcnow()
            await self.db.update_scan_state(job.scan_id, "cancelled")
            scan_log.warning("Scan cancelled.")
            raise

        except Exception as e:
            tb = traceback.format_exc()
            job.state = JobState.FAILED
            job.error = str(e)
            job.completed_at = datetime.utcnow()
            await self.db.update_scan_state(job.scan_id, "failed", error=str(e))
            await self.db.audit(
                "scan_failed", user_id=job.user_id,
                scan_id=job.scan_id, detail=str(e)[:500],
            )
            scan_log.error(f"Scan failed: {e}\n{tb}")
            await notify("Error", f"Scan failed: {e}")

        finally:
            scan_log.close()
            # Clean up work directory
            import shutil
            shutil.rmtree(work_dir, ignore_errors=True)

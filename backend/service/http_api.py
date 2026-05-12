"""
PentestBot v2 — FastAPI HTTP API

Provides scan submission, status polling, log retrieval, and report download
for the web dashboard. Replaces the previous aiohttp-based API.
"""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from config import Config
from core.database import Database
from core.job_manager import JobManager
from utils.logger import get_logger

logger = get_logger("service.http_api")

STAGE_ORDER = [
    "Queued",
    "Recon",
    "Resolver",
    "OriginIP",
    "PortScan",
    "ServiceScan",
    "HTTPProbe",
    "Fingerprint",
    "WebDiscovery",
    "VulnScan",
    "GitExposure",
    "TLSScan",
    "Aggregation",
    "AIAnalysis",
    "Report",
    "Done",
]

STAGE_PROGRESS = {
    "Queued": 0,
    "Recon": 8,
    "Resolver": 15,
    "OriginIP": 22,
    "PortScan": 32,
    "ServiceScan": 42,
    "HTTPProbe": 52,
    "Fingerprint": 58,
    "WebDiscovery": 65,
    "VulnScan": 76,
    "GitExposure": 82,
    "TLSScan": 87,
    "Aggregation": 90,
    "AIAnalysis": 94,
    "Report": 98,
    "Done": 100,
    "Completed": 100,
    "Error": 99,
    "Failed": 99,
}

LOG_PATTERN = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+\[(?P<level>[^\]]+)\]\s+\[[^\]]+\]\s+"
    r"(?:(?:\[(?P<stage>[^\]]+)\])\s*)?(?P<message>.*)$"
)


# ── Request/Response models ──────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    scanMode: Optional[str] = "fast"
    userRef: Optional[str] = ""
    externalJobId: Optional[str] = ""


# ── Helpers ──────────────────────────────────────────────────────────────────

def _stable_dashboard_user_id(raw: str) -> int:
    if not raw:
        return 0
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
    return int(digest[:8], 16)


def _to_iso(ts: Any) -> str | None:
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    return str(ts)


def _summary_from_json(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except Exception:
        return None
    return value if isinstance(value, dict) else None


# ── App Factory ──────────────────────────────────────────────────────────────

def create_app(
    config: Config,
    database: Database,
    job_manager: JobManager,
) -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title="PentestBot API",
        version=config.version,
        description="Automated Penetration Testing Platform — No-Exploit Reconnaissance & Discovery",
        docs_url="/docs",
        redoc_url=None,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition"],
    )

    # Store references for route handlers
    app.state.config = config
    app.state.db = database
    app.state.job_manager = job_manager

    # ── Auth dependency ──────────────────────────────────────────────────

    async def verify_token(request: Request) -> None:
        expected = config.api.auth_token.strip()
        if not expected:
            return  # No token configured — open access

        auth_header = request.headers.get("Authorization", "")
        scheme, _, supplied = auth_header.partition(" ")
        if scheme.lower() != "bearer" or supplied.strip() != expected:
            raise HTTPException(status_code=401, detail="Unauthorized.")

    # ── Health ───────────────────────────────────────────────────────────

    @app.get("/health")
    async def health():
        return {
            "ok": True,
            "service": "pentestbot-api",
            "version": config.version,
            "mode": "api",
            "telegram": config.telegram.enabled,
            "queue": {
                "active": job_manager.queue.active_count,
                "depth": job_manager.queue.queue_depth,
            },
        }

    # ── Create Scan ──────────────────────────────────────────────────────

    @app.post("/api/scans", status_code=202, dependencies=[Depends(verify_token)])
    async def create_scan(body: ScanRequest):
        target = body.target.strip()
        user_ref = (body.userRef or "").strip()
        external_job_id = (body.externalJobId or "").strip()
        mapped_user_id = _stable_dashboard_user_id(
            user_ref or external_job_id or "dashboard"
        )

        try:
            scan_mode = (body.scanMode or "fast").strip().lower()
            job = await job_manager.submit(
                user_id=mapped_user_id,
                raw_target=target,
                scan_mode=scan_mode,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error))

        await database.audit(
            "dashboard_scan_submitted",
            user_id=mapped_user_id,
            scan_id=job.scan_id,
            detail=external_job_id or target,
        )

        return {
            "scanId": job.scan_id,
            "state": job.state.value,
            "target": job.target,
            "scanMode": job.scan_mode,
            "externalJobId": external_job_id or None,
        }

    # ── Get Scan Status ──────────────────────────────────────────────────

    @app.get("/api/scans/{scan_id}", dependencies=[Depends(verify_token)])
    async def get_scan(scan_id: str):
        scan = await database.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")

        stages = await database.get_scan_stages(scan_id)
        job = job_manager.get_job(scan_id)
        state = (
            getattr(job.state, "value", None)
            if job
            else str(scan.get("state", "queued"))
        )
        current_stage = _derive_current_stage(job, stages, state)
        progress = _derive_progress(state, current_stage, stages)

        return {
            "scanId": scan_id,
            "target": scan.get("target"),
            "state": state,
            "currentStage": current_stage,
            "progress": progress,
            "createdAt": _to_iso(scan.get("created_at")),
            "startedAt": _to_iso(scan.get("started_at")),
            "completedAt": _to_iso(scan.get("completed_at")),
            "pdfReady": bool(scan.get("pdf_path")),
            "reportFilename": Path(str(scan.get("pdf_path"))).name if scan.get("pdf_path") else None,
            "rawReady": bool(scan.get("raw_path")),
            "rawFilename": Path(str(scan.get("raw_path"))).name if scan.get("raw_path") else None,
            "scanMode": scan.get("scan_mode", "fast"),
            "summary": _summary_from_json(scan.get("summary")),
            "stages": [
                {
                    "name": stage.get("stage_name"),
                    "state": stage.get("state"),
                    "startedAt": _to_iso(stage.get("started_at")),
                    "completedAt": _to_iso(stage.get("completed_at")),
                    "error": stage.get("error"),
                }
                for stage in stages
            ],
        }

    # ── Cancel Scan ──────────────────────────────────────────────────────
    @app.post("/api/scans/{scan_id}/cancel", dependencies=[Depends(verify_token)])
    async def cancel_scan_endpoint(scan_id: str):
        scan = await database.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")

        ok = await job_manager.cancel(scan_id)
        if not ok:
            # If the scan wasn't successfully cancelled, it might mean it's already done or failed
            # We still return HTTP 200 but indicate it in the response body if needed
            pass
            
        return {"scanId": scan_id, "cancelled": ok}

    @app.delete("/api/scans/{scan_id}", dependencies=[Depends(verify_token)])
    async def delete_scan_endpoint(scan_id: str):
        scan = await database.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")

        # 1. Stop if running
        await job_manager.cancel(scan_id)

        # 2. Clean up files (PDF and Logs)
        try:
            # Delete PDF
            raw_path = scan.get("pdf_path")
            if raw_path:
                pdf_file = Path(str(raw_path))
                if pdf_file.exists():
                    pdf_file.unlink()
            
            # Delete Log File
            log_file = config.log_dir / f"scan_{scan_id}.log"
            if log_file.exists():
                log_file.unlink()

            # Delete Raw JSON
            raw_path = scan.get("raw_path")
            if raw_path:
                raw_file = Path(str(raw_path))
                if raw_file.exists():
                    raw_file.unlink()
        except Exception as e:
            logger.warning(f"File cleanup during delete failed for {scan_id}: {e}")

        # 3. Delete from Database
        ok = await database.delete_scan(scan_id)
        if not ok:
            raise HTTPException(status_code=500, detail="Failed to delete scan record.")

        return {"scanId": scan_id, "deleted": True}

    # ── Get Scan Logs ────────────────────────────────────────────────────

    @app.get("/api/scans/{scan_id}/logs", dependencies=[Depends(verify_token)])
    async def get_scan_logs(scan_id: str, after: int = 0):
        scan = await database.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")

        entries = _read_log_entries(config, scan_id)
        after = max(0, after)
        return {
            "entries": entries[after:],
            "nextCursor": len(entries),
        }

    # ── Get Scan Report ──────────────────────────────────────────────────

    @app.get("/api/scans/{scan_id}/report", dependencies=[Depends(verify_token)])
    async def get_scan_report(scan_id: str):
        scan = await database.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")

        raw_path = scan.get("pdf_path")
        if not raw_path:
            raise HTTPException(status_code=409, detail="Report is not available yet.")

        pdf_path = Path(str(raw_path))
        if not pdf_path.exists():
            raise HTTPException(status_code=404, detail="Stored report file is missing.")

        return FileResponse(
            path=str(pdf_path),
            media_type="application/pdf",
            filename=pdf_path.name,
        )

    @app.get("/api/scans/{scan_id}/raw", dependencies=[Depends(verify_token)])
    async def get_scan_raw_data(scan_id: str):
        scan = await database.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")

        raw_path = scan.get("raw_path")
        if not raw_path:
            raise HTTPException(status_code=409, detail="Raw data is not available.")

        file_path = Path(str(raw_path))
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Raw data file is missing.")

        return FileResponse(
            path=str(file_path),
            media_type="application/json",
            filename=file_path.name,
        )

    # ── List Recent Scans ────────────────────────────────────────────────

    @app.get("/api/scans", dependencies=[Depends(verify_token)])
    async def list_scans(limit: int = 20):
        scans = await database.get_recent_scans(limit=min(limit, 100))
        return {
            "scans": [
                {
                    "scanId": s.get("scan_id"),
                    "target": s.get("target"),
                    "state": s.get("state"),
                    "completedAt": _to_iso(s.get("completed_at")),
                    "pdfReady": bool(s.get("pdf_path")),
                    "reportFilename": Path(str(s.get("pdf_path"))).name if s.get("pdf_path") else None,
                    "rawReady": bool(s.get("raw_path")),
                    "rawFilename": Path(str(s.get("raw_path"))).name if s.get("raw_path") else None,
                    "scanMode": s.get("scan_mode", "fast"),
                    "summary": _summary_from_json(s.get("summary")),
                }
                for s in scans
            ]
        }

    return app


# ── Stage derivation helpers ─────────────────────────────────────────────────

def _derive_current_stage(job, stages: list[dict], state: str) -> str:
    if job and getattr(job, "current_stage", None):
        return str(job.current_stage)

    ordered = sorted(
        stages,
        key=lambda item: (
            STAGE_ORDER.index(item["stage_name"])
            if item["stage_name"] in STAGE_ORDER
            else len(STAGE_ORDER),
            item.get("id", 0),
        ),
    )

    for stage in reversed(ordered):
        if stage.get("state") in {"running", "failed", "completed"}:
            return str(stage.get("stage_name"))

    if state == "completed":
        return "Completed"
    if state in {"failed", "cancelled"}:
        return "Failed"
    return "Queued"


def _derive_progress(state: str, current_stage: str, stages: list[dict]) -> int:
    if state == "queued":
        return 0
    if state == "completed":
        return 100

    completed_stages = {
        str(stage.get("stage_name"))
        for stage in stages
        if stage.get("state") == "completed"
    }
    max_completed = max(
        (STAGE_PROGRESS.get(name, 0) for name in completed_stages), default=0
    )
    current = STAGE_PROGRESS.get(current_stage, max_completed)

    return max(max_completed, current, 1)


def _read_log_entries(config: Config, scan_id: str) -> list[dict]:
    log_path = config.log_dir / f"scan_{scan_id}.log"
    if not log_path.exists():
        return []

    entries: list[dict] = []
    for index, raw_line in enumerate(
        log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    ):
        line = raw_line.strip()
        if not line:
            continue

        match = LOG_PATTERN.match(line)
        if not match:
            entries.append(
                {
                    "id": f"{scan_id}:{index}",
                    "createdAt": None,
                    "stage": "System",
                    "message": line,
                }
            )
            continue

        stage = match.group("stage") or "System"
        entries.append(
            {
                "id": f"{scan_id}:{index}",
                "createdAt": _normalize_log_timestamp(match.group("ts")),
                "stage": stage,
                "message": match.group("message").strip(),
            }
        )
    return entries


def _normalize_log_timestamp(raw: str) -> str | None:
    try:
        parsed = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return raw
    return parsed.replace(tzinfo=timezone.utc).isoformat()

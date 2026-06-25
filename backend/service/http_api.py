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
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

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
    "APIScan",
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
    "APIScan": 80,
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
URL_PATTERN = re.compile(r"https?://[^\s'\"<>]+")


# ── Request/Response models ──────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    scanMode: Optional[str] = "fast"
    userRef: Optional[str] = ""
    externalJobId: Optional[str] = ""
    customCookies: Optional[str] = None
    customHeaders: Optional[str] = None
    authLoginUrl: Optional[str] = None
    authLoginPayload: Optional[str] = None
    authTokenJsonPath: Optional[str] = None
    authHeaderTemplate: Optional[str] = None
    originIp: Optional[str] = None
    origin_ip: Optional[str] = None
    apiEndpoints: Optional[str] = None
    api_endpoints: Optional[str] = None


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


SENSITIVE_QUERY_NAMES = {
    "access_token",
    "apikey",
    "api_key",
    "auth",
    "key",
    "secret",
    "signature",
    "token",
}


def _redact_url(raw_url: str) -> str:
    parsed = urlparse(str(raw_url or ""))
    if not parsed.query:
        return str(raw_url or "")

    redacted_pairs = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if name.lower() in SENSITIVE_QUERY_NAMES or "key" in name.lower() or "token" in name.lower():
            redacted_pairs.append((name, "REDACTED"))
        else:
            redacted_pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(redacted_pairs, doseq=True)))


def _redact_sensitive_text(raw_text: Any) -> str:
    text = str(raw_text or "")
    return URL_PATTERN.sub(lambda match: _redact_url(match.group(0)), text)


def _json_fields(body_excerpt: Any) -> list[str]:
    try:
        parsed = json.loads(str(body_excerpt or ""))
    except Exception:
        return []
    if isinstance(parsed, dict):
        return sorted(str(key) for key in parsed.keys())
    return []


NEGATIVE_CONTROL_HINTS = (
    "negative control",
    "invalid key",
    "missing key",
    "key swap",
    "with balance key",
    "with channel key",
    "wrong merchant",
    "merchant-scope",
    "wrong key",
    "wrong-purpose",
)

KEY_SWAP_HINTS = (
    "key swap",
    "with balance key",
    "with channel key",
    "wrong-purpose",
)


def _looks_like_negative_control(name: str) -> bool:
    lowered = str(name or "").lower()
    return any(hint in lowered for hint in NEGATIVE_CONTROL_HINTS)


def _looks_like_key_swap(name: str) -> bool:
    lowered = str(name or "").lower()
    return any(hint in lowered for hint in KEY_SWAP_HINTS)


def _api_observation_result(obs: dict) -> str:
    status = int(obs.get("status", 0) or 0)
    name = str(obs.get("name", "") or "")
    excerpt = str(obs.get("body_excerpt", "") or "").lower()

    if status == 403 and ("just a moment" in excerpt or "challenges.cloudflare.com" in excerpt):
        return "blocked"
    if _looks_like_negative_control(name):
        return "finding" if 200 <= status < 300 else "pass"
    return "pass" if 200 <= status < 300 else "fail"


def _api_observation_expected(obs: dict) -> str:
    name = str(obs.get("name", "") or "")
    if _looks_like_negative_control(name):
        return "Should be rejected"
    return "Should succeed"


def _api_case_result(observations: list[dict]) -> str:
    results = {str(obs.get("result", "")) for obs in observations}
    if "finding" in results:
        return "finding"
    if "blocked" in results:
        return "blocked"
    if "fail" in results:
        return "fail"
    return "pass"


def _api_case_summary(case_name: str, result: str, statuses: list[int], json_fields: list[str]) -> str:
    status_text = ", ".join(str(status) for status in sorted(set(statuses))) or "unknown"
    is_negative = _looks_like_negative_control(case_name)
    is_key_swap = _looks_like_key_swap(case_name)

    if result == "blocked":
        return "Request belum sampai aplikasi karena diblokir CDN/WAF. Validasi belum konklusif."
    if result == "finding":
        if is_key_swap:
            return (
                "Kandidat finding: endpoint menerima key dari workflow lain dan tetap mengembalikan data. "
                f"HTTP {status_text}; fields: {', '.join(json_fields) if json_fields else 'n/a'}."
            )
        if not is_negative:
            return (
                "Kandidat finding: request berhasil tetapi response memicu indikator keamanan. "
                f"HTTP {status_text}; fields: {', '.join(json_fields) if json_fields else 'n/a'}."
            )
        return (
            "Kandidat finding: negative control diterima sebagai request sukses. "
            f"HTTP {status_text}; fields: {', '.join(json_fields) if json_fields else 'n/a'}."
        )
    if is_negative:
        return f"Aman untuk skenario ini: negative control ditolak sesuai ekspektasi. HTTP {status_text}."
    if result == "pass":
        return f"Request valid berhasil. HTTP {status_text}."
    return f"Request valid tidak sesuai ekspektasi. HTTP {status_text}; perlu cek path, key, body, atau origin routing."


def _api_build_test_cases(observations: list[dict], findings: list[dict]) -> list[dict]:
    finding_names = {str(finding.get("endpointName") or "") for finding in findings}
    finding_urls = {
        str(url)
        for finding in findings
        for url in finding.get("_rawAffected", finding.get("affected", []))
    }
    grouped: dict[tuple[str, str, str], list[dict]] = {}

    for obs in observations:
        key = (
            str(obs.get("name") or "Unnamed API check"),
            str(obs.get("method") or "GET"),
            str(obs.get("url") or ""),
        )
        grouped.setdefault(key, []).append(obs)

    test_cases = []
    for (name, method, url), items in grouped.items():
        result = _api_case_result(items)
        raw_urls = {str(item.get("_rawUrl") or item.get("url") or "") for item in items}
        if name in finding_names or bool(raw_urls & finding_urls):
            result = "finding"
        statuses = [int(item.get("status", 0) or 0) for item in items]
        fields = sorted({field for item in items for field in item.get("jsonFields", [])})
        contexts = [
            {
                "authContext": item.get("authContext") or "",
                "status": item.get("status", 0),
                "result": item.get("result") or "fail",
            }
            for item in items
        ]
        test_cases.append({
            "name": name,
            "method": method,
            "url": url,
            "expected": _api_observation_expected({"name": name}),
            "result": result,
            "statuses": sorted(set(statuses)),
            "jsonFields": fields,
            "contexts": contexts,
            "summary": _api_case_summary(name, result, statuses, fields),
        })

    order = {"finding": 0, "fail": 1, "blocked": 2, "pass": 3}
    return sorted(test_cases, key=lambda item: (order.get(item["result"], 9), item["name"]))


def _api_finding_confidence(extra: dict) -> tuple[str, int, str]:
    kind = str(extra.get("kind") or "").lower()
    similarity = float(extra.get("response_similarity", 0) or 0)
    has_financial_fields = bool(extra.get("has_financial_fields"))
    is_key_swap = bool(extra.get("is_key_swap"))

    if kind == "api-negative-control-accepted":
        if has_financial_fields or is_key_swap:
            return (
                "confirmed",
                92,
                "Negative control returned a successful business response with financial fields or key-swap evidence.",
            )
        return (
            "probable",
            78,
            "Negative control returned HTTP success; business impact still needs manual validation.",
        )

    if kind == "api-invalid-auth-accepted":
        if similarity >= 0.85:
            return (
                "confirmed",
                90,
                "Invalid authentication returned a successful response close to the authenticated response.",
            )
        return (
            "probable",
            76,
            "Invalid authentication was accepted, but response similarity needs review.",
        )

    if kind == "api-signature-bypass-candidate":
        if similarity >= 0.85:
            return (
                "confirmed",
                88,
                "Missing or invalid signature material returned a successful similar response.",
            )
        return (
            "probable",
            74,
            "Signature enforcement appears weak, but manual replay is recommended.",
        )

    if kind == "api-idor-candidate":
        if similarity >= 0.85:
            return (
                "probable",
                72,
                "Identifier tampering returned a successful similar response; object ownership needs confirmation.",
            )
        return (
            "needs_manual_validation",
            58,
            "Identifier tampering returned success, but cross-object access is not confirmed.",
        )

    if kind == "api-sensitive-data":
        return (
            "probable",
            72,
            "Successful API response contains patterns consistent with sensitive data.",
        )

    return (
        "needs_manual_validation",
        50,
        "Application-layer signal needs manual review.",
    )


def _api_evidence_from_raw(raw_entries: list[dict]) -> dict:
    observations: list[dict] = []
    findings: list[dict] = []
    validation_queue: list[dict] = []

    for entry in raw_entries:
        if entry.get("tool_name") != "api-scan":
            continue
        try:
            payload = json.loads(str(entry.get("stdout") or "{}"))
        except Exception:
            continue

        for obs in payload.get("observations", []):
            if not isinstance(obs, dict):
                continue
            status = int(obs.get("status", 0) or 0)
            result = _api_observation_result(obs)
            observations.append({
                "name": obs.get("name") or "Unnamed API check",
                "method": obs.get("method") or "GET",
                "url": _redact_url(str(obs.get("url") or "")),
                "_rawUrl": str(obs.get("url") or ""),
                "authContext": obs.get("auth_context") or "authenticated",
                "status": status,
                "expected": _api_observation_expected(obs),
                "result": result,
                "length": obs.get("length", 0),
                "jsonFields": _json_fields(obs.get("body_excerpt")),
                "blockedBy": "Cloudflare" if result == "blocked" else None,
            })

        for finding in payload.get("findings", []):
            if not isinstance(finding, dict):
                continue
            extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
            raw_affected = [str(url) for url in finding.get("affected", [])]
            confidence, confidence_score, confidence_reason = _api_finding_confidence(extra)
            findings.append({
                "title": finding.get("title") or "API Finding",
                "severity": finding.get("severity") or "info",
                "description": _redact_sensitive_text(finding.get("description")),
                "affected": [_redact_url(url) for url in raw_affected],
                "_rawAffected": raw_affected,
                "kind": extra.get("kind") or "",
                "endpointName": extra.get("endpoint_name") or "",
                "jsonFields": extra.get("json_fields") or [],
                "hasFinancialFields": bool(extra.get("has_financial_fields")),
                "confidence": confidence,
                "confidenceScore": confidence_score,
                "confidenceReason": confidence_reason,
            })

        for item in payload.get("validation_queue", []):
            if not isinstance(item, dict):
                continue
            validation_queue.append({
                "title": item.get("title") or "Manual validation queued",
                "kind": item.get("kind") or "",
                "method": item.get("method") or "",
                "url": _redact_url(str(item.get("url") or "")),
                "reason": item.get("reason") or "",
                "status": (item.get("evidence") or {}).get("status") if isinstance(item.get("evidence"), dict) else None,
            })

    counts = {
        "total": len(observations),
        "pass": sum(1 for obs in observations if obs["result"] == "pass"),
        "fail": sum(1 for obs in observations if obs["result"] == "fail"),
        "finding": sum(1 for obs in observations if obs["result"] == "finding"),
        "blocked": sum(1 for obs in observations if obs["result"] == "blocked"),
    }
    test_cases = _api_build_test_cases(observations, findings)
    case_counts = {
        "total": len(test_cases),
        "pass": sum(1 for item in test_cases if item["result"] == "pass"),
        "fail": sum(1 for item in test_cases if item["result"] == "fail"),
        "finding": sum(1 for item in test_cases if item["result"] == "finding"),
        "blocked": sum(1 for item in test_cases if item["result"] == "blocked"),
    }
    if case_counts["finding"]:
        verdict = "finding"
        headline = f"{case_counts['finding']} kandidat finding perlu divalidasi manual."
    elif case_counts["fail"]:
        verdict = "needs_review"
        headline = f"{case_counts['fail']} test valid gagal dan perlu dicek."
    elif case_counts["blocked"]:
        verdict = "blocked"
        headline = f"{case_counts['blocked']} test diblokir sebelum mencapai aplikasi."
    else:
        verdict = "pass"
        headline = "Semua kontrol yang diuji berjalan sesuai ekspektasi."

    public_observations = [
        {key: value for key, value in obs.items() if not key.startswith("_")}
        for obs in observations
    ]
    public_findings = [
        {key: value for key, value in finding.items() if not key.startswith("_")}
        for finding in findings
    ]

    return {
        "verdict": verdict,
        "headline": headline,
        "counts": counts,
        "caseCounts": case_counts,
        "testCases": test_cases,
        "observations": public_observations,
        "findings": public_findings,
        "validationQueue": validation_queue,
    }


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
                custom_cookies=body.customCookies,
                custom_headers=body.customHeaders,
                auth_login_url=body.authLoginUrl,
                auth_login_payload=body.authLoginPayload,
                auth_token_json_path=body.authTokenJsonPath,
                auth_header_template=body.authHeaderTemplate,
                origin_ip=body.originIp or body.origin_ip,
                api_endpoints=body.apiEndpoints or body.api_endpoints,
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

    @app.get("/api/scans/{scan_id}/api-evidence", dependencies=[Depends(verify_token)])
    async def get_scan_api_evidence(scan_id: str):
        scan = await database.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")

        raw_path = scan.get("raw_path")
        if not raw_path:
            return {
                "scanId": scan_id,
                "ready": False,
                "counts": {"total": 0, "pass": 0, "fail": 0, "finding": 0, "blocked": 0},
                "observations": [],
                "findings": [],
                "validationQueue": [],
            }

        file_path = Path(str(raw_path))
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Raw data file is missing.")

        try:
            raw_entries = json.loads(file_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Could not parse raw API evidence: {exc}")

        evidence = _api_evidence_from_raw(raw_entries if isinstance(raw_entries, list) else [])
        return {
            "scanId": scan_id,
            "ready": True,
            **evidence,
        }

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


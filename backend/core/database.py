"""
PentestBot v2 — Database Layer
Async SQLite via aiosqlite.
Stores scan jobs, raw outputs, results, and audit logs persistently.
"""

import json
import time
from pathlib import Path
from typing import Any, Optional

import aiosqlite

from utils.logger import get_logger

logger = get_logger("core.database")


class Database:
    """
    Async SQLite database for persistent scan state storage.
    All operations are non-blocking; designed for single-process use.
    """

    SCHEMA = """
    PRAGMA journal_mode=WAL;
    PRAGMA foreign_keys=ON;

    CREATE TABLE IF NOT EXISTS scans (
        scan_id     TEXT PRIMARY KEY,
        user_id     INTEGER NOT NULL,
        target      TEXT NOT NULL,
        state       TEXT NOT NULL DEFAULT 'queued',
        created_at  REAL NOT NULL,
        started_at  REAL,
        completed_at REAL,
        error       TEXT,
        pdf_path    TEXT,
        raw_path    TEXT,
        summary     TEXT,  -- JSON blob of key metrics
        auth_login_url TEXT,
        auth_login_payload TEXT,
        auth_token_json_path TEXT
    );

    CREATE TABLE IF NOT EXISTS scan_stages (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
        stage_name  TEXT NOT NULL,
        state       TEXT NOT NULL DEFAULT 'pending',
        started_at  REAL,
        completed_at REAL,
        error       TEXT,
        result_size INTEGER DEFAULT 0  -- bytes of output
    );

    CREATE TABLE IF NOT EXISTS scan_results (
        scan_id     TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
        data        TEXT NOT NULL  -- JSON blob of all aggregated results
    );

    CREATE TABLE IF NOT EXISTS raw_outputs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
        tool_name   TEXT NOT NULL,
        stage_name  TEXT NOT NULL,
        status      TEXT NOT NULL DEFAULT 'success',  -- success, failed, misconfigured, no_findings
        stdout      TEXT DEFAULT '',
        stderr      TEXT DEFAULT '',
        duration    REAL DEFAULT 0,
        created_at  REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          REAL NOT NULL,
        user_id     INTEGER,
        scan_id     TEXT,
        action      TEXT NOT NULL,
        detail      TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_scans_user   ON scans(user_id);
    CREATE INDEX IF NOT EXISTS idx_scans_state  ON scans(state);
    CREATE INDEX IF NOT EXISTS idx_stages_scan  ON scan_stages(scan_id);
    CREATE INDEX IF NOT EXISTS idx_raw_scan     ON raw_outputs(scan_id);
    CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(ts);
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        """Open the connection and create tables."""
        self._conn = await aiosqlite.connect(str(self.db_path))
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(self.SCHEMA)
        await self._conn.commit()
        # Migration: add columns if missing
        await self._migrate_columns()
        logger.info(f"Database initialized: {self.db_path}")

    async def _migrate_columns(self) -> None:
        """Ensure all columns exist in scans table."""
        try:
            async with self._conn.execute("PRAGMA table_info(scans)") as cur:
                columns = [row[1] for row in await cur.fetchall()]
            if "scan_mode" not in columns:
                await self._conn.execute(
                    "ALTER TABLE scans ADD COLUMN scan_mode TEXT DEFAULT 'fast'"
                )
                await self._conn.commit()
                logger.info("Migration: added scan_mode column to scans table")
            
            if "raw_path" not in columns:
                await self._conn.execute(
                    "ALTER TABLE scans ADD COLUMN raw_path TEXT"
                )
                await self._conn.commit()
                logger.info("Migration: added raw_path column to scans table")

            if "auth_login_url" not in columns:
                await self._conn.execute(
                    "ALTER TABLE scans ADD COLUMN auth_login_url TEXT"
                )
                await self._conn.commit()
                logger.info("Migration: added auth_login_url column to scans table")

            if "auth_login_payload" not in columns:
                await self._conn.execute(
                    "ALTER TABLE scans ADD COLUMN auth_login_payload TEXT"
                )
                await self._conn.commit()
                logger.info("Migration: added auth_login_payload column to scans table")

            if "auth_token_json_path" not in columns:
                await self._conn.execute(
                    "ALTER TABLE scans ADD COLUMN auth_token_json_path TEXT"
                )
                await self._conn.commit()
                logger.info("Migration: added auth_token_json_path column to scans table")
        except Exception as e:
            if "duplicate column name" not in str(e).lower():
                logger.warning(f"Migration check failed: {e}")

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    # ── Scans ──────────────────────────────────────────────────────────────

    async def create_scan(
        self,
        scan_id: str,
        user_id: int,
        target: str,
        scan_mode: str = "fast",
        auth_login_url: Optional[str] = None,
        auth_login_payload: Optional[str] = None,
        auth_token_json_path: Optional[str] = None,
    ) -> None:
        await self._conn.execute(
            """INSERT INTO scans (scan_id, user_id, target, state, created_at, scan_mode,
                                 auth_login_url, auth_login_payload, auth_token_json_path)
               VALUES (?, ?, ?, 'queued', ?, ?, ?, ?, ?)""",
            (scan_id, user_id, target, time.time(), scan_mode,
             auth_login_url, auth_login_payload, auth_token_json_path),
        )
        await self._conn.commit()
        logger.debug(f"Created scan record: {scan_id}")

    async def update_scan_state(
        self,
        scan_id: str,
        state: str,
        error: Optional[str] = None,
        pdf_path: Optional[str] = None,
        raw_path: Optional[str] = None,
        summary: Optional[dict] = None,
    ) -> None:
        now = time.time()
        updates = ["state = ?"]
        params: list[Any] = [state]

        if state == "running":
            updates.append("started_at = ?")
            params.append(now)
        elif state in ("completed", "failed", "cancelled"):
            updates.append("completed_at = ?")
            params.append(now)

        if error is not None:
            updates.append("error = ?")
            params.append(error)
        if pdf_path is not None:
            updates.append("pdf_path = ?")
            params.append(pdf_path)
        if raw_path is not None:
            updates.append("raw_path = ?")
            params.append(raw_path)
        if summary is not None:
            updates.append("summary = ?")
            params.append(json.dumps(summary))

        params.append(scan_id)
        await self._conn.execute(
            f"UPDATE scans SET {', '.join(updates)} WHERE scan_id = ?",
            params,
        )
        await self._conn.commit()

    async def get_scan(self, scan_id: str) -> Optional[dict]:
        async with self._conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def delete_scan(self, scan_id: str) -> bool:
        """Remove a scan and all its cascaded records from the database."""
        try:
            await self._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            await self._conn.commit()
            logger.info(f"Deleted scan record: {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete scan {scan_id}: {e}")
            return False

    async def get_user_scans(
        self, user_id: int, limit: int = 10
    ) -> list[dict]:
        async with self._conn.execute(
            """SELECT scan_id, target, state, created_at, completed_at,
                      pdf_path, raw_path, summary, scan_mode
               FROM scans
               WHERE user_id = ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (user_id, limit),
        ) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_recent_scans(self, limit: int = 20) -> list[dict]:
        """Return the most recent scans across all users."""
        async with self._conn.execute(
            """SELECT scan_id, target, state, created_at, completed_at,
                      pdf_path, raw_path, summary, scan_mode
               FROM scans
               ORDER BY created_at DESC
               LIMIT ?""",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_active_scans(self) -> list[dict]:
        """Return all scans currently in queued or running state."""
        async with self._conn.execute(
            "SELECT * FROM scans WHERE state IN ('queued', 'running')"
        ) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    # ── Stages ────────────────────────────────────────────────────────────

    async def upsert_stage(
        self,
        scan_id: str,
        stage_name: str,
        state: str,
        error: Optional[str] = None,
        result_size: int = 0,
    ) -> None:
        now = time.time()
        existing = await self._get_stage(scan_id, stage_name)

        if existing is None:
            # Only set started_at if it's starting in 'running' state
            started_at = now if state == "running" else None
            await self._conn.execute(
                """INSERT INTO scan_stages
                   (scan_id, stage_name, state, started_at, result_size)
                   VALUES (?, ?, ?, ?, ?)""",
                (scan_id, stage_name, state, started_at, result_size),
            )
        else:
            updates = ["state = ?"]
            params: list[Any] = [state]

            # Set started_at if transitioning to running and it's not already set
            if state == "running" and not existing.get("started_at"):
                updates.append("started_at = ?")
                params.append(now)

            if state in ("completed", "failed"):
                updates.append("completed_at = ?")
                params.append(now)
            if error:
                updates.append("error = ?")
                params.append(error)
            if result_size:
                updates.append("result_size = ?")
                params.append(result_size)

            params += [scan_id, stage_name]
            await self._conn.execute(
                f"UPDATE scan_stages SET {', '.join(updates)} "
                f"WHERE scan_id = ? AND stage_name = ?",
                params,
            )
        await self._conn.commit()

    async def _get_stage(self, scan_id: str, stage_name: str) -> Optional[dict]:
        async with self._conn.execute(
            "SELECT * FROM scan_stages WHERE scan_id = ? AND stage_name = ?",
            (scan_id, stage_name),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_scan_stages(self, scan_id: str) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM scan_stages WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    # ── Raw Outputs ──────────────────────────────────────────────────────

    async def save_raw_output(
        self,
        scan_id: str,
        tool_name: str,
        stage_name: str,
        status: str = "success",
        stdout: str = "",
        stderr: str = "",
        duration: float = 0.0,
    ) -> None:
        """Persist per-tool raw stdout/stderr separately from parsed findings."""
        await self._conn.execute(
            """INSERT INTO raw_outputs
               (scan_id, tool_name, stage_name, status, stdout, stderr, duration, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, tool_name, stage_name, status, stdout, stderr, duration, time.time()),
        )
        await self._conn.commit()

    async def get_raw_outputs(self, scan_id: str) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM raw_outputs WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_tool_status_summary(self, scan_id: str) -> dict:
        """Return classification of tool results: success/failed/misconfigured/no_findings."""
        outputs = await self.get_raw_outputs(scan_id)
        summary = {
            "success": [],
            "failed": [],
            "misconfigured": [],
            "no_findings": [],
        }
        for row in outputs:
            status = row.get("status", "success")
            tool = row.get("tool_name", "unknown")
            if status in summary:
                summary[status].append(tool)
            else:
                summary["failed"].append(tool)
        return summary

    # ── Results ───────────────────────────────────────────────────────────

    async def save_results(self, scan_id: str, data: dict) -> None:
        serialized = json.dumps(data, default=str)
        await self._conn.execute(
            """INSERT OR REPLACE INTO scan_results (scan_id, data)
               VALUES (?, ?)""",
            (scan_id, serialized),
        )
        await self._conn.commit()
        logger.debug(f"Saved results for {scan_id} ({len(serialized)} bytes)")

    async def load_results(self, scan_id: str) -> Optional[dict]:
        async with self._conn.execute(
            "SELECT data FROM scan_results WHERE scan_id = ?",
            (scan_id,),
        ) as cur:
            row = await cur.fetchone()
            if row:
                return json.loads(row["data"])
            return None

    # ── Audit Log ─────────────────────────────────────────────────────────

    async def audit(
        self,
        action: str,
        user_id: Optional[int] = None,
        scan_id: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> None:
        await self._conn.execute(
            "INSERT INTO audit_log (ts, user_id, scan_id, action, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (time.time(), user_id, scan_id, action, detail),
        )
        await self._conn.commit()

    # ── Statistics ────────────────────────────────────────────────────────

    async def get_stats(self) -> dict:
        stats = {}
        for state in ("queued", "running", "completed", "failed", "cancelled"):
            async with self._conn.execute(
                "SELECT COUNT(*) as n FROM scans WHERE state = ?", (state,)
            ) as cur:
                row = await cur.fetchone()
                stats[state] = row["n"]

        async with self._conn.execute(
            "SELECT COUNT(DISTINCT user_id) as n FROM scans"
        ) as cur:
            row = await cur.fetchone()
            stats["unique_users"] = row["n"]

        return stats

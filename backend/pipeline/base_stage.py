"""
PentestBot v2 — Pipeline Base Stage
All pipeline stages inherit from BaseStage for a uniform interface.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from utils.command_runner import CommandRunner, CommandResult
from utils.logger import ScanLogger


class BaseStage(ABC):
    """
    Abstract base for all pipeline stages.

    Each stage receives a shared `ctx` dict that carries
    data from previous stages and accumulates new results.
    """

    NAME: str = "base"

    def __init__(self, ctx: dict):
        self.ctx:      dict          = ctx
        self.scan_id:  str           = ctx["scan_id"]
        self.target:   str           = ctx["target"]
        self.work_dir: Path          = ctx["work_dir"]
        self.config:   Any           = ctx["config"]
        self.log:      ScanLogger    = ctx["logger"]
        self.runner:   CommandRunner = CommandRunner(
            default_timeout=300,
            work_dir=self.work_dir,
        )

    @abstractmethod
    async def run(self) -> None:
        """Execute this stage. Must update ctx in place."""

    def temp_file(self, name: str) -> Path:
        """Return a path to a temp file in the work directory."""
        return self.work_dir / name

    def write_lines(self, path: Path, lines: list[str]) -> Path:
        """Write a list of strings to a file, one per line."""
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def read_lines(self, path: Path) -> list[str]:
        """Read non-empty lines from a file."""
        if not path.exists():
            return []
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def add_tool_error(self, message: str) -> None:
        self.ctx.setdefault("tool_errors", []).append(f"{self.NAME}: {message}")

    def set_stage_error(self, message: str) -> None:
        self.ctx.setdefault("stage_errors", {})[self.NAME] = message
        self.add_tool_error(message)

    def clear_stage_error(self) -> None:
        self.ctx.setdefault("stage_errors", {}).pop(self.NAME, None)

    def log_result(self, result: CommandResult) -> None:
        if result.success:
            self.log.info(
                f"[{self.NAME}] {result.command[0]} OK "
                f"({result.duration:.1f}s, {len(result.stdout)} bytes)"
            )
        else:
            self.log.warning(
                f"[{self.NAME}] {result.command[0]} failed: "
                f"{result.stderr[:200]}"
            )
        # Automatically capture for Task 3: Raw Data Preservation
        self.save_raw_result(result.command[0], result)

    def save_raw_result(self, tool_name: str, result: CommandResult) -> None:
        """Capture raw tool output into context for later preservation."""
        self.ctx.setdefault("raw_outputs", []).append({
            "tool_name": Path(tool_name).name,
            "stage_name": self.NAME,
            "status": "success" if result.success else "failed",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration": result.duration,
        })

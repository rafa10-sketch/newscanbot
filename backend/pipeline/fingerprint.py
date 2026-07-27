"""
PentestBot v2 - Fingerprinting Stage
Runs WhatWeb, Wafw00f, and Webanalyze for technology detection and WAF identification.
"""

import asyncio
import json
from pathlib import Path

from pipeline.base_stage import BaseStage


class FingerprintStage(BaseStage):
    """
    Stage: Fingerprinting & Security Checks

    WhatWeb:    Web technology fingerprinting (CMS, frameworks, libraries).
    Wafw00f:    Web Application Firewall detection.
    Webanalyze: Wappalyzer-based technology detection (Go binary).

    All tools are run concurrently on the primary target. Results enrich the
    existing technology/web_server data from HTTPX.
    """

    NAME = "Fingerprint"

    async def run(self) -> None:
        self.clear_stage_error()

        if not getattr(self.config, "enable_fingerprint", True):
            self.log.info("[Fingerprint] Fingerprinting disabled by configuration")
            return

        live_hosts = self.ctx.get("live_hosts", [])
        primary_url = self._pick_primary_url(live_hosts)

        self.log.info(f"[Fingerprint] Starting fingerprinting on {primary_url}")

        tasks = [
            self._run_whatweb(primary_url),
            self._run_wafw00f(primary_url),
            self._run_webanalyze(primary_url),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            tool_name = ["whatweb", "wafw00f", "webanalyze"][i]
            if isinstance(result, Exception):
                self.log.warning(f"[Fingerprint] {tool_name} failed: {result}")

        # Merge technologies from fingerprinting into existing list
        existing_techs = set(self.ctx.get("technologies", []))
        new_techs = set(self.ctx.get("fingerprint_technologies", []))
        merged = list(existing_techs | new_techs)
        self.ctx["technologies"] = sorted(merged)

        waf_info = self.ctx.get("waf_detected", None)
        if waf_info:
            self.ctx.setdefault("limitations", []).append(
                f"WAF detected: {waf_info}. Some scan results may be affected by WAF filtering."
            )

        self.log.info(
            f"[Fingerprint] Complete. "
            f"Technologies: {len(merged)}, "
            f"WAF: {waf_info or 'none detected'}"
        )

    async def _run_whatweb(self, target_url: str) -> None:
        """Run WhatWeb for technology fingerprinting."""
        if not self.runner.which("whatweb"):
            self.log.info("[Fingerprint] whatweb not found - skipping")
            self._save_raw_output("whatweb", "misconfigured", "", "binary not found")
            return

        # Write JSON to a temp file instead of stdout to avoid Ruby
        # IOError ("closed stream") when the pipe closes.
        json_out = self.temp_file("whatweb_output.json")

        cmd = [
            "whatweb",
            "--no-errors",
            f"--log-json={json_out}",
            "-a", "3",  # aggression level 3 (passive + content)
            target_url,
        ]

        result = await self.runner.run(cmd=cmd, timeout=self.config.whatweb_timeout)
        self.log_result(result)

        # Read output from the file instead of stdout
        raw = ""
        if json_out.exists():
            raw = json_out.read_text(encoding="utf-8", errors="replace").strip()

        self._save_raw_output(
            "whatweb",
            "success" if (result.success or raw) else "failed",
            raw,
            result.stderr.strip(),
        )

        if not raw:
            if not result.success:
                self.add_tool_error(f"whatweb failed: {result.stderr[:200]}")
            return

        # Parse WhatWeb JSON output
        techs = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                plugins = entry.get("plugins", {})
                for plugin_name, plugin_data in plugins.items():
                    if plugin_name in {"IP", "Country", "HTTPServer"}:
                        continue
                    version_list = plugin_data.get("version", [])
                    version_str = version_list[0] if version_list else ""
                    tech_label = f"{plugin_name} {version_str}".strip()
                    if tech_label:
                        techs.append(tech_label)
            except (json.JSONDecodeError, AttributeError):
                continue

        if techs:
            self.ctx.setdefault("fingerprint_technologies", []).extend(techs)
            self.log.info(f"[Fingerprint] WhatWeb detected {len(techs)} technologies")

    async def _run_wafw00f(self, target_url: str) -> None:
        """Run Wafw00f for WAF detection."""
        if not self.runner.which("wafw00f"):
            self.log.info("[Fingerprint] wafw00f not found - skipping")
            self._save_raw_output("wafw00f", "misconfigured", "", "binary not found")
            return

        cmd = [
            "wafw00f",
            target_url,
            "-o", "-",  # output to stdout
            "-f", "json",
        ]

        result = await self.runner.run(cmd=cmd, timeout=self.config.wafw00f_timeout)
        self.log_result(result)

        raw = result.stdout.strip()
        self._save_raw_output(
            "wafw00f",
            "success" if result.success else "failed",
            raw,
            result.stderr.strip(),
        )

        if not raw:
            return

        # Parse wafw00f output
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                for entry in data:
                    firewall = entry.get("firewall", "")
                    if firewall and firewall.lower() not in {"none", "generic", "unknown"}:
                        self.ctx["waf_detected"] = firewall
                        self.ctx.setdefault("fingerprint_technologies", []).append(
                            f"WAF: {firewall}"
                        )
                        self.log.info(f"[Fingerprint] WAF detected: {firewall}")
        except (json.JSONDecodeError, TypeError):
            # Try line-based parsing as fallback
            for line in raw.splitlines():
                if "detected" in line.lower() and "waf" in line.lower():
                    self.ctx["waf_detected"] = line.strip()

    async def _run_webanalyze(self, target_url: str) -> None:
        """Run Webanalyze (Wappalyzer-based) for technology detection."""
        if not self.runner.which("webanalyze"):
            self.log.info("[Fingerprint] webanalyze not found - skipping")
            self._save_raw_output("webanalyze", "misconfigured", "", "binary not found")
            return

        cmd = [
            "webanalyze",
            "-host", target_url,
            "-output", "json",
            "-silent",
        ]

        result = await self.runner.run(cmd=cmd, timeout=self.config.webanalyze_timeout)

        # Auto-recover: if technologies.json is missing, download it and retry
        if not result.success and "technologies.json" in (result.stderr or ""):
            self.log.info("[Fingerprint] webanalyze missing technologies.json — running update")
            update_result = await self.runner.run(
                cmd=["webanalyze", "-update"], timeout=30
            )
            if update_result.success:
                result = await self.runner.run(cmd=cmd, timeout=self.config.webanalyze_timeout)

        self.log_result(result)

        raw = result.stdout.strip()
        self._save_raw_output(
            "webanalyze",
            "success" if result.success else "failed",
            raw,
            result.stderr.strip(),
        )

        if not result.success or not raw:
            return

        techs = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                matches = entry.get("matches", [])
                for match in matches:
                    app_name = match.get("app_name") or match.get("app", "")
                    version = match.get("version", "")
                    tech_label = f"{app_name} {version}".strip()
                    if tech_label:
                        techs.append(tech_label)
            except (json.JSONDecodeError, AttributeError):
                continue

        if techs:
            self.ctx.setdefault("fingerprint_technologies", []).extend(techs)
            self.log.info(f"[Fingerprint] Webanalyze detected {len(techs)} technologies")

    def _pick_primary_url(self, live_hosts: list[dict]) -> str:
        """Select the best URL for fingerprinting."""
        if live_hosts:
            # Prefer HTTPS on the root domain
            for host in live_hosts:
                url = host.get("url", "")
                if url.startswith("https://") and self.target in url:
                    return url
            return live_hosts[0].get("url", f"https://{self.target}")
        return f"https://{self.target}"

    def _save_raw_output(
        self, tool: str, status: str, stdout: str, stderr: str
    ) -> None:
        """Queue raw output for database persistence."""
        self.ctx.setdefault("raw_outputs", []).append({
            "tool_name": tool,
            "stage_name": self.NAME,
            "status": status,
            "stdout": stdout[:50000],  # cap at 50KB per tool
            "stderr": stderr[:10000],
        })

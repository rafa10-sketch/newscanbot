"""
PentestBot v2 - Web Discovery Stage
Expands the web attack surface using passive URL sources and focused crawling.
"""

from __future__ import annotations
import asyncio
from urllib.parse import urljoin, urlparse

from pipeline.base_stage import BaseStage


class WebDiscoveryStage(BaseStage):
    """
    Stage 7: Web Discovery

    Collects additional URLs from:
      - gau (historical passive URL discovery)
      - katana (focused crawling from already live URLs)

    The output is intentionally capped and filtered to stay within the target's
    web scope and to avoid turning passive observations into noisy findings.
    """

    NAME = "WebDiscovery"
    DEFAULT_WORDLIST = (
        "admin",
        "api",
        "app",
        "assets",
        "backup",
        "config",
        "dashboard",
        "dev",
        "docs",
        "health",
        "login",
        "logout",
        "portal",
        "private",
        "public",
        "robots.txt",
        "server-status",
        "staging",
        "static",
        "status",
        "test",
        "uat",
        "uploads",
        "user",
        "users",
        "vendor",
    )

    async def run(self) -> None:
        self.clear_stage_error()

        live_hosts = self.ctx.get("live_hosts", [])
        seed_urls = [host.get("url", "") for host in live_hosts if host.get("url")]
        if not seed_urls:
            self.log.warning(
                "[WebDiscovery] No live web hosts found by HTTPProbe (possibly due to WAF/blocking). "
                f"Falling back to target seeds: https://{self.target}, http://{self.target}"
            )
            seed_urls = [f"https://{self.target}", f"http://{self.target}"]

        if not getattr(self.config, "enable_web_discovery", True):
            self.ctx["discovered_urls"] = list(dict.fromkeys(seed_urls))
            self.log.info("[WebDiscovery] Disabled by configuration.")
            return

        discovered: list[str] = []
        discovered.extend(seed_urls)
        discovery_results = await asyncio.gather(
            self._run_gau(),
            self._run_katana(seed_urls),
            self._run_gobuster(seed_urls),
            self._run_dirsearch(seed_urls),
            return_exceptions=True,
        )
        for tool_name, result in zip(("gau", "katana", "gobuster", "dirsearch"), discovery_results):
            if isinstance(result, Exception):
                self.add_tool_error(f"{tool_name} failed: {result}")
                continue
            discovered.extend(result)

        filtered = self._normalize_urls(discovered)
        self.ctx["discovered_urls"] = filtered

        urls_file = self.temp_file("discovered_urls.txt")
        self.write_lines(urls_file, filtered or seed_urls)
        self.ctx["discovered_urls_file"] = urls_file

        self.log.info(
            f"[WebDiscovery] Retained {len(filtered)} scoped URL(s) "
            f"from {len(discovered)} candidate(s)"
        )

    async def _run_gau(self) -> list[str]:
        if not self.runner.which("gau"):
            self.add_tool_error("gau not found; skipped passive URL discovery.")
            return []

        result = await self.runner.run(
            cmd=["gau", "--subs", self.target],
            timeout=self.config.gau_timeout,
        )
        self.log_result(result)
        if not result.success and not result.stdout:
            self.add_tool_error(
                f"gau failed: {self._format_tool_error(result)}"
            )
            return []
        return self._extract_urls(result.stdout)

    async def _run_katana(self, seed_urls: list[str]) -> list[str]:
        if not self.runner.which("katana"):
            self.add_tool_error("katana not found; skipped focused crawling.")
            return []

        seed_file = self.temp_file("web_discovery_seeds.txt")
        self.write_lines(seed_file, seed_urls[:20])

        cmd = [
            "katana",
            "-list",
            str(seed_file),
            "-silent",
            "-d",
            str(self.config.katana_depth),
            "-jc",
        ]
        
        # Inject dynamic cookies and custom headers for authenticated crawling
        custom_cookies = self.ctx.get("custom_cookies")
        custom_headers = self.ctx.get("custom_headers")
        if custom_cookies:
            cmd.extend(["-H", f"Cookie: {custom_cookies}"])
        if custom_headers:
            for header in str(custom_headers).splitlines():
                if header.strip():
                    cmd.extend(["-H", header.strip()])

        result = await self.runner.run(cmd=cmd, timeout=self.config.katana_timeout)
        if not result.success and "flag provided but not defined" in result.stderr.lower():
            cmd = [
                "katana",
                "-list",
                str(seed_file),
                "-silent",
                "-d",
                str(self.config.katana_depth),
            ]
            if custom_cookies:
                cmd.extend(["-H", f"Cookie: {custom_cookies}"])
            if custom_headers:
                for header in str(custom_headers).splitlines():
                    if header.strip():
                        cmd.extend(["-H", header.strip()])
            result = await self.runner.run(cmd=cmd, timeout=self.config.katana_timeout)
        self.log_result(result)
        if not result.success and not result.stdout:
            self.add_tool_error(
                f"katana failed: {self._format_tool_error(result)}"
            )
            return []
        return self._extract_urls(result.stdout)

    async def _run_gobuster(self, seed_urls: list[str]) -> list[str]:
        if not getattr(self.config, "enable_gobuster", True):
            self.log.info("[WebDiscovery] Gobuster disabled by configuration")
            return []

        if not self.runner.which("gobuster"):
            self.add_tool_error("gobuster not found; skipped directory brute forcing.")
            return []

        wordlist = self._wordlist_file()
        discovered: list[str] = []
        for seed in seed_urls[:5]:
            cmd = [
                "gobuster",
                "dir",
                "-u",
                seed,
                "-w",
                str(wordlist),
                "-q",
                "-k",
                "--no-error",
                "-t",
                "20",
            ]

            custom_cookies = self.ctx.get("custom_cookies")
            custom_headers = self.ctx.get("custom_headers")
            if custom_cookies:
                cmd.extend(["-c", str(custom_cookies)])
            if custom_headers:
                for header in str(custom_headers).splitlines():
                    if header.strip():
                        cmd.extend(["-H", header.strip()])

            result = await self.runner.run(cmd=cmd, timeout=self.config.gobuster_timeout)
            self.log_result(result)
            if not result.success and not result.stdout:
                self.add_tool_error(f"gobuster failed for {seed}: {self._format_tool_error(result)}")
                continue
            discovered.extend(self._extract_discovered_paths(seed, result.stdout))

        return discovered

    async def _run_dirsearch(self, seed_urls: list[str]) -> list[str]:
        if not getattr(self.config, "enable_dirsearch", False):
            self.log.info("[WebDiscovery] Dirsearch disabled by configuration")
            return []

        if not self.runner.which("dirsearch"):
            self.add_tool_error("dirsearch not found; skipped directory discovery.")
            return []

        wordlist = self._wordlist_file()
        discovered: list[str] = []
        for seed in seed_urls[:5]:
            cmd = self._dirsearch_base_cmd(seed, wordlist)

            custom_cookies = self.ctx.get("custom_cookies")
            custom_headers = self.ctx.get("custom_headers")
            if custom_cookies:
                cmd.extend(["--cookie", str(custom_cookies)])
            if custom_headers:
                for header in str(custom_headers).splitlines():
                    if header.strip():
                        cmd.extend(["-H", header.strip()])

            result = await self.runner.run(cmd=cmd, timeout=self.config.dirsearch_timeout)
            if not result.success and "traceback" in result.stderr.lower():
                fallback_cmd = self._dirsearch_base_cmd(seed, wordlist, force_python=True)
                if fallback_cmd != cmd:
                    self.log.warning("[WebDiscovery] Dirsearch direct launch failed; retrying via python3")
                    result = await self.runner.run(cmd=fallback_cmd, timeout=self.config.dirsearch_timeout)
            self.log_result(result)
            if not result.success and not result.stdout:
                self.add_tool_error(f"dirsearch failed for {seed}: {self._format_tool_error(result)}")
                continue
            discovered.extend(self._extract_discovered_paths(seed, result.stdout))

        return discovered

    def _wordlist_file(self):
        path = self.temp_file("web_discovery_wordlist.txt")
        if not path.exists():
            self.write_lines(path, list(self.DEFAULT_WORDLIST))
        return path

    def _dirsearch_base_cmd(self, seed: str, wordlist, force_python: bool = False) -> list[str]:
        binary = self.runner.resolve_binary("dirsearch") or "dirsearch"
        cmd_prefix = ["dirsearch"]
        if force_python:
            script = "/opt/dirsearch/dirsearch.py"
            if not self.runner.which("python3"):
                return cmd_prefix
            cmd_prefix = ["python3", script]
        elif str(binary).endswith(".py"):
            cmd_prefix = ["python3", str(binary)] if self.runner.which("python3") else [str(binary)]

        return cmd_prefix + [
            "-u",
            seed,
            "-w",
            str(wordlist),
            "-e",
            "php,html,js,txt,json",
            "-q",
            "--no-color",
        ]

    def _normalize_urls(self, raw_urls: list[str]) -> list[str]:
        seen: set[str] = set()
        normalized: list[str] = []
        max_urls = max(20, int(getattr(self.config, "max_discovered_urls", 150)))

        static_exts = {
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".avi",
            ".mp3", ".wav", ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z"
        }

        for candidate in raw_urls:
            parsed = urlparse(str(candidate).strip())
            if parsed.scheme not in {"http", "https"}:
                continue
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            if host != self.target and not host.endswith(f".{self.target}"):
                continue

            # Filter out static files so we focus on APIs and dynamic endpoints
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in static_exts):
                continue

            # Prefer path-bearing URLs and parameterized endpoints first.
            cleaned = parsed._replace(fragment="").geturl().rstrip("/")
            if cleaned in seen:
                continue
            seen.add(cleaned)
            normalized.append(cleaned)

        normalized.sort(key=self._url_priority)
        return normalized[:max_urls]

    @staticmethod
    def _extract_urls(raw: str) -> list[str]:
        return [
            line.strip()
            for line in raw.splitlines()
            if line.strip().startswith(("http://", "https://"))
        ]

    @staticmethod
    def _extract_discovered_paths(base_url: str, raw: str) -> list[str]:
        urls: list[str] = []
        for line in raw.splitlines():
            text = line.strip()
            if not text:
                continue
            if text.startswith(("http://", "https://")):
                urls.append(text.split()[0])
                continue
            if text.startswith("/"):
                path = text.split()[0]
                urls.append(urljoin(base_url.rstrip("/") + "/", path.lstrip("/")))
        return urls

    @staticmethod
    def _url_priority(url: str) -> tuple[int, int, int, str]:
        parsed = urlparse(url)
        has_query = 0 if parsed.query else 1
        path_depth = -len([part for part in parsed.path.split("/") if part])
        is_root = 1 if parsed.path in {"", "/"} else 0
        return (has_query, is_root, path_depth, url)

    @staticmethod
    def _format_tool_error(result) -> str:
        details = result.stderr.strip()
        if not details:
            stdout_snippet = result.stdout.strip().replace("\n", " ")
            if stdout_snippet:
                details = stdout_snippet[:200]
        if not details:
            details = f"return code {result.returncode}"
        return details

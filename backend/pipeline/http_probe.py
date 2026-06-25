"""
PentestBot v2 - HTTP Probe Stage
Web surface discovery and technology fingerprinting using httpx.
"""

import asyncio
import os
from pathlib import Path

from pipeline.base_stage import BaseStage


class HttpProbeStage(BaseStage):
    """
    Stage 6: HTTP Probing

    Builds a URL list from the most likely web ports and probes each
    with httpx for status, title, technologies, and server headers.
    """

    NAME = "HTTPProbe"

    HTTPS_PORTS = {443, 4443, 7443, 8443, 9443, 10443}
    HTTP_PORTS = {
        80, 81, 82, 83, 84, 88, 591, 593,
        3000, 5000, 7001, 7080, 8000, 8008,
        8080, 8081, 8088, 8089, 8181, 8880,
        8888, 9000, 9090, 10000,
    }
    MAX_PORT_CANDIDATES = 30
    MAX_URLS = 200

    async def run(self) -> None:
        self.clear_stage_error()
        urls = self._build_url_list()
        if not urls:
            urls = [f"https://{self.target}", f"http://{self.target}"]

        self.ctx["probe_urls"] = urls
        urls_file = self.temp_file("probe_urls.txt")
        self.write_lines(urls_file, urls)
        self.ctx["probe_urls_file"] = urls_file
        self.log.info(f"[HTTPProbe] Probing {len(urls)} URLs")

        httpx_binary = await self._select_projectdiscovery_httpx()
        if not httpx_binary:
            self.log.warning(
                "[HTTPProbe] Compatible ProjectDiscovery httpx not found - "
                "using curl fallback"
            )
            self.add_tool_error(
                "ProjectDiscovery httpx not available on PATH; curl fallback used."
            )
            await self._curl_fallback(urls)
            return

        self.ctx["httpx_binary"] = httpx_binary
        await self._run_httpx(urls_file)

    async def _select_projectdiscovery_httpx(self) -> str | None:
        for candidate in self._httpx_candidates():
            self.log.info(f"[HTTPProbe] Using httpx candidate: {candidate}")
            result = await self.runner.run([candidate, "-h"], timeout=10)
            help_text = f"{result.stdout}\n{result.stderr}".lower()
            if "usage: httpx [options] url" in help_text:
                self.log.warning(
                    "[HTTPProbe] Detected Python httpx CLI instead of "
                    "ProjectDiscovery httpx."
                )
                continue
            if self._is_projectdiscovery_httpx_help(help_text):
                return candidate
        return None

    def _httpx_candidates(self) -> list[str]:
        candidates: list[str] = []
        explicit = [
            "pd-httpx",
            "/usr/local/bin/pd-httpx",
            "/usr/local/bin/httpx",
        ]
        preferred = [
            Path.home() / "go" / "bin" / "httpx",
            Path.home() / "go" / "bin" / "pd-httpx",
            Path("/home/ubuntu/go/bin/httpx"),
            Path("/home/ubuntu/go/bin/pd-httpx"),
            Path("/usr/local/bin/pd-httpx"),
            Path("/usr/local/bin/httpx"),
            Path("/usr/bin/httpx"),
        ]

        for name in explicit:
            resolved = self.runner.resolve_binary(name)
            if resolved:
                candidates.append(resolved)

        for candidate in preferred:
            if candidate.exists():
                candidates.append(str(candidate))

        seen: set[str] = set()
        ordered: list[str] = []
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                ordered.append(candidate)
        return ordered

    @staticmethod
    def _is_projectdiscovery_httpx_help(help_text: str) -> bool:
        return (
            "httpx is a fast and multi-purpose http toolkit" in help_text
            or "retryablehttp library" in help_text
            or (
                ("http toolkit" in help_text or "projectdiscovery" in help_text)
                and "-json" in help_text
                and "-tech-detect" in help_text
            )
        )

    def _build_url_list(self) -> list[str]:
        subdomains = self.ctx.get("subdomains", [self.target])
        port_list = self._candidate_ports()
        service_map = self._service_map()
        urls: list[str] = []

        for sub in subdomains[:100]:
            for port in port_list:
                if port in self.HTTPS_PORTS:
                    url = f"https://{sub}" if port == 443 else f"https://{sub}:{port}"
                elif port in self.HTTP_PORTS:
                    url = f"http://{sub}" if port == 80 else f"http://{sub}:{port}"
                else:
                    service_name = service_map.get(port, "")
                    if self._looks_like_https(service_name):
                        url = f"https://{sub}:{port}"
                    elif self._looks_like_http(service_name):
                        url = f"http://{sub}:{port}"
                    else:
                        urls.append(f"http://{sub}:{port}")
                        url = f"https://{sub}:{port}"
                urls.append(url)

        # Fallback CDN Bypass: Include direct origin IP URLs
        active_origin_ip = self.ctx.get("active_origin_ip")
        if active_origin_ip:
            self.log.info(f"[HTTPProbe] Adding fallback CDN bypass probes for origin IP: {active_origin_ip}")
            for port in port_list:
                if port in self.HTTPS_PORTS:
                    urls.append(f"https://{active_origin_ip}" if port == 443 else f"https://{active_origin_ip}:{port}")
                elif port in self.HTTP_PORTS:
                    urls.append(f"http://{active_origin_ip}" if port == 80 else f"http://{active_origin_ip}:{port}")

        seen: set[str] = set()
        out: list[str] = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                out.append(url)
        return out[:self.MAX_URLS]

    def _candidate_ports(self) -> list[int]:
        service_ports: list[int] = []
        for service in self.ctx.get("services", [])[:200]:
            port = service.get("port")
            if not isinstance(port, int):
                continue

            service_name = str(service.get("service", "")).lower()
            version = str(service.get("version", "")).lower()
            if (
                port in self.HTTPS_PORTS
                or port in self.HTTP_PORTS
                or self._looks_like_http(service_name)
                or self._looks_like_https(service_name)
                or "apache" in version
                or "nginx" in version
                or "iis" in version
                or "tomcat" in version
                or "jetty" in version
                or "caddy" in version
            ):
                service_ports.append(port)

        if service_ports:
            return self._dedupe_ports(service_ports)[:self.MAX_PORT_CANDIDATES]

        known_ports = [
            port
            for port in self.ctx.get("port_list", [80, 443])
            if port in self.HTTPS_PORTS or port in self.HTTP_PORTS
        ]
        if known_ports:
            return self._dedupe_ports(known_ports)[:self.MAX_PORT_CANDIDATES]

        return [443, 80]

    def _service_map(self) -> dict[int, str]:
        mapping: dict[int, str] = {}
        for service in self.ctx.get("services", [])[:200]:
            port = service.get("port")
            if isinstance(port, int) and port not in mapping:
                mapping[port] = str(service.get("service", "")).lower()
        return mapping

    @staticmethod
    def _dedupe_ports(ports: list[int]) -> list[int]:
        seen: set[int] = set()
        deduped: list[int] = []
        for port in ports:
            if port not in seen:
                seen.add(port)
                deduped.append(port)
        return deduped

    @staticmethod
    def _looks_like_http(service_name: str) -> bool:
        lowered = service_name.lower()
        return "http" in lowered or lowered in {"www", "http-proxy", "sun-answerbook"}

    @staticmethod
    def _looks_like_https(service_name: str) -> bool:
        lowered = service_name.lower()
        return "https" in lowered or "ssl/http" in lowered or "tls/http" in lowered

    async def _run_httpx(self, urls_file: Path) -> None:
        cfg = self.config
        json_out = self.temp_file("httpx_output.json")
        httpx_binary = self.ctx.get("httpx_binary", "httpx")

        cmd = [
            httpx_binary,
            "-list",
            str(urls_file),
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-web-server",
            "-follow-redirects",
            "-threads",
            str(cfg.httpx_threads),
            "-timeout",
            str(cfg.httpx_timeout),
            "-rate-limit",
            str(cfg.httpx_rate_limit),
            "-o",
            str(json_out),
        ]

        custom_cookies = self.ctx.get("custom_cookies")
        custom_headers = self.ctx.get("custom_headers")
        if custom_cookies:
            cmd.extend(["-H", f"Cookie: {custom_cookies}"])
        if custom_headers:
            for header in str(custom_headers).splitlines():
                if header.strip():
                    cmd.extend(["-H", header.strip()])

        result = await self.runner.run(
            cmd=cmd,
            timeout=cfg.httpx_timeout * 20,
        )
        self.log_result(result)

        if not result.success:
            error = result.stderr.strip() or f"return code {result.returncode}"
            self.add_tool_error(f"httpx failed: {error}")
            await self._curl_fallback(self.read_lines(urls_file))
            if not self.ctx.get("live_hosts"):
                self.set_stage_error(
                    "HTTP probing failed and curl fallback found no live hosts."
                )
            return

        from parser.httpx_parser import HttpxParser

        parser = HttpxParser()
        source = result.stdout or (
            json_out.read_text(encoding="utf-8", errors="replace")
            if json_out.exists() else ""
        )
        parsed = parser.parse(source)
        self._store_results(parsed)

    async def _curl_fallback(self, urls: list[str]) -> None:
        import asyncio

        live: list[dict] = []
        seen_urls: set[str] = set()
        urls = urls[:60]

        async def probe(url: str) -> None:
            res = await self.runner.run(
                cmd=[
                    "curl",
                    "-s",
                    "-o",
                    os.devnull,
                    "-w",
                    "%{http_code}|%{url_effective}",
                    "-L",
                    "--max-time",
                    "10",
                    "-k",
                    url,
                ],
                timeout=15,
            )
            if res.success and "|" in res.stdout:
                code_str, final_url = res.stdout.split("|", 1)
                if code_str.isdigit() and int(code_str) > 0:
                    final_url = final_url.strip()
                    if final_url in seen_urls:
                        return
                    seen_urls.add(final_url)
                    live.append({
                        "url": final_url,
                        "status_code": int(code_str),
                        "title": "",
                        "technologies": [],
                        "web_server": "",
                        "content_length": 0,
                    })

        await asyncio.gather(*[probe(url) for url in urls])
        self._store_results({
            "live_hosts": live,
            "technologies": [],
            "web_servers": [],
        })

    def _store_results(self, parsed: dict) -> None:
        live_hosts = parsed.get("live_hosts", [])
        technologies = parsed.get("technologies", [])
        web_servers = parsed.get("web_servers", [])

        self.ctx["live_hosts"] = live_hosts
        self.ctx["technologies"] = technologies
        self.ctx["web_servers"] = web_servers

        live_urls = [host["url"] for host in live_hosts]
        if not live_urls:
            live_urls = self._fallback_scan_urls()

        live_file = self.temp_file("live_urls.txt")
        self.write_lines(live_file, live_urls)
        self.ctx["live_urls_file"] = live_file

        self.log.info(
            f"[HTTPProbe] {len(live_hosts)} live hosts, "
            f"tech: {technologies[:5]}, "
            f"servers: {web_servers[:3]}"
        )

    def _fallback_scan_urls(self) -> list[str]:
        port_list = self._candidate_ports()
        candidates: list[str] = []

        if 443 in port_list:
            candidates.append(f"https://{self.target}")
        if 80 in port_list:
            candidates.append(f"http://{self.target}")

        for port in port_list:
            if port in self.HTTPS_PORTS and port != 443:
                candidates.append(f"https://{self.target}:{port}")
            elif port in self.HTTP_PORTS and port != 80:
                candidates.append(f"http://{self.target}:{port}")

        if not candidates:
            candidates = [f"https://{self.target}", f"http://{self.target}"]

        seen: set[str] = set()
        deduped: list[str] = []
        for url in candidates:
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        return deduped[:20]

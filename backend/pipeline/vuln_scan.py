"""
PentestBot v2 - Vulnerability Scan Stage
Runs Nuclei (template-based) and Nikto (web server checks) in parallel.
"""

import asyncio
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from pipeline.base_stage import BaseStage


class VulnScanStage(BaseStage):
    """
    Stage 7: Vulnerability Scanning

    Nuclei: fast template-based scanning across all live endpoints.
    Nikto: deep web server misconfiguration scanning on the primary target.

    Both are run concurrently to save time.
    """

    NAME = "VulnScan"
    MAX_NUCLEI_TARGETS = 4  # Default; overridden by deep mode via ctx
    NIKTO_NOISE_MARKERS = (
        "no cgi directories found",
        "cgi tests skipped",
        "scan terminated:",
        "host(s) tested",
        "start time:",
        "end time:",
        "target ip:",
        "target hostname:",
        "target port:",
        "platform:",
        "server:",
        "multiple ips found:",
        "error:",
        "consider using mitmproxy",
        "cannot test http/3 over quic",
        "uncommon header",
        "allowed http methods",
        "strict-transport-security",
        "x-frame-options",
        "content-security-policy",
    )
    NUCLEI_EXCLUDED_TEMPLATE_IDS = {
        "rdap-whois",
        "dns-waf-detect",
        "dns-caa",
        "dns-ns",
        "dns-mx",
        "dns-soa",
        "ssl-dns-names",
        "ssl-issuer",
        "tls-version",
        "http-missing-security-headers",
    }
    NUCLEI_EXCLUDED_NAME_FRAGMENTS = (
        "rdap whois",
        "ns record",
        "mx record",
        "soa record",
        "caa record",
        "ssl dns names",
        "detect ssl certificate issuer",
        "tls version",
        "http missing security headers",
        "dns waf detection",
    )

    async def run(self) -> None:
        self.clear_stage_error()
        live_urls_file = self.ctx.get("discovered_urls_file") or self.ctx.get("live_urls_file")
        live_hosts = self.ctx.get("live_hosts", [])

        if not live_urls_file or not live_urls_file.exists():
            live_urls_file = self.temp_file("live_urls.txt")
            urls = [host["url"] for host in live_hosts] or self._candidate_urls()
            self.write_lines(live_urls_file, urls)

        primary_url = self._pick_primary_url(live_hosts, live_urls_file)

        self.log.info("[VulnScan] Starting Nuclei + Nikto + SQLMap + Dalfox in parallel")
        self.log.info(f"[VulnScan] Primary URL: {primary_url}")

        # Set dynamic nuclei target count from scan profile
        if self.ctx.get("scan_mode") == "deep":
            from scan_profiles import DEEP_MAX_NUCLEI_TARGETS
            self.ctx["max_nuclei_targets"] = DEEP_MAX_NUCLEI_TARGETS

        nuclei_task = self._run_nuclei(live_urls_file)
        nikto_task = self._run_nikto(primary_url)
        sqlmap_task = self._run_sqlmap(live_urls_file)
        dalfox_task = self._run_dalfox(live_urls_file)
        s3scanner_task = self._run_s3scanner()

        # Conditionally run CMS-specific tools when detected and enabled.
        cms_tasks = self._get_cms_scan_tasks(primary_url)

        all_tasks = [nuclei_task, nikto_task, sqlmap_task, dalfox_task, s3scanner_task] + cms_tasks
        all_results = await asyncio.gather(
            *all_tasks,
            return_exceptions=True,
        )

        nuclei_result = all_results[0]
        nikto_result = all_results[1]
        sqlmap_result = all_results[2]
        dalfox_result = all_results[3]
        s3scanner_result = all_results[4]

        if isinstance(nuclei_result, Exception):
            self.log.error(f"[VulnScan] Nuclei failed: {nuclei_result}")
            self.add_tool_error(f"nuclei failed: {nuclei_result}")
        if isinstance(nikto_result, Exception):
            self.log.error(f"[VulnScan] Nikto failed: {nikto_result}")
            self.add_tool_error(f"nikto failed: {nikto_result}")
        if isinstance(sqlmap_result, Exception):
            self.log.error(f"[VulnScan] SQLMap failed: {sqlmap_result}")
            self.add_tool_error(f"sqlmap failed: {sqlmap_result}")
        if isinstance(dalfox_result, Exception):
            self.log.error(f"[VulnScan] Dalfox failed: {dalfox_result}")
            self.add_tool_error(f"dalfox failed: {dalfox_result}")
        if isinstance(s3scanner_result, Exception):
            self.log.error(f"[VulnScan] S3Scanner failed: {s3scanner_result}")
            self.add_tool_error(f"s3scanner failed: {s3scanner_result}")

        # Log CMS tool errors
        for i, cms_result in enumerate(all_results[5:]):
            if isinstance(cms_result, Exception):
                self.log.warning(f"[VulnScan] CMS tool {i} failed: {cms_result}")
                self.add_tool_error(f"CMS scan failed: {cms_result}")

        from parser.nuclei_parser import NucleiParser

        parser = NucleiParser()
        nuclei_raw = self.ctx.get("nuclei_raw", "")
        nuclei_parsed = parser.parse(nuclei_raw)
        filtered_nuclei = [
            finding
            for finding in nuclei_parsed.get("findings", [])
            if self._is_reportable_nuclei_finding(finding)
        ]
        self.ctx["nuclei_findings"] = filtered_nuclei
        self.ctx["nuclei_findings_count"] = len(filtered_nuclei)
        self.ctx["nuclei_by_severity"] = nuclei_parsed.get("by_severity", {})

        if self.ctx.get("nuclei_error") and self.ctx.get("nikto_error"):
            self.set_stage_error(
                "Both nuclei and nikto failed; vulnerability coverage is incomplete."
            )

        self.log.info(
            f"[VulnScan] Nuclei: {self.ctx['nuclei_findings_count']} reportable findings | "
            f"Nikto: {len(self.ctx.get('nikto_findings', []))} findings | "
            f"Dalfox: {len(self.ctx.get('dalfox_findings', []))} findings | "
            f"S3Scanner: {len(self.ctx.get('s3_findings', []))} findings"
        )

    async def _run_nuclei(self, urls_file: Path) -> None:
        if not self.runner.which("nuclei"):
            self.log.warning("[VulnScan] nuclei not found - skipping")
            self.ctx["nuclei_raw"] = ""
            self.ctx["nuclei_error"] = "binary not found"
            self.add_tool_error("nuclei binary not found.")
            return

        templates_arg = self._resolve_nuclei_templates()
        if not templates_arg:
            templates_arg = await self._ensure_nuclei_templates()

        if not templates_arg:
            error = "nuclei templates unavailable after update attempts"
            self.log.warning(f"[VulnScan] {error} - skipping nuclei")
            self.ctx["nuclei_raw"] = ""
            self.ctx["nuclei_error"] = error
            self.add_tool_error(error)
            return

        self.log.info(f"[VulnScan] Using nuclei templates: {templates_arg}")

        cfg = self.config
        nuclei_urls_file = self._prepare_nuclei_urls(urls_file)
        json_flags = self._nuclei_json_flags()
        base_cmd = [
            "nuclei",
            "-l",
            str(nuclei_urls_file),
            "-silent",
            "-severity",
            cfg.nuclei_severity,
            "-rate-limit",
            str(cfg.nuclei_rate_limit),
            "-c",
            "15",
            "-bulk-size",
            "10",
            "-duc",
            "-no-color",
            "-system-resolvers",
        ]

        base_cmd.extend(["-t", templates_arg])

        # Inject dynamic cookies and custom headers for authenticated nuclei scanning
        custom_cookies = self.ctx.get("custom_cookies")
        custom_headers = self.ctx.get("custom_headers")
        if custom_cookies:
            base_cmd.extend(["-H", f"Cookie: {custom_cookies}"])
        if custom_headers:
            for header in str(custom_headers).splitlines():
                if header.strip():
                    base_cmd.extend(["-H", header.strip()])

        result = None
        attempted_flags: list[str] = []
        for json_flag in json_flags:
            attempted_flags.append(json_flag)
            cmd = list(base_cmd)
            cmd.insert(4, json_flag)
            self.log.info(f"[VulnScan] Running nuclei with output flag: {json_flag}")
            result = await self.runner.run(cmd=cmd, timeout=cfg.nuclei_timeout)
            self.log_result(result)
            if result.success:
                break
            self.log.warning(
                f"[VulnScan] nuclei attempt with {json_flag} failed: "
                f"{self._format_tool_error(result)}"
            )
            if result.timed_out:
                break

        assert result is not None
        self.ctx["nuclei_raw"] = result.stdout
        if result.success:
            self.ctx.pop("nuclei_error", None)
            return

        error = self._format_tool_error(result)
        error = f"{error} (tried: {', '.join(attempted_flags)})"
        self.ctx["nuclei_error"] = error
        self.add_tool_error(f"nuclei failed: {error}")
        if result.timed_out:
            self.add_tool_error(
                "nuclei scan timed out; vulnerability coverage may be incomplete."
            )

    async def _run_nikto(self, target_url: str) -> None:
        if not getattr(self.config, "enable_nikto", False):
            self.log.info("[VulnScan] Nikto disabled by configuration")
            self.ctx["nikto_raw"] = ""
            self.ctx["nikto_findings"] = []
            self.ctx["nikto_error"] = "disabled by configuration"
            return

        if not self.runner.which("nikto"):
            self.log.warning("[VulnScan] nikto not found - skipping")
            self.ctx["nikto_raw"] = ""
            self.ctx["nikto_findings"] = []
            self.ctx["nikto_error"] = "binary not found"
            self.add_tool_error("nikto binary not found.")
            return

        host = target_url
        port = "80"
        ssl = False

        if target_url.startswith("https://"):
            host = target_url.replace("https://", "")
            port = "443"
            ssl = True
        elif target_url.startswith("http://"):
            host = target_url.replace("http://", "")

        host = host.rstrip("/").split("/")[0]
        if ":" in host:
            host, port = host.rsplit(":", 1)

        cmd = [
            "nikto",
            "-host",
            host,
            "-port",
            port,
            "-ask",
            "no",
            "-nointeractive",
            "-Tuning",
            "1234578",
	    "-maxtime",
	    "10m",
        ]
        if ssl:
            cmd.append("-ssl")

        # Origin IP CDN Bypass support for Nikto
        if self.ctx.get("active_origin_ip"):
            cmd.extend(["-vhost", self.target])
            self.log.info(f"[VulnScan] Nikto using -vhost {self.target} for origin bypass")

        result = await self.runner.run(cmd=cmd, timeout=self.config.nikto_timeout)
        self.log_result(result)

        raw = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
        self.ctx["nikto_raw"] = raw
        self._parse_nikto(raw)
        if result.success:
            self.ctx.pop("nikto_error", None)
            return

        error = self._format_tool_error(result)
        self.ctx["nikto_error"] = error
        self.add_tool_error(f"nikto failed: {error}")

    async def _run_sqlmap(self, urls_file: Path) -> None:
        if not getattr(self.config, "enable_sqlmap", False):
            self.log.info("[VulnScan] SQLMap disabled by configuration")
            self.ctx["sqlmap_raw"] = ""
            self.ctx["sqlmap_findings"] = []
            return

        if not self.runner.which("sqlmap"):
            self.log.warning("[VulnScan] sqlmap not found - skipping")
            self.ctx["sqlmap_raw"] = ""
            self.ctx["sqlmap_findings"] = []
            self.add_tool_error("sqlmap binary not found.")
            return

        sqlmap_urls_file = self._prepare_parameterized_urls(
            urls_file,
            "sqlmap_urls.txt",
            max_per_host=10,
        )
        target_count = len(self.read_lines(sqlmap_urls_file))
        if target_count == 0:
            self.log.info("[VulnScan] SQLMap skipped - no parameterized URLs found")
            self.ctx["sqlmap_raw"] = ""
            self.ctx["sqlmap_findings"] = []
            return

        self.log.info(f"[VulnScan] Running SQLMap on {target_count} parameterized URL(s)")
        cmd = [
            "sqlmap",
            "-m", str(sqlmap_urls_file),
            "--batch",
            "--random-agent",
            "--smart",
            "--level=1",
            "--risk=1",
            "--forms",
            "--threads=10"
        ]

        # Inject dynamic cookies and custom headers for authenticated SQLMap scanning
        custom_cookies = self.ctx.get("custom_cookies")
        custom_headers = self.ctx.get("custom_headers")
        if custom_cookies:
            cmd.extend(["--cookie", str(custom_cookies)])
        if custom_headers:
            cmd.extend(["--headers", str(custom_headers)])

        result = await self.runner.run(cmd=cmd, timeout=getattr(self.config, "sqlmap_timeout", 600))
        self.log_result(result)

        raw = result.stdout.strip()
        self.ctx["sqlmap_raw"] = raw
        
        findings = []
        is_vulnerable = "sqlmap identified the following injection point(s)" in raw.lower() or "is vulnerable" in raw.lower()
        
        if is_vulnerable:
            for line in raw.splitlines():
                if "parameter" in line.lower() and "is vulnerable" in line.lower() and "not" not in line.lower():
                    findings.append({
                        "description": line.strip(),
                        "severity": "high",
                        "source": "sqlmap"
                    })
            if not findings:
                findings.append({
                    "description": "SQLMap identified a potential SQL Injection vulnerability (see raw output for details).",
                    "severity": "high",
                    "source": "sqlmap"
                })
        self.ctx["sqlmap_findings"] = findings

    async def _run_dalfox(self, urls_file: Path) -> None:
        if not getattr(self.config, "enable_dalfox", False):
            self.log.info("[VulnScan] Dalfox disabled by configuration")
            self.ctx["dalfox_raw"] = ""
            self.ctx["dalfox_findings"] = []
            return

        if not self.runner.which("dalfox"):
            self.log.warning("[VulnScan] dalfox not found - skipping")
            self.ctx["dalfox_raw"] = ""
            self.ctx["dalfox_findings"] = []
            self.add_tool_error("dalfox binary not found.")
            return

        parameterized_file = self._prepare_dalfox_urls(urls_file)
        target_count = len(self.read_lines(parameterized_file))
        if target_count == 0:
            self.log.info("[VulnScan] Dalfox skipped - no parameterized URLs found")
            self.ctx["dalfox_raw"] = ""
            self.ctx["dalfox_findings"] = []
            return

        self.log.info(f"[VulnScan] Running Dalfox on {target_count} parameterized URL(s)")
        worker_count = max(1, int(getattr(self.config, "dalfox_workers", 20)))
        deep_domxss = self.ctx.get("scan_mode") == "deep" or getattr(self.config, "dalfox_deep_scan", False)
        cmd = [
            "dalfox",
            "file",
            str(parameterized_file),
            "--format",
            "json",
            "--silence",
            "--no-color",
            "--worker",
            str(worker_count),
            "--timeout",
            str(max(1, int(getattr(self.config, "dalfox_request_timeout", 10)))),
	    "--skip-headless",
	    "--skip-mining-dom"
        ]

        if deep_domxss:
            cmd.append("--deep-domxss")

        custom_cookies = self.ctx.get("custom_cookies")
        custom_headers = self.ctx.get("custom_headers")
        if custom_cookies:
            cmd.extend(["-C", str(custom_cookies)])
        if custom_headers:
            for header in str(custom_headers).splitlines():
                if header.strip():
                    cmd.extend(["-H", header.strip()])

        dalfox_timeout = max(1, int(getattr(self.config, "dalfox_timeout", 600)))
        result = await self.runner.run(
            cmd=cmd,
            timeout=dalfox_timeout,
        )
        raw = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
        dalfox_chromedp_panic = self._is_dalfox_chromedp_panic(raw)
        self._log_dalfox_result(result, dalfox_chromedp_panic)

        if (
            not result.success
            and dalfox_chromedp_panic
            and (deep_domxss or worker_count > 1)
        ):
            self.log.warning(
                "[VulnScan] Dalfox crashed in browser-backed scanning; "
                "retrying once with DOM checks disabled and worker=1"
            )
            retry_cmd = [part for part in cmd if part != "--deep-domxss"]
            if "--worker" in retry_cmd:
                worker_index = retry_cmd.index("--worker") + 1
                if worker_index < len(retry_cmd):
                    retry_cmd[worker_index] = "1"

            retry_result = await self.runner.run(cmd=retry_cmd, timeout=dalfox_timeout)
            retry_raw = "\n".join(
                part for part in (retry_result.stdout, retry_result.stderr) if part
            ).strip()
            retry_chromedp_panic = self._is_dalfox_chromedp_panic(retry_raw)
            self._log_dalfox_result(retry_result, retry_chromedp_panic)

            if retry_result.success or self._parse_dalfox(retry_raw):
                result = retry_result
                raw = retry_raw
                dalfox_chromedp_panic = retry_chromedp_panic
            elif retry_chromedp_panic:
                result = retry_result
                raw = retry_raw
                dalfox_chromedp_panic = True

        self.ctx["dalfox_raw"] = self._sanitize_dalfox_raw(raw)
        self.ctx["dalfox_findings"] = self._parse_dalfox(raw)

        if dalfox_chromedp_panic and not self.ctx["dalfox_findings"]:
            friendly_error = (
                "Dalfox hit a known upstream chromedp/browser panic and was skipped "
                "after a conservative retry. Other vulnerability scanners continued."
            )
            self.ctx["dalfox_error"] = friendly_error
            self.log.warning(f"[VulnScan] {friendly_error}")
            return

        if not result.success and not self.ctx["dalfox_findings"]:
            error = self._format_tool_error(result)
            self.ctx["dalfox_error"] = error
            self.add_tool_error(f"dalfox failed: {error}")
        else:
            self.ctx.pop("dalfox_error", None)

    def _log_dalfox_result(self, result, chromedp_panic: bool) -> None:
        if chromedp_panic:
            stderr = (
                "Dalfox crashed in its browser-backed chromedp scanner "
                "(panic: close of closed channel)."
            )
            self.log.warning(f"[VulnScan] {stderr}")
            self.ctx.setdefault("raw_outputs", []).append({
                "tool_name": Path(result.command[0]).name,
                "stage_name": self.NAME,
                "status": "skipped",
                "stdout": "",
                "stderr": stderr,
                "duration": result.duration,
            })
            return
        self.log_result(result)

    def _sanitize_dalfox_raw(self, raw: str) -> str:
        if self._is_dalfox_chromedp_panic(raw):
            return (
                "Dalfox crashed in its browser-backed chromedp scanner "
                "(panic: close of closed channel)."
            )
        return raw

    @staticmethod
    def _is_dalfox_chromedp_panic(raw: str) -> bool:
        lowered = raw.lower()
        return (
            "panic: close of closed channel" in lowered
            or "chromedp.(*execallocator)" in lowered
        )

    def _prepare_dalfox_urls(self, urls_file: Path) -> Path:
        return self._prepare_parameterized_urls(
            urls_file,
            "dalfox_urls.txt",
            max_per_host=max(1, int(getattr(self.config, "dalfox_max_targets_per_host", 30))),
        )

    def _prepare_parameterized_urls(self, urls_file: Path, filename: str, max_per_host: int) -> Path:
        counts_by_host: dict[str, int] = {}
        urls = []
        for url in self.read_lines(urls_file):
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            if not parse_qsl(parsed.query, keep_blank_values=True):
                continue
            host_key = parsed.netloc.lower()
            if counts_by_host.get(host_key, 0) >= max_per_host:
                continue
            counts_by_host[host_key] = counts_by_host.get(host_key, 0) + 1
            urls.append(url)

        output_file = self.temp_file(filename)
        self.write_lines(output_file, list(dict.fromkeys(urls)))
        return output_file

    def _parse_dalfox(self, raw: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()

        for item in self._iter_dalfox_json(raw):
            if not isinstance(item, dict):
                continue

            finding_type = str(
                item.get("type")
                or item.get("vulnerability")
                or item.get("category")
                or item.get("class")
                or "xss"
            ).strip()
            url = str(
                item.get("url")
                or item.get("data")
                or item.get("target")
                or item.get("poc")
                or self.target
            ).strip()
            param = str(item.get("param") or item.get("parameter") or "").strip()
            payload = str(item.get("payload") or item.get("evidence") or "").strip()
            evidence = str(item.get("evidence") or item.get("poc") or payload or "").strip()

            lowered = " ".join([finding_type, str(item.get("message", "")), evidence]).lower()
            if not any(token in lowered for token in ("xss", "vulnerable", "verified", "reflected", "dom")):
                continue

            key = "|".join([finding_type.lower(), url, param, payload])
            if key in seen:
                continue
            seen.add(key)

            severity = "high" if any(token in lowered for token in ("verified", "vulnerable", "xss")) else "medium"
            title_suffix = f" in parameter '{param}'" if param else ""
            findings.append({
                "title": f"Cross-Site Scripting{title_suffix}",
                "description": self._dalfox_description(finding_type, url, param, evidence),
                "severity": severity,
                "url": url,
                "affected": [url],
                "source": "dalfox",
                "extra": {
                    "kind": "dalfox",
                    "type": finding_type,
                    "parameter": param,
                    "payload": payload,
                    "evidence": evidence,
                },
            })

        return findings

    @staticmethod
    def _iter_dalfox_json(raw: str):
        text = raw.strip()
        if not text:
            return

        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                for item in parsed:
                    yield item
            elif isinstance(parsed, dict):
                nested = parsed.get("data") or parsed.get("results") or parsed.get("findings")
                if isinstance(nested, list):
                    for item in nested:
                        yield item
                else:
                    yield parsed
            return
        except Exception:
            pass

        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue

    @staticmethod
    def _dalfox_description(finding_type: str, url: str, param: str, evidence: str) -> str:
        parts = [
            f"Dalfox identified a potential cross-site scripting issue of type '{finding_type}' at {url}."
        ]
        if param:
            parts.append(f"The affected parameter is '{param}'.")
        if evidence:
            parts.append(f"Evidence or payload excerpt: {evidence[:300]}")
        parts.append("Manual validation is recommended before exploitation assumptions are made.")
        return " ".join(parts)

    async def _run_s3scanner(self) -> None:
        if not getattr(self.config, "enable_s3scanner", False):
            self.log.info("[VulnScan] S3Scanner disabled by configuration")
            self.ctx["s3scanner_raw"] = ""
            self.ctx["s3_findings"] = []
            return

        if not self.runner.which("s3scanner"):
            self.log.warning("[VulnScan] s3scanner not found - skipping")
            self.ctx["s3scanner_raw"] = ""
            self.ctx["s3_findings"] = []
            self.add_tool_error("s3scanner binary not found.")
            return

        bucket_file = self._prepare_s3_bucket_candidates()
        candidates = self.read_lines(bucket_file)
        if not candidates:
            self.ctx["s3scanner_raw"] = ""
            self.ctx["s3_findings"] = []
            return

        self.log.info(f"[VulnScan] Running S3Scanner on {len(candidates)} bucket candidate(s)")
        timeout = int(getattr(self.config, "s3scanner_timeout", 240))
        commands = [
            # Python/PyPI s3scanner 2.x
            ["s3scanner", "scan", "--buckets-file", str(bucket_file)],
            # Go sa7mon/s3scanner
            ["s3scanner", "-bucket-file", str(bucket_file), "-threads", "8"],
            ["s3scanner", "-bucket-file", str(bucket_file)],
            # Legacy Python variants
            ["s3scanner", "-f", str(bucket_file)],
        ]

        last_result = None
        for cmd in commands:
            result = await self.runner.run(cmd=cmd, timeout=timeout)
            self.log_result(result)
            last_result = result
            if result.success or result.stdout:
                break

        if last_result is None:
            self.ctx["s3scanner_raw"] = ""
            self.ctx["s3_findings"] = []
            return

        raw = "\n".join(part for part in (last_result.stdout, last_result.stderr) if part).strip()
        self.ctx["s3scanner_raw"] = raw
        self.ctx["s3_findings"] = self._parse_s3scanner(raw)

        if not last_result.success and not self.ctx["s3_findings"]:
            self.add_tool_error(f"s3scanner failed: {self._format_tool_error(last_result)}")

    def _prepare_s3_bucket_candidates(self) -> Path:
        values: list[str] = []
        hostnames = [self.target]
        hostnames.extend(self.ctx.get("subdomains", [])[:50])

        for host in hostnames:
            clean = str(host).strip().lower().removeprefix("www.")
            if not clean:
                continue
            dashed = clean.replace(".", "-")
            compact = clean.replace(".", "")
            values.extend([clean, dashed, compact])

        valid = []
        for value in values:
            candidate = value.strip("-.")
            if self._is_valid_s3_bucket_name(candidate):
                valid.append(candidate)

        path = self.temp_file("s3_bucket_candidates.txt")
        self.write_lines(path, list(dict.fromkeys(valid))[:75])
        return path

    @staticmethod
    def _is_valid_s3_bucket_name(name: str) -> bool:
        import re
        if len(name) < 3 or len(name) > 63:
            return False
        if not re.match(r"^[a-z0-9][a-z0-9.-]+[a-z0-9]$", name):
            return False
        if ".." in name or ".-" in name or "-." in name:
            return False
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
            return False
        return True

    def _parse_s3scanner(self, raw: str) -> list[dict]:
        findings = []
        seen: set[str] = set()
        for line in raw.splitlines():
            text = line.strip()
            lowered = text.lower()
            if not text:
                continue
            if not any(token in lowered for token in ("public", "open", "read", "write", "list", "vulnerable", "exposed")):
                continue
            if any(token in lowered for token in ("not public", "not vulnerable", "access denied", "does not exist", "not found")):
                continue

            bucket = self._bucket_from_s3_line(text)
            key = bucket or text
            if key in seen:
                continue
            seen.add(key)
            affected = [bucket] if bucket else [self.target]
            findings.append({
                "title": f"Potentially Exposed S3 Bucket{f': {bucket}' if bucket else ''}",
                "severity": "high" if "write" in lowered else "medium",
                "description": f"S3Scanner reported possible public bucket exposure: {text}",
                "affected": affected,
                "source": "s3scanner",
                "extra": {"kind": "s3scanner", "raw": text, "bucket": bucket or ""},
            })
        return findings

    @staticmethod
    def _bucket_from_s3_line(line: str) -> str:
        import re
        match = re.search(r"(?:s3://)?([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])", line.lower())
        return match.group(1) if match else ""

    def _parse_nikto(self, raw: str) -> None:
        findings = []
        seen: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("+ "):
                continue
            content = line[2:].strip()
            if not content or "No web server found" in content:
                continue

            severity = "info"
            lowered = content.lower()
            if any(marker in lowered for marker in self.NIKTO_NOISE_MARKERS):
                continue
            if any(token in lowered for token in [
                "vuln",
                "xss",
                "sql inject",
                "rce",
                "remote code",
                "cve-",
                "command injection",
                "path traversal",
                "file disclosure",
            ]):
                severity = "medium"
            if any(token in lowered for token in [
                "critical",
                "arbitrary",
                "remote code execution",
                "authentication bypass",
                "sql injection",
            ]):
                severity = "high"
            if severity == "info":
                continue
            if content in seen:
                continue
            seen.add(content)

            findings.append({
                "description": content,
                "severity": severity,
                "source": "nikto",
            })
        self.ctx["nikto_findings"] = findings

    def _is_reportable_nuclei_finding(self, finding: dict) -> bool:
        severity = str(finding.get("severity", "info")).lower()
        if severity not in {"critical", "high", "medium"}:
            return False

        template_id = str(finding.get("template_id", "")).strip().lower()
        if template_id in self.NUCLEI_EXCLUDED_TEMPLATE_IDS:
            return False

        name = str(finding.get("name", "")).strip().lower()
        if any(fragment in name for fragment in self.NUCLEI_EXCLUDED_NAME_FRAGMENTS):
            return False

        description = str(finding.get("description", "")).strip().lower()
        if any(
            marker in description
            for marker in (
                "registration data access protocol",
                "an ns record was detected",
                "an mx record was detected",
                "a caa record was discovered",
                "extract the issuer",
                "subject alternative name",
                "tls version detection",
            )
        ):
            return False

        # Additional safe mode filtering to reduce false positives
        mode = self.ctx.get("scan_mode", "fast")
        if mode == "safe":
            # In safe mode, drop medium-severity findings that are often noisy (default pages, generic detections, etc.)
            # unless they are explicitly validated.
            if severity == "medium" and any(term in name for term in ("default", "generic", "detect", "panel", "info")):
                return False
            # Also drop findings that are often triggered by standard WAF/404 responses
            if "waf" in name or "404" in name or "not found" in name:
                return False

        return True

    def _get_cms_scan_tasks(self, primary_url: str) -> list:
        """Return WPScan/Joomscan tasks if fingerprinting detected the relevant CMS."""
        tasks = []
        technologies = [t.lower() for t in self.ctx.get("technologies", [])]
        fingerprint_techs = [t.lower() for t in self.ctx.get("fingerprint_technologies", [])]
        all_techs = technologies + fingerprint_techs

        if getattr(self.config, "enable_wpscan", False) and any("wordpress" in t for t in all_techs):
            self.log.info("[VulnScan] WordPress detected — queueing WPScan")
            tasks.append(self._run_wpscan(primary_url))

        if getattr(self.config, "enable_joomscan", False) and any("joomla" in t for t in all_techs):
            self.log.info("[VulnScan] Joomla detected — queueing Joomscan")
            tasks.append(self._run_joomscan(primary_url))

        return tasks

    async def _run_wpscan(self, target_url: str) -> None:
        """Run WPScan for WordPress-specific vulnerability detection."""
        if not self.runner.which("wpscan"):
            self.log.warning("[VulnScan] wpscan not found - skipping")
            self.add_tool_error("wpscan binary not found.")
            return

        cmd = [
            "wpscan",
            "--url", target_url,
            "--no-banner",
            "--random-user-agent",
            "--format", "json",
        ]
        result = await self.runner.run(cmd=cmd, timeout=self.config.wpscan_timeout)
        self.log_result(result)

        if result.stdout:
            self.log.info(f"[VulnScan] WPScan complete ({len(result.stdout)} bytes)")
        self.ctx["wpscan_raw"] = result.stdout
        self.ctx["wpscan_findings"] = self._parse_wpscan(result.stdout, target_url)

    async def _run_joomscan(self, target_url: str) -> None:
        """Run Joomscan for Joomla-specific vulnerability detection."""
        if not self.runner.which("joomscan"):
            self.log.warning("[VulnScan] joomscan not found - skipping")
            self.add_tool_error("joomscan binary not found.")
            return

        cmd = ["joomscan", "-u", target_url]
        result = await self.runner.run(cmd=cmd, timeout=self.config.joomscan_timeout)
        self.log_result(result)

        if result.stdout:
            self.log.info(f"[VulnScan] Joomscan complete ({len(result.stdout)} bytes)")
        self.ctx["joomscan_raw"] = result.stdout
        self.ctx["joomscan_findings"] = self._parse_joomscan(result.stdout, target_url)

    def _parse_wpscan(self, raw: str, target_url: str) -> list[dict]:
        findings: list[dict] = []
        try:
            data = json.loads(raw)
        except Exception:
            return findings

        def add_vulns(component: str, vulns: list[dict]) -> None:
            for vuln in vulns or []:
                title = str(vuln.get("title") or vuln.get("cve") or "WordPress Vulnerability")
                references = []
                refs = vuln.get("references") or {}
                if isinstance(refs, dict):
                    for values in refs.values():
                        if isinstance(values, list):
                            references.extend(str(v) for v in values[:3])
                        elif values:
                            references.append(str(values))
                findings.append({
                    "title": title,
                    "severity": "high" if "unauthenticated" in title.lower() or "rce" in title.lower() else "medium",
                    "description": f"WPScan reported a vulnerability in {component}: {title}",
                    "affected": [target_url],
                    "source": "wpscan",
                    "references": references[:5],
                    "extra": {"kind": "wpscan", "component": component},
                })

        for name, item in (data.get("plugins") or {}).items():
            add_vulns(f"plugin {name}", item.get("vulnerabilities") or [])
        for name, item in (data.get("themes") or {}).items():
            add_vulns(f"theme {name}", item.get("vulnerabilities") or [])
        version = data.get("version") or {}
        if isinstance(version, dict):
            add_vulns("WordPress core", version.get("vulnerabilities") or [])
        return findings

    def _parse_joomscan(self, raw: str, target_url: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            text = line.strip()
            lowered = text.lower()
            if not text:
                continue
            if not any(token in lowered for token in ("vulnerable", "cve-", "exploit", "exposed", "backup", "configuration")):
                continue
            if text in seen:
                continue
            seen.add(text)
            findings.append({
                "title": "Joomla Security Finding",
                "severity": "medium",
                "description": f"Joomscan reported: {text}",
                "affected": [target_url],
                "source": "joomscan",
                "extra": {"kind": "joomscan", "raw": text},
            })
        return findings

    def _pick_primary_url(self, live_hosts: list[dict], live_urls_file: Path) -> str:
        if live_hosts:
            return live_hosts[0]["url"]

        urls = self.read_lines(live_urls_file)
        if urls:
            return urls[0]

        return self._candidate_urls()[0]

    @staticmethod
    def _dir_has_templates(path: Path) -> bool:
        """Return True only if the directory exists AND contains nuclei YAML files."""
        if not path.is_dir():
            return False
        try:
            return any(path.rglob("*.yaml")) or any(path.rglob("*.yml"))
        except OSError:
            return False

    @classmethod
    def _first_template_dir(cls, path: Path) -> Path | None:
        expanded = path.expanduser()
        candidates = [
            expanded / "templates",
            expanded / "nuclei-templates",
            expanded,
        ]
        for candidate in candidates:
            if cls._dir_has_templates(candidate):
                return candidate
        return None

    async def _ensure_nuclei_templates(self) -> str | None:
        from config import DATA_DIR

        nuclei_dir = DATA_DIR / "nuclei-templates"
        nuclei_dir.mkdir(parents=True, exist_ok=True)
        self.log.info(f"[VulnScan] nuclei templates missing — downloading to {nuclei_dir}...")

        update_commands = [
            ["nuclei", "-update-templates", "-ud", str(nuclei_dir), "-duc"],
            ["nuclei", "-ut", "-ud", str(nuclei_dir), "-duc"],
            ["nuclei", "-update-templates", "-duc"],
        ]
        for cmd in update_commands:
            dl = await self.runner.run(cmd=cmd, timeout=300)
            if dl.success:
                templates_arg = self._resolve_nuclei_templates()
                if templates_arg:
                    self.log.info("[VulnScan] nuclei templates downloaded successfully")
                    return templates_arg
                self.log.warning(
                    "[VulnScan] nuclei template update exited successfully, "
                    "but no YAML templates were found"
                )
            else:
                self.log.warning(
                    f"[VulnScan] nuclei template download failed with {' '.join(cmd[:2])}: "
                    f"{self._format_tool_error(dl)}"
                )

        return self._resolve_nuclei_templates()

    def _resolve_nuclei_templates(self) -> str | None:
        configured = str(self.config.nuclei_templates or "").strip()
        valid_paths: list[str] = []
        if configured:
            paths = [
                Path(part.strip()).expanduser()
                for part in configured.split(",")
                if part.strip()
            ]
            for path in paths:
                template_dir = self._first_template_dir(path)
                if template_dir:
                    valid_paths.append(str(template_dir))
            if valid_paths:
                return ",".join(valid_paths)

        from config import DATA_DIR
        common_dirs = [
             DATA_DIR / "nuclei-templates",
            # Nuclei v3 default paths
            Path.home() / ".local" / "nuclei" / "templates",
            Path.home() / ".config" / "nuclei" / "templates",
            # Legacy / alternative paths
            Path.home() / "nuclei-templates",
            Path.home() / ".nuclei-templates",
            Path.home() / ".local" / "nuclei-templates",
            Path.home() / ".local" / "share" / "nuclei-templates",
            Path("/home/pentestbot/.local/nuclei/templates"),
            Path("/home/pentestbot/.config/nuclei/templates"),
            Path("/home/ubuntu/nuclei-templates"),
            Path("/home/ubuntu/.nuclei-templates"),
            Path("/home/ubuntu/.local/nuclei-templates"),
            Path("/home/ubuntu/.local/share/nuclei-templates"),
            Path("/usr/local/share/nuclei-templates"),
            Path("/opt/nuclei-templates"),
        ]
        for candidate in common_dirs:
            template_dir = self._first_template_dir(candidate)
            if template_dir:
                return str(template_dir)
        return None

    def _prepare_nuclei_urls(self, urls_file: Path) -> Path:
        urls = self.read_lines(urls_file)
        selected = self._select_nuclei_urls(urls)
        out_file = self.temp_file("nuclei_urls.txt")
        self.write_lines(out_file, selected)
        self.log.info(
            f"[VulnScan] Nuclei target set reduced to {len(selected)} URL(s)"
        )
        return out_file

    def _select_nuclei_urls(self, urls: list[str]) -> list[str]:
        if not urls:
            max_targets = self.ctx.get("max_nuclei_targets", self.MAX_NUCLEI_TARGETS)
            return self._candidate_urls()[:max_targets]

        def score(url: str) -> tuple[int, int, int, str]:
            normalized = url.lower()
            host = normalized.split("://", 1)[-1].split("/", 1)[0]
            hostname = host.split(":", 1)[0]
            is_root = 0 if hostname == self.target else 1
            is_subdomain = 0 if hostname.endswith(f".{self.target}") else 1
            is_https = 0 if normalized.startswith("https://") else 1
            return (is_root, is_subdomain, is_https, normalized)

        ordered = sorted(dict.fromkeys(urls), key=score)
        max_targets = self.ctx.get("max_nuclei_targets", self.MAX_NUCLEI_TARGETS)
        return ordered[:max_targets]

    def _candidate_urls(self) -> list[str]:
        port_list = self.ctx.get("port_list", [80, 443])
        urls: list[str] = []

        if 443 in port_list:
            urls.append(f"https://{self.target}")
        if 80 in port_list:
            urls.append(f"http://{self.target}")

        for port in port_list:
            if port in {80, 443}:
                continue
            if port in {4443, 8443, 9443}:
                urls.append(f"https://{self.target}:{port}")
            elif port in {3000, 5000, 8000, 8080, 8888, 9000, 9090}:
                urls.append(f"http://{self.target}:{port}")

        if not urls:
            urls = [f"https://{self.target}", f"http://{self.target}"]

        seen: set[str] = set()
        deduped: list[str] = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        return deduped[:20]

    def _nuclei_json_flags(self) -> list[str]:
        # Nuclei v3 uses -jsonl for JSON Lines output.
        # Fallback to -je (JSON Events) which also works in v3.
        # Note: -json is a v2 flag and does NOT exist in v3.
        return ["-jsonl", "-je"]

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

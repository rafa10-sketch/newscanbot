"""
PentestBot v2 — Port Scan Stage
Fast, rate-limited port scanning via naabu.
Produces structured open port data for downstream stages.
"""

import json
from pathlib import Path
from pipeline.base_stage import BaseStage


class PortScanStage(BaseStage):
    """
    Stage 4: Port Scanning

    Scans all resolved IPs or origin candidates using naabu.
    Falls back to a simple socket scan if naabu is unavailable.

    Populates:
      ctx['open_ports']       → list[dict]: {host, port}
      ctx['port_list']        → list[int]: sorted unique ports
      ctx['open_ports_file']  → path to temp file with host:port lines
    """

    NAME = "PortScan"

    # Common high-value ports always scanned regardless of top_ports setting
    EXTRA_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445,
        465, 587, 993, 995, 1433, 1521, 2049, 3000, 3306, 3389,
        4443, 5000, 5432, 5900, 6379, 7443, 8000, 8080, 8081,
        8443, 8888, 9000, 9090, 9200, 9443, 27017,
    ]

    async def run(self) -> None:
        # Build target list: prefer origin candidates, fallback to live IPs, then root target
        cdn_only = self.ctx.get("cdn_detected", False) and not self.ctx.get("origin_candidates")

        targets = (
            self.ctx.get("origin_candidates")
            or ([self.target] if self.ctx.get("cdn_detected") else [])
            or self.ctx.get("live_ips")
            or [self.target]
        )
        targets = [t for t in targets if t][:20]  # Cap at 20 IPs

        targets_file = self.temp_file("scan_targets.txt")
        self.write_lines(targets_file, targets)

        self.log.info(f"[PortScan] Scanning {len(targets)} hosts")

        if not self.runner.which("naabu"):
            self.log.warning("[PortScan] naabu not found — using socket fallback")
            await self._socket_fallback(targets)
            return

        await self._run_naabu(targets_file, cdn_only=cdn_only)

    async def _run_naabu(self, targets_file: Path, cdn_only: bool = False) -> None:
        cfg = self.config

        # 1. Determine the rate. 
        # If this is a deep scan (custom ports defined), force a very high rate 
        # to try and beat the job_manager's timeout limit.
        scan_rate = str(cfg.naabu_rate)
        if cfg.naabu_ports:
            self.log.info(f"[PortScan] Deep scan detected (ports: {cfg.naabu_ports}): forcing high scan rate (3000) to beat timeout limit.")
            scan_rate = "3000"

        cmd = [
            "naabu",
            "-l", str(targets_file),
            "-rate", scan_rate,
            "-retries", str(cfg.naabu_retries),
            "-silent",
            "-json",
        ]

        # Only exclude CDN IPs when we have origin IPs to scan.
        # If the target is CDN-only, excluding CDN IPs leaves zero targets.
        if not cdn_only:
            cmd.append("-exclude-cdn")

        if cfg.naabu_ports:
            cmd += ["-p", cfg.naabu_ports]
        else:
            # Scan top N ports + our extra list
            extra_str = ",".join(str(p) for p in self.EXTRA_PORTS)
            cmd += ["-top-ports", str(cfg.naabu_top_ports), "-p", extra_str]

        # 2. Execute Naabu
        result = await self.runner.run(
            cmd=cmd,
            timeout=cfg.naabu_timeout,
        )
        self.log_result(result)
        self._parse_and_store(result.stdout)

    def _parse_and_store(self, raw_output: str) -> None:
        open_ports: list[dict] = []
        seen: set[tuple] = set()

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            # JSON mode: {"ip":"1.2.3.4","port":80,"protocol":"tcp"}
            if line.startswith("{"):
                try:
                    entry = json.loads(line)
                    host = entry.get("ip") or entry.get("host", self.target)
                    port = entry.get("port")
                    if port and (host, port) not in seen:
                        seen.add((host, port))
                        open_ports.append({"host": host, "port": int(port)})
                    continue
                except json.JSONDecodeError:
                    pass

            # Plain text: host:port
            if ":" in line:
                parts = line.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    host, port_str = parts[0], int(parts[1])
                    if (host, port_str) not in seen:
                        seen.add((host, port_str))
                        open_ports.append({"host": host, "port": port_str})

        port_numbers = sorted({e["port"] for e in open_ports})
        self.ctx["open_ports"]  = open_ports
        self.ctx["port_list"]   = port_numbers

        # Write host:port file for nmap
        lines = [f"{e['host']}:{e['port']}" for e in open_ports]
        out_file = self.temp_file("open_ports.txt")
        self.write_lines(out_file, lines)
        self.ctx["open_ports_file"] = out_file

        self.log.info(
            f"[PortScan] {len(open_ports)} open ports found "
            f"across {len({e['host'] for e in open_ports})} hosts. "
            f"Ports: {port_numbers[:20]}"
        )

    async def _socket_fallback(self, targets: list[str]) -> None:
        """Simple TCP connect scan on common ports."""
        import asyncio as _asyncio

        COMMON = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
            3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
        ]
        open_ports = []

        async def check(host: str, port: int) -> None:
            try:
                _, writer = await _asyncio.wait_for(
                    _asyncio.open_connection(host, port), timeout=2
                )
                writer.close()
                await writer.wait_closed()
                open_ports.append({"host": host, "port": port})
            except Exception:
                pass

        tasks = [check(t, p) for t in targets for p in COMMON]
        await _asyncio.gather(*tasks)
        self._store_results(open_ports)

    def _store_results(self, open_ports: list[dict]) -> None:
        self.ctx["open_ports"] = open_ports
        self.ctx["port_list"]  = sorted({e["port"] for e in open_ports})
        out_file = self.temp_file("open_ports.txt")
        self.write_lines(out_file, [f"{e['host']}:{e['port']}" for e in open_ports])
        self.ctx["open_ports_file"] = out_file

"""
PentestBot v2 - Service Scan Stage
Version detection and banner grabbing using nmap.
Outputs are fed to nmap_parser for structured extraction.
"""

from pipeline.base_stage import BaseStage


class ServiceScanStage(BaseStage):
    """
    Stage 5: Service Detection

    Runs nmap with service version detection (-sV), default scripts (-sC),
    OS detection (-O), and selected NSE scripts for HTTP/TLS info.

    Outputs both XML and greppable (-oG) formats for the parser.

    Populates:
      ctx['nmap_xml_file']   -> path to nmap XML output
      ctx['nmap_grep_file']  -> path to nmap grepable output
      ctx['nmap_raw']        -> raw stdout
    """

    NAME = "ServiceScan"

    def _get_nse_scripts(self) -> str:
        base_scripts = [
            "banner",
            "http-title",
            "http-methods",
            "http-server-header",
            "ssl-cert",
            "ssl-enum-ciphers",
            "ftp-anon",
            "smtp-open-relay",
            "rdp-enum-encryption",
            "vnc-info",
            "mongodb-info",
            "redis-info",
            "ms-sql-info",
        ]
        
        mode = self.ctx.get("scan_mode", "fast")
        if mode in ("safe", "deep"):
            # Perluasan enumerasi aset yang sah (Legitimate enumeration for asset management)
            base_scripts.extend([
                "snmp-info",
                "snmp-sysdescr",
                "ldap-rootdse",
                "smb-os-discovery",
                "smb-security-mode"
            ])
            
        return ",".join(base_scripts)

    async def run(self) -> None:
        self.clear_stage_error()

        if not self.runner.which("nmap"):
            self.log.warning("[ServiceScan] nmap not found - skipping")
            self.ctx["services"] = []
            self.ctx["nmap_hosts"] = []
            self.ctx["nmap_scripts"] = {}
            self.ctx["os_matches"] = []
            return

        port_list: list[int] = self.ctx.get("port_list", [])
        if not port_list:
            port_list = [80, 443, 22, 8080, 8443]

        cfg = self.config
        top_ports = port_list[:cfg.nmap_max_ports]
        ports_arg = ",".join(str(p) for p in top_ports)

        origin_candidates = self.ctx.get("origin_candidates") or []
        if self.ctx.get("cdn_detected") and not origin_candidates:
            self.log.warning(
                "[ServiceScan] Skipping nmap fingerprinting because the target "
                "is CDN-proxied and no origin IP was identified."
            )
            self.ctx["nmap_xml_file"] = None
            self.ctx["nmap_grep_file"] = None
            self.ctx["nmap_raw"] = ""
            self.ctx["services"] = []
            self.ctx["nmap_hosts"] = []
            self.ctx["nmap_scripts"] = {}
            self.ctx["os_matches"] = []
            self.add_tool_error(
                "nmap fingerprinting skipped because the target is CDN-proxied "
                "and no origin IP was identified."
            )
            return

        targets = origin_candidates or self.ctx.get("live_ips") or [self.target]

        xml_out = self.temp_file("nmap.xml")
        grep_out = self.temp_file("nmap.gnmap")

        self.log.info(
            f"[ServiceScan] nmap on {len(targets)} target(s), "
            f"{len(top_ports)} ports"
        )

        cmd_prefix = [
            "nmap",
            f"-{cfg.nmap_timing}",
            "--open",
            "-p", ports_arg,
            "-oX", str(xml_out),
            "-oG", str(grep_out),
            "--script", self._get_nse_scripts(),
        ]

        requested_flags = cfg.nmap_flags.split()
        
        mode = self.ctx.get("scan_mode", "fast")
        if mode == "safe" and "-sC" in requested_flags:
            # -sC runs default scripts, some of which might be slightly intrusive.
            # We rely on our curated list of safe scripts instead for safe mode.
            requested_flags.remove("-sC")

        cmd = cmd_prefix + requested_flags + targets[:5]
        result = await self.runner.run(cmd=cmd, timeout=cfg.nmap_timeout)
        self.log_result(result)

        stderr_text = (result.stderr or "").lower()
        if (
            not result.success
            and "-O" in requested_flags
            and "requires root privileges" in stderr_text
        ):
            fallback_flags = [flag for flag in requested_flags if flag != "-O"]
            self.log.warning(
                "[ServiceScan] Retrying nmap without -O because the container "
                "does not have root privileges."
            )
            self.add_tool_error(
                "nmap OS fingerprinting (-O) skipped because root privileges are unavailable."
            )
            retry_cmd = cmd_prefix + fallback_flags + targets[:5]
            result = await self.runner.run(cmd=retry_cmd, timeout=cfg.nmap_timeout)
            self.log_result(result)

        self.ctx["nmap_xml_file"] = xml_out if xml_out.exists() else None
        self.ctx["nmap_grep_file"] = grep_out if grep_out.exists() else None
        self.ctx["nmap_raw"] = result.stdout

        from parser.nmap_parser import NmapParser

        parser = NmapParser()
        parsed = parser.parse(
            xml_path=xml_out if xml_out.exists() else None,
            grep_output=result.stdout,
        )
        self.ctx["services"] = parsed.get("services", [])
        self.ctx["nmap_hosts"] = parsed.get("hosts", [])
        self.ctx["nmap_scripts"] = parsed.get("script_results", {})
        self.ctx["os_matches"] = parsed.get("os_matches", [])

        self.log.info(
            f"[ServiceScan] Found {len(self.ctx['services'])} services, "
            f"{len(self.ctx.get('os_matches', []))} OS matches"
        )

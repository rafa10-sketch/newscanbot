"""
PentestBot v2 — Scan Profiles
Defines Fast and Deep scan modes and provides a function to overlay
profile-specific overrides onto the base ScanConfig at runtime.
"""

import copy
from enum import Enum


class ScanMode(str, Enum):
    FAST = "fast"
    DEEP = "deep"
    API = "api"
    SAFE = "safe"

    @classmethod
    def from_str(cls, value: str) -> "ScanMode":
        normalized = (value or "").strip().lower()
        if normalized in ("deep", "in-depth", "indepth", "thorough"):
            return cls.DEEP
        if normalized in ("api", "api-only", "apiscan", "api-scan"):
            return cls.API
        if normalized in ("safe", "defensive", "stealth"):
            return cls.SAFE
        return cls.FAST


# Overrides applied on top of the base ScanConfig when deep mode is selected.
# Keys must match ScanConfig field names exactly.
DEEP_OVERRIDES: dict = {
    # Port scanning — wider range, higher rate
    "naabu_top_ports":       "full",
    "naabu_rate":            2000,
    "naabu_timeout":         600,

    # Service detection — deeper scripts, more ports
    "nmap_flags":            "-sV -sC --script vuln",
    "nmap_timing":           "T3",
    "nmap_max_ports":        200,
    "nmap_timeout":          3600,

    # HTTP probing — higher throughput
    "httpx_threads":         80,
    "httpx_rate_limit":      250,

    # Web discovery — deeper crawl, more URLs kept
    "katana_depth":          4,
    "katana_timeout":        360,
    "gau_timeout":           240,
    "max_discovered_urls":   500,

    # Nuclei — more templates, higher rate, includes low severity
    "nuclei_severity":       "critical,high,medium,low",
    "nuclei_rate_limit":     250,
    "nuclei_timeout":        3600,

    # Pipeline timeouts — longer for thorough scans
    "stage_timeout":         600,
    "total_scan_timeout":    14400,
}

# Overrides applied for safe mode to protect network stability and avoid DoS.
SAFE_OVERRIDES: dict = {
    # Network Stability - much slower rates, more retries
    "naabu_rate":            200,
    "naabu_retries":         5,
    "naabu_timeout":         600,

    # Service detection - more stable timing
    "nmap_timing":           "T3",
    "nmap_timeout":          2400,

    # HTTP probing - gentle on web servers
    "httpx_threads":         20,
    "httpx_rate_limit":      50,

    # Nuclei - gentle rate
    "nuclei_severity":       "critical,high,medium",
    "nuclei_rate_limit":     50,
}

# Deep-mode value for max nuclei targets (used by VulnScanStage)
DEEP_MAX_NUCLEI_TARGETS = 12


def apply_profile(base_config, mode: ScanMode):
    """
    Return a copy of the ScanConfig with mode overrides applied.
    Fast mode returns an unmodified copy.
    """
    config = copy.copy(base_config)

    overrides = None
    if mode == ScanMode.DEEP:
        overrides = DEEP_OVERRIDES
    elif mode == ScanMode.SAFE:
        overrides = SAFE_OVERRIDES

    if overrides:
        for key, value in overrides.items():
            if hasattr(config, key):
                base_val = getattr(config, key)
                # For DEEP mode, we usually take max() for ints.
                # For SAFE mode, we take max() for timeouts/retries, but min() for rates/threads.
                if isinstance(base_val, int) and isinstance(value, int) and not isinstance(value, bool):
                    if mode == ScanMode.SAFE:
                        if "timeout" in key or "retries" in key:
                            setattr(config, key, max(base_val, value))
                        elif "rate" in key or "threads" in key or "max" in key:
                            setattr(config, key, min(base_val, value))
                        else:
                            setattr(config, key, value)
                    else:
                        setattr(config, key, max(base_val, value))
                else:
                    setattr(config, key, value)

    return config

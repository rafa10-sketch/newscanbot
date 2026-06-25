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

    @classmethod
    def from_str(cls, value: str) -> "ScanMode":
        normalized = (value or "").strip().lower()
        if normalized in ("deep", "in-depth", "indepth", "thorough"):
            return cls.DEEP
        if normalized in ("api", "api-only", "apiscan", "api-scan"):
            return cls.API
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

# Deep-mode value for max nuclei targets (used by VulnScanStage)
DEEP_MAX_NUCLEI_TARGETS = 12


def apply_profile(base_config, mode: ScanMode):
    """
    Return a copy of the ScanConfig with deep-mode overrides applied.
    Fast mode returns an unmodified copy.
    """
    config = copy.copy(base_config)

    if mode == ScanMode.DEEP:
        for key, value in DEEP_OVERRIDES.items():
            if hasattr(config, key):
                base_val = getattr(config, key)
                # If both are integers (e.g. timeouts), take the max so .env can override explicitly
                if isinstance(base_val, int) and isinstance(value, int) and not isinstance(value, bool):
                    setattr(config, key, max(base_val, value))
                else:
                    setattr(config, key, value)

    return config

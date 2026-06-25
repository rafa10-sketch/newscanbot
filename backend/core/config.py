	"""
PentestBot v2 — Configuration
Loads, validates, and exposes all runtime settings from environment / .env file.
"""

import itertools
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


# ── Paths ─────────────────────────────────────────────────────────────────────

def _path_from_env(name: str, default: Path) -> Path:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    return Path(raw).expanduser()


BASE_DIR    = _path_from_env("PENTESTBOT_BASE_DIR", Path(__file__).resolve().parent)
DATA_DIR    = _path_from_env("PENTESTBOT_DATA_DIR", BASE_DIR / "data")
REPORTS_DIR = _path_from_env("PENTESTBOT_REPORTS_DIR", BASE_DIR / "reports")
LOGS_DIR    = _path_from_env("PENTESTBOT_LOGS_DIR", BASE_DIR / "logs")
WORK_DIR    = _path_from_env("PENTESTBOT_WORK_DIR", DATA_DIR / "work")
DB_PATH     = _path_from_env("PENTESTBOT_DB_PATH", DATA_DIR / "pentestbot.db")

for _d in [DATA_DIR, REPORTS_DIR, LOGS_DIR, WORK_DIR]:
    _d.mkdir(parents=True, exist_ok=True)


# ── Config Dataclasses ────────────────────────────────────────────────────────

@dataclass
class TelegramConfig:
    token: str = ""
    allowed_user_ids: list[int] = field(default_factory=list)
    max_message_length: int = 4096

    @property
    def enabled(self) -> bool:
        return bool(self.token.strip())


@dataclass
class GroqConfig:
    api_keys: list[str]
    model: str             = "llama-3.3-70b-versatile"
    max_tokens: int        = 4096
    temperature: float     = 0.2
    timeout: int           = 90
    retry_attempts: int    = 3

    def __post_init__(self):
        self._key_cycle = itertools.cycle(self.api_keys)

    def next_key(self) -> str:
        """Return the next API key in round-robin order."""
        return next(self._key_cycle)

    @property
    def api_key(self) -> str:
        """Backward-compat: returns the first key."""
        return self.api_keys[0]


@dataclass
class GeminiConfig:
    api_key: str
    model: str             = "gemini-1.5-pro"
    max_tokens: int        = 4096
    temperature: float     = 0.2
    timeout: int           = 120
    retry_attempts: int    = 3

    @property
    def enabled(self) -> bool:
        return bool(self.api_key.strip())


@dataclass
class ScanConfig:
    # Subfinder
    subfinder_threads: int     = 10
    subfinder_timeout: int     = 150
    assetfinder_timeout: int   = 150

    # Amass (optional)
    enable_amass: bool         = False
    amass_timeout: int         = 300

    # Naabu
    naabu_ports: str           = ""          # empty = use top_ports
    naabu_top_ports: int       = 1000
    naabu_rate: int            = 1000
    naabu_timeout: int         = 300
    naabu_retries: int         = 3

    # Nmap
    nmap_flags: str            = "-sV -sC"
    nmap_timing: str           = "T4"
    nmap_timeout: int          = 1800
    nmap_max_ports: int        = 50          # cap nmap to top N discovered ports

    # HTTPX
    httpx_threads: int         = 50
    httpx_timeout: int         = 15
    httpx_rate_limit: int      = 150

    # Web Discovery
    enable_web_discovery: bool = True
    katana_timeout: int        = 180
    katana_depth: int          = 2
    gau_timeout: int           = 120
    max_discovered_urls: int   = 150

    # Gobuster / Dirsearch
    enable_gobuster: bool      = True
    gobuster_timeout: int      = 180
    enable_dirsearch: bool     = False
    dirsearch_timeout: int     = 240

    # Fingerprinting (WhatWeb, Wafw00f, Webanalyze)
    enable_fingerprint: bool   = True
    whatweb_timeout: int       = 120
    wafw00f_timeout: int       = 60
    webanalyze_timeout: int    = 60

    # Nuclei
    nuclei_severity: str       = "critical,high,medium"
    nuclei_rate_limit: int     = 150
    nuclei_timeout: int        = 1000
    nuclei_templates: str      = str(Path.home() / ".config" / "nuclei" / "templates")

    # Nikto
    enable_nikto: bool         = False
    nikto_timeout: int         = 900

    # WPScan / Joomscan
    enable_wpscan: bool        = False
    wpscan_timeout: int        = 300
    enable_joomscan: bool      = False
    joomscan_timeout: int      = 300

    # SQLMap
    enable_sqlmap: bool        = False
    sqlmap_timeout: int        = 600

    # Dalfox
    enable_dalfox: bool        = False
    dalfox_timeout: int        = 600
    dalfox_request_timeout: int = 10
    dalfox_workers: int        = 20
    dalfox_max_targets_per_host: int = 30
    dalfox_deep_scan: bool     = False

    # S3Scanner
    enable_s3scanner: bool     = False
    s3scanner_timeout: int     = 240

    # testssl.sh / sslyze
    enable_sslyze: bool        = True
    sslyze_timeout: int        = 180
    testssl_timeout: int       = 1000

    # Pipeline timeouts
    stage_timeout: int         = 300         # per-stage default timeout
    total_scan_timeout: int    = 9000        # entire scan


@dataclass
class ApiConfig:
    enabled: bool          = True
    host: str              = "0.0.0.0"
    port: int              = 8000
    auth_token: str        = ""
    cors_origins: list[str] = field(default_factory=lambda: ["*"])


@dataclass
class Config:
    # Subsystem configs
    telegram: TelegramConfig
    groq: GroqConfig
    gemini: GeminiConfig
    scan: ScanConfig
    api: ApiConfig

    # Paths
    base_dir: Path    = BASE_DIR
    data_dir: Path    = DATA_DIR
    reports_dir: Path = REPORTS_DIR
    log_dir: Path     = LOGS_DIR
    work_dir: Path    = WORK_DIR
    db_path: Path     = DB_PATH

    # Application
    log_level: str             = "INFO"
    max_concurrent_scans: int  = 3
    version: str               = "2.0.0"


# ── Loader ────────────────────────────────────────────────────────────────────

def _parse_user_ids(raw: str) -> list[int]:
    if not raw.strip():
        return []
    return [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]


def _normalize_groq_model(raw: str) -> str:
    aliases = {
        "llama3-70b-8192": "llama-3.3-70b-versatile",
        "llama-3.1-70b-versatile": "llama-3.3-70b-versatile",
    }
    raw = raw.strip()
    return aliases.get(raw, raw) or "llama-3.3-70b-versatile"


def _parse_bool(raw: str, default: bool = True) -> bool:
    normalized = raw.strip().lower()
    if not normalized:
        return default
    return normalized not in {"0", "false", "no", "off"}


def _parse_cors_origins(raw: str) -> list[str]:
    if not raw.strip():
        return ["*"]
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def load_config(env_file: str = ".env", require_secrets: bool = True) -> Config:
    """Load configuration from environment / .env file."""
    if Path(env_file).exists():
        load_dotenv(env_file, override=False)

    tg = TelegramConfig(
        token=os.getenv("TELEGRAM_BOT_TOKEN", ""),
        allowed_user_ids=_parse_user_ids(os.getenv("ALLOWED_USER_IDS", "")),
    )
    # Telegram is now optional — no error if token is missing.

    # Support both GROQ_API_KEYS (comma-separated) and legacy GROQ_API_KEY
    raw_keys = os.getenv("GROQ_API_KEYS", "") or os.getenv("GROQ_API_KEY", "")
    api_keys = [k.strip() for k in raw_keys.split(",") if k.strip()]

    groq = GroqConfig(
        api_keys=api_keys or [""],
        model=_normalize_groq_model(os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")),
        max_tokens=int(os.getenv("GROQ_MAX_TOKENS", "4096")),
        temperature=float(os.getenv("GROQ_TEMPERATURE", "0.2")),
    )

    gemini = GeminiConfig(
        api_key=os.getenv("GEMINI_API_KEY", ""),
        model=os.getenv("GEMINI_MODEL", "gemini-1.5-pro"),
        max_tokens=int(os.getenv("GEMINI_MAX_TOKENS", "4096")),
        temperature=float(os.getenv("GEMINI_TEMPERATURE", "0.2")),
    )

    scan = ScanConfig(
        subfinder_threads=int(os.getenv("SUBFINDER_THREADS", "10")),
        enable_amass=_parse_bool(os.getenv("ENABLE_AMASS", "false"), default=False),
        amass_timeout=int(os.getenv("AMASS_TIMEOUT", "300")),
        naabu_ports=os.getenv("NAABU_PORTS", ""),
        naabu_top_ports=int(os.getenv("NAABU_TOP_PORTS", "1000")),
        naabu_rate=int(os.getenv("NAABU_RATE", "1000")),
        nmap_flags=os.getenv("NMAP_FLAGS", "-sV -sC"),
        nmap_timing=os.getenv("NMAP_TIMING", "T4"),
        httpx_threads=int(os.getenv("HTTPX_THREADS", "50")),
        enable_web_discovery=_parse_bool(os.getenv("ENABLE_WEB_DISCOVERY", "true"), default=True),
        katana_timeout=int(os.getenv("KATANA_TIMEOUT", "180")),
        katana_depth=int(os.getenv("KATANA_DEPTH", "2")),
        gau_timeout=int(os.getenv("GAU_TIMEOUT", "120")),
        max_discovered_urls=int(os.getenv("MAX_DISCOVERED_URLS", "150")),
        enable_gobuster=_parse_bool(os.getenv("ENABLE_GOBUSTER", "true"), default=True),
        gobuster_timeout=int(os.getenv("GOBUSTER_TIMEOUT", "180")),
        enable_dirsearch=_parse_bool(os.getenv("ENABLE_DIRSEARCH", "false"), default=False),
        dirsearch_timeout=int(os.getenv("DIRSEARCH_TIMEOUT", "240")),
        enable_fingerprint=_parse_bool(os.getenv("ENABLE_FINGERPRINT", "true"), default=True),
        whatweb_timeout=int(os.getenv("WHATWEB_TIMEOUT", "120")),
        wafw00f_timeout=int(os.getenv("WAFW00F_TIMEOUT", "60")),
        webanalyze_timeout=int(os.getenv("WEBANALYZE_TIMEOUT", "60")),
        nuclei_severity=os.getenv("NUCLEI_SEVERITY", "critical,high,medium"),
        nuclei_rate_limit=int(os.getenv("NUCLEI_RATE_LIMIT", "150")),
        nuclei_templates=os.getenv(
            "NUCLEI_TEMPLATES",
            str(Path.home() / ".config" / "nuclei" / "templates"),
        ),
        enable_nikto=_parse_bool(os.getenv("ENABLE_NIKTO", "false"), default=False),
        enable_wpscan=_parse_bool(os.getenv("ENABLE_WPSCAN", "false"), default=False),
        wpscan_timeout=int(os.getenv("WPSCAN_TIMEOUT", "300")),
        enable_joomscan=_parse_bool(os.getenv("ENABLE_JOOMSCAN", "false"), default=False),
        joomscan_timeout=int(os.getenv("JOOMSCAN_TIMEOUT", "300")),
        enable_sqlmap=_parse_bool(os.getenv("ENABLE_SQLMAP", "false"), default=False),
        sqlmap_timeout=int(os.getenv("SQLMAP_TIMEOUT", "600")),
        enable_dalfox=_parse_bool(os.getenv("ENABLE_DALFOX", "false"), default=False),
        dalfox_timeout=int(os.getenv("DALFOX_TIMEOUT", "600")),
        dalfox_request_timeout=int(os.getenv("DALFOX_REQUEST_TIMEOUT", "10")),
        dalfox_workers=int(os.getenv("DALFOX_WORKERS", "20")),
        dalfox_max_targets_per_host=int(os.getenv("DALFOX_MAX_TARGETS_PER_HOST", "30")),
        dalfox_deep_scan=_parse_bool(os.getenv("DALFOX_DEEP_SCAN", "false"), default=False),
        enable_s3scanner=_parse_bool(os.getenv("ENABLE_S3SCANNER", "false"), default=False),
        s3scanner_timeout=int(os.getenv("S3SCANNER_TIMEOUT", "240")),
        enable_sslyze=_parse_bool(os.getenv("ENABLE_SSLYZE", "true"), default=True),
        sslyze_timeout=int(os.getenv("SSLYZE_TIMEOUT", "180")),
        total_scan_timeout=int(os.getenv("SCAN_TIMEOUT", "3600")),
    )

    api = ApiConfig(
        enabled=_parse_bool(os.getenv("PENTESTBOT_API_ENABLED", "true"), default=True),
        host=os.getenv("PENTESTBOT_API_HOST", "0.0.0.0"),
        port=int(os.getenv("PENTESTBOT_API_PORT", "8000")),
        auth_token=os.getenv("PENTESTBOT_API_TOKEN", "").strip(),
        cors_origins=_parse_cors_origins(os.getenv("CORS_ORIGINS", "*")),
    )

    return Config(
        telegram=tg,
        groq=groq,
        gemini=gemini,
        scan=scan,
        api=api,
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        max_concurrent_scans=int(os.getenv("MAX_CONCURRENT_SCANS", "3")),
    )


"""
ScanBot — AI Engine Orchestrator

PRIMARY ENGINE  : Google Gemini 1.5 Pro   → [PRO-GEMINI-ANALYSIS]
BACKUP ENGINE   : Groq (round-robin keys) → [GROQ-BACKUP-ANALYSIS]

Failover logic per section:
  1. Attempt generation via Gemini 1.5 Pro.
  2. On HTTP 429 / quota / any Gemini API error → immediately retry with Groq.
  3. On total failure → static fallback text.

Attribution is tracked per-section and surfaced in:
  - Log entries  (prefixed with [PRO-GEMINI-ANALYSIS] or [GROQ-BACKUP-ANALYSIS])
  - PDF report   ("AI Analysis Attribution" section)
"""

import asyncio
from typing import Optional

import httpx

from analysis.gemini_ai import GeminiAI
from analysis.groq_ai import AIAnalysis, GroqAI
from analysis.result_aggregator import AggregatedResult
from config import GeminiConfig, GroqConfig
from utils.logger import get_logger

logger = get_logger("analysis.ai_engine")

ENGINE_GEMINI = "PRO-GEMINI"
ENGINE_GROQ   = "GROQ-BACKUP"
ENGINE_STATIC = "STATIC-FALLBACK"


class AIEngine:
    """
    Orchestrates AI analysis with Gemini 1.5 Pro primary → Groq backup failover.

    Each report section is attempted with Gemini first.
    Any Gemini error (rate-limit, quota, network) triggers per-section Groq retry.
    Attribution is logged and written to AIAnalysis.engine_attribution.
    """

    INTER_SECTION_DELAY = 5.0  # seconds between sections

    def __init__(self, gemini_config: GeminiConfig, groq_config: GroqConfig):
        self._gemini: Optional[GeminiAI] = (
            GeminiAI(gemini_config) if gemini_config.enabled else None
        )
        self._groq = GroqAI(groq_config)

        if self._gemini:
            logger.info(
                "[AIEngine] Primary: Gemini 1.5 Pro [PRO-GEMINI-ANALYSIS] | "
                "Backup: Groq [GROQ-BACKUP-ANALYSIS]"
            )
        else:
            logger.info(
                "[AIEngine] Gemini not configured — "
                "Groq is sole engine [GROQ-BACKUP-ANALYSIS]"
            )

    # ── Public API ─────────────────────────────────────────────────────────────

    async def analyze(self, result: AggregatedResult) -> AIAnalysis:
        """Run full report analysis with primary/backup failover per section."""
        logger.info(f"[AIEngine] Starting analysis for scan {result.scan_id}")
        analysis = AIAnalysis()
        ctx = self._groq._build_context(result)
        attribution: dict = {}  # Local dict — defensive against old AIAnalysis versions

        sections = [
            ("executive_summary",      self._groq._prompt_executive(result, ctx)),
            ("scope_and_coverage",     self._groq._prompt_scope(result, ctx)),
            ("attack_surface",         self._groq._prompt_attack_surface(result, ctx)),
            ("vulnerability_analysis", self._groq._prompt_vulnerabilities(result, ctx)),
            ("network_exposure",       self._groq._prompt_network(result, ctx)),
            ("tls_analysis",           self._groq._prompt_tls(result, ctx)),
            ("realistic_risk_summary", self._groq._prompt_realistic_risk(result, ctx)),
            ("attack_path_simulation", self._groq._prompt_attack_paths(result, ctx)),
            ("remediation_plan",       self._groq._prompt_remediation(result, ctx)),
            ("conclusion",             self._groq._prompt_conclusion(result, ctx)),
            ("initial_recommendations",self._groq._prompt_initial_recommendations(result, ctx)),
        ]

        for i, (name, prompt) in enumerate(sections):
            max_tok = self._groq.SECTION_MAX_TOKENS.get(name, self._groq.config.max_tokens)
            text, engine = await self._generate_section(name, prompt, max_tok, result)
            setattr(analysis, name, text)
            attribution[name] = engine
            if engine == ENGINE_STATIC:
                analysis.error_sections.append(name)

            if i < len(sections) - 1:
                await asyncio.sleep(self.INTER_SECTION_DELAY)

        # Determine overall engine label
        gemini_count = sum(1 for v in attribution.values() if v == ENGINE_GEMINI)
        overall = ENGINE_GEMINI if gemini_count >= len(sections) // 2 else ENGINE_GROQ

        # Assign attribution fields — safe even if AIAnalysis is an older version
        try:
            analysis.engine_used = overall
        except AttributeError:
            pass
        try:
            analysis.engine_attribution = attribution
        except AttributeError:
            pass

        logger.info(
            f"[AIEngine] Analysis complete. "
            f"Gemini: {gemini_count}/{len(sections)} sections. "
            f"Overall: [{overall}-ANALYSIS]"
        )
        return analysis

    async def enrich_findings(self, findings: list) -> list:
        """Enrich findings with AI descriptions. Gemini first, Groq fallback."""
        if self._gemini:
            try:
                return await self._enrich_with_gemini(findings)
            except Exception as exc:
                logger.warning(
                    f"[PRO-GEMINI-ANALYSIS] Finding enrichment failed entirely, "
                    f"falling back to Groq. Error: {exc}"
                )
        return await self._groq.enrich_findings(findings)

    async def close(self) -> None:
        if self._gemini:
            await self._gemini.close()
        await self._groq.close()

    # ── Internal ───────────────────────────────────────────────────────────────

    async def _generate_section(
        self,
        name: str,
        prompt: str,
        max_tokens: int,
        result: AggregatedResult,
    ) -> tuple[str, str]:
        """
        Generate a single section. Returns (text, engine_label).
        Priority: Gemini → Groq → Static fallback.
        """
        # ── Attempt 1: Gemini (Primary) ────────────────────────────────────────
        if self._gemini:
            try:
                text = await self._gemini.call(
                    system_prompt=self._groq.SYSTEM_PROMPT,
                    user_prompt=prompt,
                    max_tokens=max_tokens,
                )
                logger.info(f"[PRO-GEMINI-ANALYSIS] Section '{name}' — OK")
                return text, ENGINE_GEMINI

            except httpx.HTTPStatusError as exc:
                code = exc.response.status_code
                reason = "Rate-limited (429)" if code == 429 else f"HTTP {code}"
                logger.warning(
                    f"[PRO-GEMINI-ANALYSIS] Section '{name}' failed — {reason}. "
                    f"Switching to [GROQ-BACKUP-ANALYSIS]"
                )
            except Exception as exc:
                logger.warning(
                    f"[PRO-GEMINI-ANALYSIS] Section '{name}' error: {exc}. "
                    f"Switching to [GROQ-BACKUP-ANALYSIS]"
                )

        # ── Attempt 2: Groq (Backup) ───────────────────────────────────────────
        try:
            text = await self._groq._fetch_section(name, prompt)
            logger.info(f"[GROQ-BACKUP-ANALYSIS] Section '{name}' — OK")
            return text, ENGINE_GROQ
        except Exception as exc:
            logger.error(
                f"[GROQ-BACKUP-ANALYSIS] Section '{name}' also failed: {exc}. "
                f"Using static fallback."
            )

        # ── Attempt 3: Static Fallback ─────────────────────────────────────────
        return self._groq._fallback(name, result), ENGINE_STATIC

    async def _enrich_with_gemini(self, findings: list) -> list:
        to_enrich = findings[: self._groq.ENRICHMENT_MAX_FINDINGS]
        if not to_enrich:
            return findings

        enriched_count = 0
        for i, finding in enumerate(to_enrich):
            try:
                prompt = self._groq._prompt_enrich_finding(finding)
                text = await self._gemini.call(
                    system_prompt=self._groq.SYSTEM_PROMPT,
                    user_prompt=prompt,
                    max_tokens=self._groq.ENRICHMENT_MAX_TOKENS,
                )
                if text and len(text) > 30:
                    finding.extra["original_description"] = finding.description
                    finding.description = text.strip()
                    enriched_count += 1
                if i < len(to_enrich) - 1:
                    await asyncio.sleep(self._groq.ENRICHMENT_DELAY_SECONDS)
            except Exception as exc:
                logger.warning(
                    f"[PRO-GEMINI-ANALYSIS] Enrichment failed for "
                    f"'{finding.title[:40]}': {exc}"
                )

        logger.info(
            f"[PRO-GEMINI-ANALYSIS] Enrichment: "
            f"{enriched_count}/{len(to_enrich)} findings via Gemini"
        )
        return findings

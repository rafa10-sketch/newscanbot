"""
ScanBot — Gemini AI Client
Primary analysis engine. Thin async wrapper around the Google Gemini REST API.
"""

import httpx

from config import GeminiConfig
from utils.logger import get_logger

logger = get_logger("analysis.gemini")

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiAI:
    """
    Async client for Google Gemini Generative Language REST API.
    Exposes a single .call() method consumed by AIEngine.
    """

    def __init__(self, config: GeminiConfig):
        self.config = config
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(config.timeout))
        logger.info(f"[PRO-GEMINI-ANALYSIS] GeminiAI initialized (model={config.model})")

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    async def call(self, system_prompt: str, user_prompt: str, max_tokens: int) -> str:
        """
        Call Gemini REST API with a system instruction and user prompt.
        Returns the text response.
        Raises httpx.HTTPStatusError on API errors (including 429 rate-limit).
        """
        url = (
            f"{GEMINI_API_BASE}/{self.config.model}:generateContent"
            f"?key={self.config.api_key}"
        )
        payload = {
            "system_instruction": {
                "parts": [{"text": system_prompt}]
            },
            "contents": [
                {"role": "user", "parts": [{"text": user_prompt}]}
            ],
            "generationConfig": {
                "maxOutputTokens": min(max_tokens, self.config.max_tokens),
                "temperature": self.config.temperature,
            },
        }
        response = await self._client.post(url, json=payload)
        if response.is_error:
            detail = response.text[:500].replace("\n", " ").strip()
            raise httpx.HTTPStatusError(
                f"{response.status_code} error from Gemini: {detail}",
                request=response.request,
                response=response,
            )
        data = response.json()
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except (KeyError, IndexError) as exc:
            raise ValueError(f"Unexpected Gemini response structure: {data}") from exc

    async def close(self) -> None:
        await self._client.aclose()

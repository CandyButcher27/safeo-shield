"""Fireworks AI — Gemma 3 4B integration for ForensicsAgent (AMD hackathon)."""
from __future__ import annotations

import json
import logging
import os

import httpx

logger = logging.getLogger("safeo.fireworks_gemma")

FIREWORKS_CHAT_URL = "https://api.fireworks.ai/inference/v1/chat/completions"
GEMMA_MODEL = "accounts/fireworks/models/gemma3-4b-it"

_MOCK_RESPONSE = json.dumps({
    "attack_type": "sql_injection",
    "attack_timeline": "Dry-run: SQL injection pattern detected in payload excerpt",
    "mitre_techniques": ["T1190"],
    "confidence": 0.88,
    "chain_of_thought": "FIREWORKS_DRY_RUN active — mocked Gemma response for development.",
})


async def call_fireworks_gemma(prompt: str) -> str:
    """Call Fireworks Gemma chat completions; returns assistant message text."""
    if os.environ.get("FIREWORKS_DRY_RUN", "").strip().lower() == "true":
        logger.debug("Fireworks Gemma dry-run — returning mock response")
        return _MOCK_RESPONSE

    api_key = os.environ["FIREWORKS_API_KEY"]
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            FIREWORKS_CHAT_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": GEMMA_MODEL,
                "max_tokens": 300,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"] or ""

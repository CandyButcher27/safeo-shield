"""
GPU-accelerated multilingual agent: Arabic, Urdu, Arabizi detection and evasion scoring.

Uses AraBERT (``aubmindlab/bert-base-arabertv2``) on AMD ROCm when available; falls back
to heuristic scoring on CPU-only hosts.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any, ClassVar, Deque, Dict, List, Optional, Tuple

from ..core.ml.securec_language import normalise_mixed_script
from ..config.amd_config import AMD_DEVICE, MULTILINGUAL_MODEL_NAME

logger = logging.getLogger("safeo.multilingual")

# Urdu-specific letters (not in standard Arabic-only text)
_URDU_SPECIFIC = set("\u06ba\u06c1\u06d2\u0688\u0691\u0679\u0686\u0698\u06af\u06be\u067e")
_ARABIC_BLOCK = range(0x0600, 0x06FF + 1)

# Reference attack phrases (Latin) for embedding similarity
_ATTACK_REFERENCE = [
    "union select password from users",
    "drop table accounts",
    "<script>alert(document.cookie)</script>",
    "ignore previous instructions system prompt",
    "' or 1=1 --",
    "offshore wire transfer avoid audit",
]

_EVASION_KEYWORDS = (
    "select", "union", "drop", "insert", "delete", "script", "alert",
    "or 1=1", "--", "ignore previous", "system prompt",
)


class MultilingualAgent:
    """Singleton-style agent with cached Hugging Face model."""

    _tokenizer: ClassVar[Any] = None
    _model: ClassVar[Any] = None
    _device: ClassVar[str] = "cpu"
    _ref_embeddings: ClassVar[Optional[Any]] = None
    _load_attempted: ClassVar[bool] = False

    _script_history: ClassVar[Deque[str]] = deque(maxlen=1000)
    _script_counts: ClassVar[Dict[str, int]] = defaultdict(int)
    _evasion_attempts: ClassVar[int] = 0
    _inference_ms_total: ClassVar[float] = 0.0
    _inference_n: ClassVar[int] = 0

    def __init__(self) -> None:
        self._ensure_model()

    @classmethod
    def _ensure_model(cls) -> None:
        if cls._load_attempted:
            return
        cls._load_attempted = True
        try:
            import torch
            from transformers import AutoModel, AutoTokenizer

            cls._device = AMD_DEVICE if AMD_DEVICE == "cuda" and torch.cuda.is_available() else "cpu"
            cls._tokenizer = AutoTokenizer.from_pretrained(MULTILINGUAL_MODEL_NAME)
            cls._model = AutoModel.from_pretrained(MULTILINGUAL_MODEL_NAME)
            cls._model.to(cls._device)
            cls._model.eval()
            cls._ref_embeddings = cls._embed_batch(_ATTACK_REFERENCE)
            logger.info("MultilingualAgent loaded %s on %s", MULTILINGUAL_MODEL_NAME, cls._device)
        except Exception as exc:
            logger.warning("MultilingualAgent model load skipped: %s", exc)
            cls._tokenizer = None
            cls._model = None

    @classmethod
    def _embed_batch(cls, texts: List[str]):
        import torch

        if cls._model is None or cls._tokenizer is None:
            return None
        encoded = cls._tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=64,
            return_tensors="pt",
        )
        encoded = {k: v.to(cls._device) for k, v in encoded.items()}
        with torch.no_grad():
            out = cls._model(**encoded)
        # Mean pool last hidden state
        return out.last_hidden_state.mean(dim=1)

    @classmethod
    def _embed_text(cls, text: str):
        vecs = cls._embed_batch([text])
        return vecs[0] if vecs is not None else None

    @staticmethod
    def _latin_ratio(text: str) -> float:
        if not text:
            return 1.0
        latin = sum(1 for c in text if "a" <= c.lower() <= "z")
        return latin / max(len(text), 1)

    @staticmethod
    def _arabic_ratio(text: str) -> float:
        if not text:
            return 0.0
        ar = sum(1 for c in text if ord(c) in _ARABIC_BLOCK)
        return ar / max(len(text), 1)

    @classmethod
    def detect_script(cls, text: str) -> str:
        if not text or not text.strip():
            return "latin"
        has_urdu = any(c in _URDU_SPECIFIC for c in text)
        ar_ratio = cls._arabic_ratio(text)
        lat_ratio = cls._latin_ratio(text)
        has_arabizi = lat_ratio > 0.35 and any(ch.isdigit() for ch in text) and ar_ratio < 0.2

        if ar_ratio > 0.25 and has_urdu:
            return "urdu"
        if ar_ratio > 0.25:
            return "arabic"
        if has_arabizi:
            return "arabizi"
        if lat_ratio > 0.5 and ar_ratio > 0.1:
            return "mixed"
        if lat_ratio > 0.6:
            return "latin"
        if ar_ratio > 0.1:
            return "arabic"
        return "latin"

    def normalise(self, text: str) -> str:
        return normalise_mixed_script(text)

    def score_evasion(self, text: str) -> Dict[str, Any]:
        """Semantic / heuristic evasion detection for non-Latin obfuscation."""
        import re

        original = text or ""
        normalised = self.normalise(original)
        script = self.detect_script(original)
        method = "heuristic"
        heuristic_conf = 0.0
        lower = normalised.lower()

        keyword_hits = sum(1 for kw in _EVASION_KEYWORDS if kw in lower)
        if keyword_hits >= 2 and script in ("arabic", "urdu", "mixed", "arabizi"):
            heuristic_conf = min(0.55 + keyword_hits * 0.12, 0.92)
            method = "heuristic_keywords"
        elif keyword_hits >= 1 and script != "latin":
            heuristic_conf = 0.45
            method = "heuristic_keywords"

        if re.search(r"[۰-۹٠-٩0-9]\s*=\s*[۰-۹٠-٩0-9]", original) and script in (
            "arabic",
            "urdu",
            "mixed",
        ):
            heuristic_conf = max(heuristic_conf, 0.72)
            method = "heuristic_digit_equality"
        if any(tok in original for tok in ("انتخاب", "حذف", "إسقاط", "سقوط")) and script in (
            "arabic",
            "urdu",
        ):
            heuristic_conf = max(heuristic_conf, 0.68)
            method = "heuristic_multilingual_sql"

        # Embedding path when model loaded
        if self._model is not None and self._ref_embeddings is not None:
            try:
                import torch

                vec = self._embed_text(text or normalised)
                if vec is not None:
                    sims = torch.nn.functional.cosine_similarity(
                        vec.unsqueeze(0), self._ref_embeddings
                    )
                    max_sim = float(sims.max().item())
                    if max_sim > 0.72:
                        emb_conf = min(max_sim, 0.98)
                        if emb_conf > heuristic_conf:
                            method = "arabert_embedding"
                            return {
                                "evasion_suspected": True,
                                "confidence": round(emb_conf, 3),
                                "method": method,
                            }
            except Exception as exc:
                logger.debug("embedding evasion check failed: %s", exc)

        suspected = heuristic_conf >= 0.45
        return {
            "evasion_suspected": suspected,
            "confidence": round(heuristic_conf, 3),
            "method": method,
        }

    def analyse(self, text: str) -> Dict[str, Any]:
        t0 = time.perf_counter()
        original = text or ""
        script = self.detect_script(original)
        normalised = self.normalise(original)
        evasion = self.score_evasion(original)
        inference_ms = int((time.perf_counter() - t0) * 1000)

        self._script_history.append(script)
        self._script_counts[script] += 1
        if evasion.get("evasion_suspected"):
            MultilingualAgent._evasion_attempts += 1
        MultilingualAgent._inference_ms_total += inference_ms
        MultilingualAgent._inference_n += 1

        return {
            "original": original,
            "normalised": normalised,
            "script_detected": script,
            "evasion_suspected": bool(evasion.get("evasion_suspected")),
            "confidence": float(evasion.get("confidence", 0.0)),
            "method": evasion.get("method", "heuristic"),
            "inference_ms": inference_ms,
            "device_used": self._device,
        }

    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        dist = {"arabic": 0, "urdu": 0, "arabizi": 0, "mixed": 0, "latin": 0}
        for script, count in cls._script_counts.items():
            key = script if script in dist else "latin"
            if script == "arabizi":
                key = "arabizi"
            dist[key] = dist.get(key, 0) + count
        avg_ms = (
            cls._inference_ms_total / cls._inference_n if cls._inference_n else 0.0
        )
        return {
            "script_distribution": dist,
            "evasion_attempts": cls._evasion_attempts,
            "avg_inference_ms": round(avg_ms, 2),
            "device": cls._device,
            "samples_tracked": len(cls._script_history),
        }


_agent_instance: Optional[MultilingualAgent] = None


def get_multilingual_agent() -> MultilingualAgent:
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = MultilingualAgent()
    return _agent_instance

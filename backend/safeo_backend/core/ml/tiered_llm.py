"""
Three-tier LLM pipeline:
  Tier 1 (heuristic, always runs)   → decisive if score < 0.35 or > 0.65
  Tier 2 (distilBERT, AMD GPU/CPU)  → resolves 0.35 – 0.65 uncertain band when confident (>0.80)
  Tier 3 (local vLLM Mistral-7B)    → only genuinely ambiguous cases + drift sampling

tier_made_call: 1 | 2 | 3 recorded in tier_stats for LLM-savings reporting.
"""
import hashlib
import logging
from typing import Any, Dict, List, Tuple

from .llm_guard import is_llm_available, llm_enabled
from ...utils.tier_stats import record as _record_tier

logger = logging.getLogger("safeo.tiered_llm")

_llm_call_count = 0

TIER2_BAND_LOW  = 0.35
TIER2_BAND_HIGH = 0.65
TIER2_CONFIDENCE_THRESHOLD = 0.80


def get_llm_call_count() -> int:
    return _llm_call_count


def record_llm_call() -> None:
    global _llm_call_count
    _llm_call_count += 1


def log_tier3_invocation(*, inference_ms: int, used_local_gpu: bool, fallback: bool) -> None:
    mode = "fallback" if fallback else ("local_gpu" if used_local_gpu else "local_vllm_cpu")
    logger.info(
        "tier3_llm inference_ms=%s mode=%s vllm_up=%s total_calls=%s",
        inference_ms, mode, is_llm_available(), get_llm_call_count(),
    )


def run_tiered_scoring(
    risk_score: float, patterns: List[str], text: str
) -> Tuple[float, int, Dict[str, Any]]:
    """
    Run tier-2 and/or tier-3 augmentation.

    Returns:
        (adjusted_score, tier_that_decided, augmentation_meta)
    """
    _record_tier(0)  # counts total requests before tier decision

    # ── Tier 1 — decisive bands ──────────────────────────────────────────────
    if risk_score < TIER2_BAND_LOW or risk_score > TIER2_BAND_HIGH:
        _record_tier(1)
        return risk_score, 1, {"tier": 1, "reason": "heuristic_decisive"}

    # ── Tier 2 — distilBERT on uncertain band ────────────────────────────────
    try:
        from .tier2_classifier import get_tier2_classifier
        clf = get_tier2_classifier()
        t2 = clf.classify(text)
        logger.info("tier2 score=%.3f label=%s conf=%.3f ms=%s",
                    t2["tier2_score"], t2.get("label"), t2.get("confidence"), t2.get("inference_ms"))

        if t2.get("confidence", 0.0) >= TIER2_CONFIDENCE_THRESHOLD:
            # Blend: 40% tier-1 heuristic + 60% tier-2 neural
            adjusted = round(0.40 * risk_score + 0.60 * t2["tier2_score"], 3)
            _record_tier(2)
            return adjusted, 2, {"tier": 2, **t2}
    except Exception as exc:
        logger.warning("tier2 skipped: %s", exc)

    # ── Tier 3 — local vLLM (only if available) ──────────────────────────────
    if llm_enabled() and is_llm_available():
        _record_tier(3)
        return risk_score, 3, {"tier": 3, "reason": "gray_zone_escalated_to_llm"}

    # No tier-3 available — resolve with tier-1 score
    _record_tier(1)
    return risk_score, 1, {"tier": 1, "reason": "tier3_unavailable_fallback"}


def should_invoke_llm(risk_score: float, patterns: List[str], text: str) -> Tuple[bool, str]:
    """
    Backward-compatible helper used by routes/waf.py.
    Returns (call_llm, reason). Tier-2 check runs internally here.
    """
    if not llm_enabled():
        return False, "llm_disabled"
    if not is_llm_available():
        return False, "vllm_unavailable"

    if risk_score >= 0.82:
        return False, "high_confidence_heuristic"
    if risk_score < 0.16 and not patterns:
        return False, "low_risk_clear"

    if TIER2_BAND_LOW <= risk_score <= TIER2_BAND_HIGH:
        try:
            from .tier2_classifier import get_tier2_classifier
            t2 = get_tier2_classifier().classify(text)
            if t2.get("confidence", 0.0) >= TIER2_CONFIDENCE_THRESHOLD:
                return False, "tier2_confident"
        except Exception:
            pass
        return True, "gray_zone"

    sample = int(hashlib.sha256((text[:1200] + str(len(text))).encode()).hexdigest(), 16) % 100
    if sample < 6:
        return True, "sampled_drift_check"
    return False, "heuristic_sufficient"

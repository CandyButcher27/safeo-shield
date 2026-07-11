"""In-memory tier decision counters — tracks where in the pipeline each call resolved."""
from __future__ import annotations

_counts = {
    "tier1_decisions": 0,
    "tier2_decisions": 0,
    "tier3_decisions": 0,
    "total_requests": 0,
}


def record(tier: int) -> None:
    _counts["total_requests"] += 1
    key = f"tier{tier}_decisions"
    if key in _counts:
        _counts[key] += 1


def get_stats() -> dict:
    t = _counts["total_requests"]
    llm_saved = _counts["tier1_decisions"] + _counts["tier2_decisions"]
    return {
        **_counts,
        "llm_calls_saved": llm_saved,
        "llm_savings_pct": round(llm_saved / t * 100, 1) if t else 0.0,
    }


def reset_stats() -> None:
    for k in _counts:
        _counts[k] = 0

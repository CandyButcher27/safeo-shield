"""Aggregated metrics for the OWL dashboard (reads shared in-memory log from `routes.waf`)."""
from fastapi import APIRouter, Body
from collections import defaultdict
from ..models.schemas import MetricsResponse
from ..agents.multilingual_agent import MultilingualAgent
from .waf import get_request_log, get_engine_stats

router = APIRouter(prefix="/metrics", tags=["Business Risk Dashboard"])
agents_router = APIRouter(prefix="/agents", tags=["Agents"])
ml_router = APIRouter(prefix="/ml", tags=["ML Internals"])

# Map raw module names to ERP module labels
_ERP_MODULE_MAP = {
    "CRM": "CRM", "Email": "CRM", "crm": "CRM",
    "Finance": "Finance", "Payment": "Finance",
    "HR": "HR", "Procurement": "Procurement",
    "Forms": "CRM", "Website": "CRM",
    "AttackLab": "Demo", "generic": "System",
}


def _to_erp_module(raw: str) -> str:
    return _ERP_MODULE_MAP.get(raw or "", raw or "System")


def _normalized_decision(value: str) -> str:
    d = (value or "").strip().lower()
    if d == "sanitize":
        return "block"
    return d or "allow"


@router.get("", response_model=MetricsResponse)
@router.get("/", response_model=MetricsResponse)
async def get_metrics():
    logs = get_request_log()
    if not logs:
        return _demo_metrics()

    total = len(logs)
    blocked = sum(1 for l in logs if _normalized_decision(l.get("decision")) == "block")
    warned = sum(1 for l in logs if _normalized_decision(l.get("decision")) == "warn")
    allowed = total - blocked - warned
    avg_risk = sum(l.get("risk_score", 0) for l in logs) / total

    by_module: dict = defaultdict(int)
    erp_breakdown: dict = defaultdict(int)
    for l in logs:
        if _normalized_decision(l.get("decision")) in ("block", "warn"):
            raw_mod = l.get("module", "unknown")
            by_module[raw_mod] += 1
            erp_breakdown[_to_erp_module(raw_mod)] += 1

    dist = {
        "low": sum(1 for l in logs if l.get("risk_score", 0) < 0.30),
        "medium": sum(1 for l in logs if 0.30 <= l.get("risk_score", 0) < 0.70),
        "high": sum(1 for l in logs if l.get("risk_score", 0) >= 0.70),
    }

    recent = [
        {
            "request_id": l.get("request_id", ""),
            "erp_module": _to_erp_module(l.get("module", "")),
            "module": l.get("module", ""),
            "user_id": l.get("user_id", "—"),
            "action": l.get("action", l.get("type", "activity")),
            "risk_score": l.get("risk_score", 0),
            "decision": _normalized_decision(l.get("decision")).upper(),
            "erp_impact": (
                "transaction_blocked" if _normalized_decision(l.get("decision")) == "block"
                else "flagged_for_review" if _normalized_decision(l.get("decision")) == "warn"
                else "transaction_approved"
            ),
            "patterns": l.get("patterns", [])[:2],
        }
        for l in reversed(logs)
        if _normalized_decision(l.get("decision")) in ("block", "warn")
    ][:10]

    eng = get_engine_stats()

    return MetricsResponse(
        total_requests=total,
        blocked_count=blocked,
        warned_count=warned,
        allowed_count=allowed,
        block_rate=round(blocked / total * 100, 1),
        avg_risk_score=round(avg_risk, 3),
        threats_by_module=dict(by_module),
        risk_distribution=dist,
        recent_attacks=recent,
        llm_calls_total=eng.get("llm_calls", 0),
        llm_calls_skipped=eng.get("llm_skipped", 0),
        decision_cache_hits=eng.get("cache_hits", 0),
        erp_module_breakdown=dict(erp_breakdown),
        recent_decisions=recent,
        network_risk_events=sum(1 for l in logs if l.get("erp_context", {}).get("network") == "risky"),
    )


def _demo_metrics() -> MetricsResponse:
    recent_decisions = [
        {
            "request_id": "a1b2c3", "erp_module": "CRM", "module": "CRM",
            "user_id": "emp_042", "risk_score": 0.94, "decision": "BLOCK",
            "erp_impact": "transaction_blocked", "patterns": ["sql_injection"],
        },
        {
            "request_id": "d4e5f6", "erp_module": "Finance", "module": "Finance",
            "user_id": "emp_017", "risk_score": 0.88, "decision": "BLOCK",
            "erp_impact": "transaction_blocked", "patterns": ["prompt_injection"],
        },
        {
            "request_id": "g7h8i9", "erp_module": "HR", "module": "HR",
            "user_id": "emp_031", "risk_score": 0.47, "decision": "WARN",
            "erp_impact": "flagged_for_review", "patterns": ["xss"],
        },
    ]
    return MetricsResponse(
        total_requests=312, blocked_count=18, warned_count=41, allowed_count=253,
        block_rate=5.8, avg_risk_score=0.21,
        threats_by_module={"CRM": 35, "Finance": 14, "HR": 10},
        risk_distribution={"low": 253, "medium": 41, "high": 18},
        recent_attacks=recent_decisions,
        llm_calls_total=42, llm_calls_skipped=198, decision_cache_hits=61,
        erp_module_breakdown={"CRM": 35, "Finance": 14, "HR": 10},
        recent_decisions=recent_decisions,
        network_risk_events=3,
    )


@agents_router.get("/multilingual/stats")
async def multilingual_agent_stats():
    """Rolling multilingual agent telemetry (last 1000 samples in-process)."""
    return MultilingualAgent.get_stats()


@agents_router.get("/behaviour/{user_id}")
async def user_behaviour_fingerprint(user_id: str):
    """Per-user behavioural fingerprint profile."""
    from ..agents.behavior_agent import get_user_fingerprint
    return get_user_fingerprint(user_id)


@ml_router.get("/tier-stats")
async def tier_stats():
    """Tier decision counters (tier1/2/3 calls + LLM-savings %)."""
    from ..utils.tier_stats import get_stats
    return get_stats()


@ml_router.get("/drift-status")
async def drift_status():
    """PSI drift detector status: drift_detected, psi_scores, alert_count."""
    from ..core.ml.drift_detector import get_drift_detector
    return get_drift_detector().status()


@ml_router.get("/temporal-stats")
async def temporal_stats():
    """Temporal signal fired distribution."""
    from ..core.ml.temporal_scorer import get_temporal_stats
    return get_temporal_stats()


@ml_router.get("/retraining-log")
async def retraining_log():
    """Last 20 retraining events from the active feedback loop."""
    from ..core.ml.retraining_loop import get_retraining_log
    return {"events": get_retraining_log(20)}


@ml_router.get("/model-health")
async def model_health():
    """Model health: error rates, retraining count, LLM savings, Bayesian threshold."""
    from ..core.ml.retraining_loop import get_model_health
    from ..core.ml.bayesian_threshold import get_bayesian_engine
    health = get_model_health()
    health["bayesian_threshold"] = get_bayesian_engine().status()
    return health


@ml_router.get("/bayesian-threshold")
async def bayesian_threshold_status():
    """Bayesian BLOCK threshold state: alpha/beta, credible interval, per-class thresholds."""
    from ..core.ml.bayesian_threshold import get_bayesian_engine
    return get_bayesian_engine().status()


@ml_router.get("/lora-finetune/status")
async def lora_finetune_status():
    """Current LoRA controller status and feedback summary."""
    from ..core.ml.lora_finetune_controller import get_lora_controller_status
    return get_lora_controller_status()


@ml_router.post("/lora-finetune/decision")
async def lora_finetune_decision(payload: dict = Body(default_factory=dict)):
    """Daily scheduler endpoint: decide whether Tier 2 LoRA fine-tuning should run."""
    from ..core.ml.lora_finetune_controller import decide_lora_finetune
    return decide_lora_finetune(payload)


@ml_router.get("/gpu-stats")
async def gpu_stats():
    """AMD GPU memory, utilisation, and inference counters."""
    from ..utils.gpu_monitor import get_gpu_stats
    return get_gpu_stats()


@ml_router.get("/full-stats")
async def full_stats():
    """Single aggregated endpoint for demo dashboard polling."""
    from ..utils.tier_stats import get_stats as tier_stats
    from ..utils.gpu_monitor import get_gpu_stats
    from ..core.ml.drift_detector import get_drift_detector
    from ..core.ml.retraining_loop import get_model_health
    from ..core.ml.temporal_scorer import get_temporal_stats
    from ..agents.investigation_room import get_investigations

    logs = get_request_log()
    total = len(logs)
    blocked = sum(1 for l in logs if _normalized_decision(l.get("decision")) == "block")
    avg_risk = round(sum(l.get("risk_score", 0) for l in logs) / total, 3) if total else 0.0
    tier = tier_stats()

    investigations = get_investigations(100)
    active_inv = sum(
        1 for inv in investigations
        if inv.get("human_required") and inv.get("approved") is None
    )

    recent_decisions = [
        {
            "time": l.get("timestamp") or "",
            "request_id": l.get("request_id", ""),
            "source_system": l.get("source_system", l.get("module", "odoo")),
            "script_detected": l.get("script_detected", "latin"),
            "tier_used": l.get("tier_used", 1),
            "risk_score": l.get("risk_score", 0),
            "decision": _normalized_decision(l.get("decision")).upper(),
            "user_id": l.get("user_id", ""),
            "jira_ticket_key": l.get("jira_ticket_key") or "",
            "jira_ticket_url": l.get("jira_ticket_url") or "",
        }
        for l in reversed(logs[-20:])
    ]

    return {
        "summary": {
            "total_scans": total,
            "blocked": blocked,
            "llm_calls_saved_pct": tier.get("llm_savings_pct", 0.0),
            "avg_score": avg_risk,
            "active_investigations": active_inv,
        },
        "tier_stats": tier,
        "gpu_stats": get_gpu_stats(),
        "drift_status": get_drift_detector().status(),
        "model_health": get_model_health(),
        "multilingual_stats": MultilingualAgent.get_stats(),
        "temporal_stats": get_temporal_stats(),
        "recent_decisions": recent_decisions,
    }

"""
Universal REST API (/v1/*) — integrate SafeO with any system, not just Odoo.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..agents.behavior_agent import behavioural_risk_score
from ..core.ml.llm_guard import is_llm_available, llm_assess_payload, llm_enabled
from ..core.ml.risk_scorer import calculate_risk_score
from ..core.ml.tiered_llm import run_tiered_scoring
from ..core.ml.retraining_loop import get_feedback_store
from ..core.ml.bayesian_threshold import (
    decision_label,
    get_bayesian_engine,
    infer_attack_class,
)
from .waf import append_request_log

router = APIRouter(prefix="/v1", tags=["Universal API"])

_START_TIME = time.time()
_scan_store: Dict[str, Dict[str, Any]] = {}


class ScanContext(BaseModel):
    user_id: str = "anonymous"
    source_system: str = "api"
    field_name: Optional[str] = None
    ip: Optional[str] = None
    timestamp: Optional[str] = None


class ScanRequest(BaseModel):
    input: str
    context: ScanContext = Field(default_factory=ScanContext)


class BatchScanRequest(BaseModel):
    inputs: List[str] = Field(..., max_length=50)
    context: ScanContext = Field(default_factory=ScanContext)


class FeedbackV1Request(BaseModel):
    scan_id: str
    verdict: str  # correct | false_positive | false_negative
    reviewer: str = "api"


def _decision_label(score: float, patterns: Optional[List[str]] = None, script: str = "latin") -> str:
    attack_class = infer_attack_class(patterns or [], script)
    return decision_label(score, attack_class=attack_class)


async def _run_scan(input_text: str, context: ScanContext) -> Dict[str, Any]:
    scan_id = str(uuid.uuid4())[:12]
    user_id = context.user_id or "anonymous"
    beh = behavioural_risk_score(user_id, input_text, context.field_name)

    tier1_score, _, patterns, explanations, meta = calculate_risk_score(
        input_text,
        user_id=user_id,
        behavioural_risk=beh,
    )

    from ..agents.multilingual_agent import get_multilingual_agent
    ml_norm = get_multilingual_agent().analyse(input_text).get("normalised", input_text)

    adjusted_score, tier_used, tier_meta = run_tiered_scoring(
        tier1_score, patterns, input_text
    )

    llm_score: Optional[float] = None
    final_score = adjusted_score
    if tier_used == 3 and llm_enabled():
        llm = llm_assess_payload(input_text)
        if llm.get("enabled") and "risk_score" in llm:
            llm_score = float(llm["risk_score"])
            final_score = round(
                min(1.0, max(adjusted_score, adjusted_score * 0.75 + llm_score * 0.25)), 3
            )

    decision = _decision_label(final_score, patterns, meta.get("script_detected", "latin"))
    tier2_score = tier_meta.get("tier2_score") if tier_used == 2 else None
    attack_class = infer_attack_class(patterns, meta.get("script_detected", "latin"))
    block_threshold = get_bayesian_engine().get_block_threshold(attack_class)

    result: Dict[str, Any] = {
        "scan_id": scan_id,
        "risk_score": round(final_score, 3),
        "risk_score_pct": round(final_score * 100),
        "decision": decision,
        "tier1_score": round(tier1_score, 3),
        "tier2_score": round(tier2_score, 3) if tier2_score is not None else None,
        "llm_score": round(llm_score, 3) if llm_score is not None else None,
        "tier_used": tier_used,
        "attack_class": attack_class,
        "block_threshold": round(block_threshold, 4),
        "matched_patterns": patterns[:10],
        "explanations": explanations,
        "behavioural_risk_score": beh,
        "script_detected": meta.get("script_detected", "latin"),
        "temporal_boost": meta.get("temporal_boost", 0.0),
        "uncertainty_score": round(1.0 - min(final_score, 0.99), 3),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if meta.get("url_analysis"):
        result["url_analysis"] = meta["url_analysis"]

    from ..agents.attack_graph import query_graph
    graph_evidence = query_graph(patterns)
    if graph_evidence:
        result["graph_evidence"] = graph_evidence.to_dict()

    audit_payload = f"{scan_id}|{input_text}|{decision}|{final_score}"
    result["audit_hash"] = hashlib.sha256(audit_payload.encode()).hexdigest()

    # Fire async LangGraph investigation for WARN/BLOCK decisions.
    if decision in ("WARN", "BLOCK"):
        from ..agents.investigation_room import run_investigation
        investigation_meta = {**meta, "tier_used": tier_used}
        asyncio.create_task(
            run_investigation(
                scan_id=scan_id,
                payload=input_text,
                risk_score=final_score,
                decision=decision,
                patterns=patterns,
                meta=investigation_meta,
                context={
                    "user_id": user_id,
                    "jurisdiction": "UAE",
                    "source_system": context.source_system or "api",
                },
                behavior_score=beh,
            )
        )

    _scan_store[scan_id] = {
        "scan_id": scan_id,
        "original_input": input_text,
        "normalised_input": ml_norm,
        "tier1_score": tier1_score,
        "tier2_score": tier2_score or 0.0,
        "llm_score": llm_score or 0.0,
        "final_decision": decision,
        "matched_patterns": patterns,
        "risk_score": final_score,
        "tier_used": tier_used,
        "attack_class": attack_class,
        "script_detected": meta.get("script_detected", "latin"),
    }

    append_request_log({
        "request_id": scan_id,
        "module": context.source_system or "api",
        "source_system": context.source_system or "api",
        "risk_score": final_score,
        "decision": decision.lower(),
        "user_id": user_id,
        "patterns": patterns[:5],
        "type": "v1_scan",
        "field_name": context.field_name,
        "ip": context.ip,
        "script_detected": meta.get("script_detected", "latin"),
        "tier_used": tier_used,
        "evasion_suspected": meta.get("evasion_suspected", False),
        "timestamp": result["timestamp"],
    })

    return result


@router.post("/scan")
async def scan(req: ScanRequest):
    """Scan a single input and return a full risk decision."""
    return await _run_scan(req.input, req.context)


@router.post("/scan/batch")
async def scan_batch(req: BatchScanRequest):
    """Scan up to 50 inputs concurrently."""
    if len(req.inputs) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 inputs per batch")
    tasks = [_run_scan(text, req.context) for text in req.inputs]
    return await asyncio.gather(*tasks)


@router.get("/health")
async def v1_health():
    """Service health with component availability flags."""
    gpu_available = False
    try:
        import torch
        gpu_available = torch.cuda.is_available()
    except ImportError:
        pass

    tier2_loaded = False
    try:
        from ..core.ml.tier2_classifier import get_tier2_classifier
        clf = get_tier2_classifier()
        tier2_loaded = clf._ready
    except Exception:
        pass

    ml_loaded = False
    try:
        from ..agents.multilingual_agent import MultilingualAgent
        ml_loaded = MultilingualAgent._model is not None
    except Exception:
        pass

    return {
        "status": "ok",
        "gpu_available": gpu_available,
        "vllm_available": is_llm_available(),
        "tier2_loaded": tier2_loaded,
        "multilingual_model_loaded": ml_loaded,
        "uptime_seconds": round(time.time() - _START_TIME, 1),
        "agent_orchestrator": "langgraph_local",
        "last_forensics_model_used": _last_forensics_model(),
    }


def _last_forensics_model() -> Optional[str]:
    try:
        from ..agents.forensics_agent import get_last_forensics_model_used
        return get_last_forensics_model_used()
    except Exception:
        return None


@router.post("/feedback")
async def submit_feedback_v1(req: FeedbackV1Request):
    """Record human verdict for a prior scan (drives retraining + Bayesian threshold)."""
    if req.verdict not in ("correct", "false_positive", "false_negative"):
        raise HTTPException(
            status_code=400,
            detail="verdict must be correct, false_positive, or false_negative",
        )

    scan = _scan_store.get(req.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"scan_id {req.scan_id} not found")

    row_id = get_feedback_store().record(scan, req.verdict, req.reviewer)
    threshold_update = get_bayesian_engine().status().get("last_update") or {}

    return {
        "status": "accepted",
        "feedback_id": row_id,
        "verdict": req.verdict,
        "threshold_update": threshold_update,
    }


def get_scan_record(scan_id: str) -> Optional[Dict[str, Any]]:
    return _scan_store.get(scan_id)

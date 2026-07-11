"""
Legacy-compatible WAF routes plus in-memory request log shared with ERP routes.

`/waf/input` runs the core risk engine (see `core.ml.risk_scorer`); results feed
Odoo metrics when proxied. Use `/erp/*` for ERP-native payloads in demos.
"""
import hashlib
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter

from ..agents.input_agent import InputAgent
from ..agents.output_agent import OutputAgent
from ..core.ml.llm_guard import llm_assess_payload, llm_enabled
from ..core.ml.risk_scorer import calculate_risk_score
from ..core.ml.tiered_llm import should_invoke_llm
from ..models.schemas import WAFInputRequest, WAFOutputRequest, WAFResponse, AgentResult

router = APIRouter(prefix="/waf", tags=["Risk Engine (Legacy WAF Compatibility)"])
_input_agent = InputAgent()
_output_agent = OutputAgent()

_request_log: list = []
_engine_stats = {
    "llm_calls": 0,
    "llm_skipped": 0,
    "cache_hits": 0,
}
_CACHE_TTL_SEC = 90
_CACHE_MAX = 400
_decision_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def get_request_log():
    return _request_log


def find_request_log_entry(request_id: str) -> Optional[Dict[str, Any]]:
    """Return the most recent log entry matching request_id."""
    for entry in reversed(_request_log):
        if entry.get("request_id") == request_id:
            return entry
    return None


def append_request_log(entry: Dict[str, Any]) -> None:
    """Shared logging hook so ERP-native routes can feed dashboard metrics."""
    if "source_system" not in entry:
        entry["source_system"] = "odoo"
    _request_log.append(entry)


def get_engine_stats():
    return dict(_engine_stats)


def _norm_cache_key(module: str, text: str) -> str:
    n = (text or "").strip().lower()[:4000]
    return hashlib.sha256(f"{module or ''}|{n}".encode()).hexdigest()


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    entry = _decision_cache.get(key)
    if not entry:
        return None
    expires_at, payload = entry
    if time.time() > expires_at:
        _decision_cache.pop(key, None)
        return None
    return payload


def _cache_set(key: str, payload: Dict[str, Any]) -> None:
    _decision_cache[key] = (time.time() + _CACHE_TTL_SEC, payload)
    while len(_decision_cache) > _CACHE_MAX:
        _decision_cache.pop(next(iter(_decision_cache)))


def _serialize_agent(ar: AgentResult) -> Dict[str, Any]:
    return ar.model_dump()


def _deserialize_agent(d: Dict[str, Any]) -> AgentResult:
    return AgentResult(**d)


@router.post("/input", response_model=WAFResponse)
async def analyze_input(req: WAFInputRequest):
    """Analyze incoming input text for security threats."""
    rid = str(uuid.uuid4())[:8]
    ckey = _norm_cache_key(req.module or "", req.input_text or "")
    cached = _cache_get(ckey)
    if cached is not None:
        _engine_stats["cache_hits"] += 1
        _request_log.append({
            "request_id": rid,
            "module": req.module,
            "risk_score": cached["risk_score"],
            "decision": cached["decision"],
            "user_id": req.user_id,
            "patterns": list(cached.get("detected_patterns") or []),
            "type": "input",
            "cache_hit": True,
        })
        agents = [_deserialize_agent(a) for a in cached["agents"]]
        return WAFResponse(
            risk_score=cached["risk_score"],
            decision=cached["decision"],
            explanation=cached["explanation"],
            detected_patterns=list(cached["detected_patterns"]),
            agents=agents,
            sanitized_text=cached.get("sanitized_text"),
            request_id=rid,
            llm_used=cached.get("llm_used"),
            decision_cache_hit=True,
            engine_note="decision_cache_hit",
        )

    risk_score, decision, patterns, explanations, _meta = calculate_risk_score(req.input_text)
    llm_used = False
    engine_note = ""
    if llm_enabled():
        call_llm, skip_reason = should_invoke_llm(risk_score, patterns, req.input_text or "")
        if call_llm:
            llm = llm_assess_payload(req.input_text)
            if llm.get("enabled"):
                _engine_stats["llm_calls"] += 1
                llm_used = True
                if llm.get("error"):
                    explanations.append(f"LLM augmentation error: {str(llm.get('error'))[:160]}")
                if "risk_score" in llm:
                    llm_risk = float(llm["risk_score"])
                    fused_risk = min(1.0, max(risk_score, risk_score * 0.75 + llm_risk * 0.25))
                    if llm_risk > 0.65:
                        patterns.append(
                            f"llm_semantic:{','.join(llm.get('attack_types', [])) or 'suspicious_intent'}"
                        )
                        explanations.append(
                            f"LLM semantic detector: {llm.get('rationale', 'high-risk intent')}"
                        )
                    risk_score = round(fused_risk, 3)
                    if risk_score >= 0.70:
                        decision = "block"
                    elif risk_score >= 0.30:
                        decision = "warn"
                    else:
                        decision = "allow"
            else:
                _engine_stats["llm_skipped"] += 1
                engine_note = str(llm.get("error") or "llm_not_configured")
        else:
            _engine_stats["llm_skipped"] += 1
            engine_note = skip_reason
    else:
        _engine_stats["llm_skipped"] += 1
        engine_note = "llm_disabled"

    agent_result = _input_agent.analyze(req.input_text, req.context or {})

    sanitized = None
    if decision in ("block", "sanitize"):
        sanitized = _input_agent.sanitize(req.input_text)
        if sanitized != req.input_text and decision == "block":
            decision = "sanitize"

    _request_log.append({
        "request_id": rid,
        "module": req.module,
        "risk_score": risk_score,
        "decision": decision,
        "user_id": req.user_id,
        "patterns": patterns,
        "type": "input",
    })

    out = WAFResponse(
        risk_score=risk_score,
        decision=decision,
        explanation=" | ".join(explanations),
        detected_patterns=patterns,
        agents=[agent_result],
        sanitized_text=sanitized,
        request_id=rid,
        llm_used=llm_used,
        decision_cache_hit=False,
        engine_note=engine_note or None,
    )
    _cache_set(
        ckey,
        {
            "risk_score": out.risk_score,
            "decision": out.decision,
            "explanation": out.explanation,
            "detected_patterns": list(out.detected_patterns),
            "agents": [_serialize_agent(agent_result)],
            "sanitized_text": out.sanitized_text,
            "llm_used": llm_used,
        },
    )
    return out


@router.post("/output", response_model=WAFResponse)
async def analyze_output(req: WAFOutputRequest):
    """Scan outgoing content for sensitive data leakage."""
    rid = str(uuid.uuid4())[:8]
    agent_result = _output_agent.analyze(req.output_text)
    risk_score = min(len(agent_result.detected_patterns) * 0.25, 1.0)

    sanitized = None
    if agent_result.decision in ("sanitize", "block"):
        sanitized = _output_agent.sanitize(req.output_text)

    explanation = (
        f"Output scan: {', '.join(agent_result.detected_patterns)}"
        if agent_result.detected_patterns
        else "No sensitive data detected in output"
    )

    _request_log.append({
        "request_id": rid,
        "module": req.module,
        "risk_score": round(risk_score, 3),
        "decision": agent_result.decision,
        "type": "output",
    })

    return WAFResponse(
        risk_score=round(risk_score, 3),
        decision=agent_result.decision,
        explanation=explanation,
        detected_patterns=agent_result.detected_patterns,
        agents=[agent_result],
        sanitized_text=sanitized,
        request_id=rid,
        llm_used=False,
        decision_cache_hit=False,
        engine_note="output_scan",
    )

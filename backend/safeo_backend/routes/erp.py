"""
ERP-native HTTP API: transactions, HR activity, CRM lead gate, finance actions,
dashboard summary, and mock network signal. Each handler calls `calculate_risk_score`
and appends to the shared log via `routes.waf.append_request_log` for dashboard metrics.
"""
import asyncio
import uuid
import time
import random
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, BackgroundTasks

from ..core.ml.risk_scorer import calculate_risk_score
from ..agents.behavior_agent import BehaviorAgent
from ..models.schemas import (
    TransactionRiskRequest,
    EmployeeActivityRequest,
    CRMLeadRequest,
    FinancialActionRequest,
    ERPDecisionResponse,
    NetworkSignalResponse,
)
from .waf import append_request_log

router = APIRouter(prefix="/erp", tags=["ERP Decision Engine"])

_behavior_agent = BehaviorAgent()
_erp_audit_trail: List[Dict[str, Any]] = []
_employees: Dict[str, Dict[str, Any]] = {}
_transactions: Dict[str, Dict[str, Any]] = {}
_crm_leads: Dict[str, Dict[str, Any]] = {}
_finance_actions: Dict[str, Dict[str, Any]] = {}

# ── Network signal mock: slow-drifting state ──────────────────────────────────
_NET_STATE = {"signal": "safe", "last_flip": time.time(), "flip_gap": 120}

# ERP module descriptions for richer explanations
_MODULE_CONTEXT = {
    "Finance": "financial transaction processing",
    "CRM": "CRM lead and contact data",
    "HR": "employee record and payroll",
    "Procurement": "purchase order and vendor management",
    "Auth": "authentication and access control",
}


def _get_network_signal() -> str:
    """Return current mock network signal, occasionally flipping to 'risky'."""
    now = time.time()
    if now - _NET_STATE["last_flip"] > _NET_STATE["flip_gap"]:
        # 25% chance to flip state
        if random.random() < 0.25:
            _NET_STATE["signal"] = "risky" if _NET_STATE["signal"] == "safe" else "safe"
        _NET_STATE["last_flip"] = now
    return _NET_STATE["signal"]


def _network_boost(signal: str) -> float:
    """Extra risk points when network environment is risky."""
    return 0.15 if signal == "risky" else 0.0


def _erp_decision(raw_score: float) -> str:
    if raw_score >= 0.70:
        return "BLOCK"
    elif raw_score >= 0.30:
        return "WARN"
    return "ALLOW"


def _log_decision(
    *,
    request_id: str,
    action: str,
    module: str,
    user_id: str,
    score: float,
    decision: str,
    patterns: List[str],
    network_signal: str,
    impact: str,
) -> None:
    """Append ERP decisions to shared metrics feed and ERP audit trail."""
    lower_decision = (decision or "ALLOW").lower()
    entry = {
        "request_id": request_id,
        "module": module,
        "risk_score": score,
        "decision": lower_decision,
        "user_id": user_id,
        "patterns": patterns[:5],
        "type": "erp_action",
        "action": action,
        "erp_context": {"network": network_signal, "impact": impact},
    }
    append_request_log(entry)
    _erp_audit_trail.append(
        {
            **entry,
            "decision": decision,
            "risk_score": round(score * 100),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def _erp_impact(decision: str, transaction_type: Optional[str] = None) -> str:
    if decision == "BLOCK":
        if transaction_type in ("payment", "invoice", "procurement"):
            return "transaction_blocked"
        return "action_blocked"
    if decision == "WARN":
        return "flagged_for_review"
    return "transaction_approved"


def _build_reason(patterns, categories, explanation_parts, module, network_signal):
    """Build a human-readable ERP-style reason string."""
    ctx = _MODULE_CONTEXT.get(module, module)
    if not patterns and not categories:
        base = f"No risk patterns detected in {ctx}"
    else:
        pattern_str = ", ".join(patterns[:3]) if patterns else "unknown pattern"
        base = f"Risk detected in {ctx}: {pattern_str}"
    if network_signal == "risky":
        base += " (elevated due to risky network environment)"
    return base[:320]


async def _fire_investigation(rid: str, text: str, score: float, decision: str,
                             patterns: list, meta: dict, user_id: str) -> None:
    """Background investigation — triggered on WARN/BLOCK decisions."""
    from ..agents.investigation_room import run_investigation
    try:
        await run_investigation(
            scan_id=rid,
            payload=text,
            risk_score=score,
            decision=decision,
            patterns=patterns,
            meta={**meta, "tier_used": meta.get("tier_used", 1)},
            context={"user_id": user_id, "jurisdiction": "UAE", "source_system": "erp"},
        )
    except Exception as exc:
        import logging
        logging.getLogger("safeo.erp").warning("investigation failed for %s: %s", rid, exc)


def _evaluate_erp_text(
    *,
    text: str,
    module: str,
    user_id: str,
    action: str,
    network_context: Optional[str],
    transaction_type: Optional[str] = None,
) -> ERPDecisionResponse:
    rid = str(uuid.uuid4())[:8]
    net_signal = network_context or _get_network_signal()
    boost = _network_boost(net_signal)
    raw_score, _, patterns, explanations, _meta = calculate_risk_score(text, user_id=user_id or "anonymous")
    final_score = round(min(raw_score + boost, 1.0), 3)
    decision = _erp_decision(final_score)
    impact = _erp_impact(decision, transaction_type)
    reason = _build_reason(patterns, [], explanations, module, net_signal)
    _log_decision(
        request_id=rid,
        action=action,
        module=module,
        user_id=user_id or "anonymous",
        score=final_score,
        decision=decision,
        patterns=patterns,
        network_signal=net_signal,
        impact=impact,
    )

    # Fire background investigation for WARN/BLOCK decisions
    if decision in ("WARN", "BLOCK"):
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(
                _fire_investigation(rid, text, final_score, decision, patterns, _meta, user_id or "anonymous")
            )
        except RuntimeError:
            pass  # no event loop in sync context — investigation skipped

    return ERPDecisionResponse(
        request_id=rid,
        risk_score=round(final_score * 100),
        risk_score_raw=final_score,
        decision=decision,
        reason=reason,
        affected_module=module,
        user_id=user_id or "anonymous",
        network_signal=net_signal,
        erp_impact=impact,
        detected_patterns=patterns[:5],
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.post("/transaction", response_model=ERPDecisionResponse)
async def analyze_transaction(req: TransactionRiskRequest):
    """Transaction Risk Analysis — scan an ERP transaction description for risk."""
    module = req.erp_module or "Finance"
    result = _evaluate_erp_text(
        text=req.description,
        module=module,
        user_id=req.user_id or "anonymous",
        action=f"transaction:{req.transaction_type or 'payment'}",
        network_context=req.network_context,
        transaction_type=req.transaction_type,
    )
    txn_id = req.transaction_id or f"txn_{result.request_id}"
    _transactions[txn_id] = {
        "transaction_id": txn_id,
        "amount": req.amount,
        "transaction_type": req.transaction_type,
        "description": req.description,
        "user_id": req.user_id or "anonymous",
        "module": module,
        "status": "blocked" if result.decision == "BLOCK" else "flagged" if result.decision == "WARN" else "approved",
        "decision": result.decision,
        "risk_score": result.risk_score,
        "timestamp": result.timestamp,
    }
    return result


@router.post("/employee/activity", response_model=ERPDecisionResponse)
async def analyze_employee_activity(req: EmployeeActivityRequest):
    """Employee Activity Monitoring — assess risk of an employee action."""
    rid = str(uuid.uuid4())[:8]
    net_signal = req.network_context or _get_network_signal()
    boost = _network_boost(net_signal)

    # Run the action text through the risk scorer for malicious intent
    text_score, _, patterns, explanations, _meta = calculate_risk_score(req.action, user_id=req.employee_id)

    # Run through behavior agent for anomaly detection
    behavior = _behavior_agent.track_action(req.employee_id, req.action)
    behavior_contrib = behavior.risk_score * 0.4

    final_score = min(text_score * 0.6 + behavior_contrib + boost, 1.0)
    final_score = round(final_score, 3)
    decision = _erp_decision(final_score)
    module = req.erp_module or "HR"
    impact = _erp_impact(decision)

    # Build enriched reason
    if behavior.anomaly_detected:
        reason = f"Behavioral anomaly for employee {req.employee_id}: {behavior.explanation}"
        if patterns:
            reason += f". Also flagged: {', '.join(patterns[:2])}"
    else:
        reason = _build_reason(patterns, [], explanations, module, net_signal)

    if net_signal == "risky":
        reason += " (risky network context)"

    _employees[req.employee_id] = {
        "employee_id": req.employee_id,
        "role": req.role,
        "department": req.department,
        "last_action": req.action,
        "risk_score": round(final_score * 100),
        "decision": decision,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _log_decision(
        request_id=rid,
        action=f"employee_activity:{req.action[:40]}",
        module=module,
        user_id=req.employee_id,
        score=final_score,
        decision=decision,
        patterns=patterns,
        network_signal=net_signal,
        impact=impact,
    )

    return ERPDecisionResponse(
        request_id=rid,
        risk_score=round(final_score * 100),
        risk_score_raw=final_score,
        decision=decision,
        reason=reason[:320],
        affected_module=module,
        user_id=req.employee_id,
        network_signal=net_signal,
        erp_impact=impact,
        detected_patterns=patterns[:5],
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.post("/crm/lead", response_model=ERPDecisionResponse)
async def analyze_crm_lead(payload: CRMLeadRequest):
    """CRM lead gate: scan lead content before create/update."""
    name = str(payload.name or "Unnamed Lead")
    message = str(payload.message or "")
    source = str(payload.source or "web")
    user_id = str(payload.user_id or "crm_user")
    network_context = payload.network_context or "safe"
    text = f"lead_name={name} | source={source} | message={message}"
    result = _evaluate_erp_text(
        text=text,
        module="CRM",
        user_id=user_id,
        action="crm_lead_submission",
        network_context=network_context,
        transaction_type="approval",
    )
    lead_id = str(payload.lead_id or f"lead_{result.request_id}")
    if result.decision != "BLOCK":
        _crm_leads[lead_id] = {
            "lead_id": lead_id,
            "name": name,
            "message": message[:400],
            "source": source,
            "status": "needs_review" if result.decision == "WARN" else "captured",
            "risk_score": result.risk_score,
            "decision": result.decision,
            "user_id": user_id,
            "timestamp": result.timestamp,
        }
    return result


@router.post("/finance/action", response_model=ERPDecisionResponse)
async def analyze_finance_action(payload: FinancialActionRequest):
    """Finance action gate: payment/approval evaluated before execution."""
    action_type = str(payload.action_type or "payment")
    amount = payload.amount
    approver = str(payload.approver_id or "finance_user")
    notes = str(payload.notes or "")
    network_context = payload.network_context or "safe"
    text = f"action={action_type} | amount={amount} | notes={notes}"
    result = _evaluate_erp_text(
        text=text,
        module="Finance",
        user_id=approver,
        action=f"finance:{action_type}",
        network_context=network_context,
        transaction_type=action_type,
    )
    action_id = str(payload.action_id or f"fin_{result.request_id}")
    if result.decision != "BLOCK":
        _finance_actions[action_id] = {
            "action_id": action_id,
            "action_type": action_type,
            "amount": amount,
            "approver_id": approver,
            "status": "flagged_review" if result.decision == "WARN" else "completed",
            "risk_score": result.risk_score,
            "decision": result.decision,
            "timestamp": result.timestamp,
        }
    return result


@router.get("/dashboard/summary")
async def erp_dashboard_summary():
    """ERP dashboard payload for demo UIs."""
    suspicious = [r for r in _erp_audit_trail if r.get("decision") in ("WARN", "BLOCK")]
    return {
        "transaction_risk_monitor": list(_transactions.values())[-10:],
        "employee_risk_profiles": list(_employees.values())[-10:],
        "suspicious_activities": suspicious[-10:],
        "recent_security_decisions": list(reversed(_erp_audit_trail[-15:])),
        "crm_leads": list(_crm_leads.values())[-10:],
        "financial_actions": list(_finance_actions.values())[-10:],
    }


@router.get("/network/signal", response_model=NetworkSignalResponse)
async def get_network_signal():
    """Network Environment Signal — returns current mock network safety context."""
    sig = _get_network_signal()
    boost = _network_boost(sig)
    if sig == "risky":
        reason = "Network environment classified as risky: elevated packet anomaly score detected on monitored segments."
    else:
        reason = "Network environment is safe: no anomalies on monitored segments."
    return NetworkSignalResponse(signal=sig, reason=reason, risk_boost=boost)


@router.post("/network/signal", response_model=NetworkSignalResponse)
async def set_network_signal(payload: Dict[str, str]):
    """Allow demo operators to force network signal safe/risky."""
    sig = (payload.get("signal") or "").strip().lower()
    if sig in ("safe", "risky"):
        _NET_STATE["signal"] = sig
        _NET_STATE["last_flip"] = time.time()
    current = _get_network_signal()
    boost = _network_boost(current)
    reason = (
        "Operator set network environment to risky for scenario testing."
        if current == "risky"
        else "Operator set network environment to safe baseline."
    )
    return NetworkSignalResponse(signal=current, reason=reason, risk_boost=boost)

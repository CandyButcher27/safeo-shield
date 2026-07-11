"""Investigation log endpoints — list, detail, approve, reject, audit chain."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from ..agents.investigation_room import (
    get_investigations,
    get_investigation,
    approve_investigation,
    reject_investigation,
    verify_audit_chain,
)
from ..core.ml.retraining_loop import get_feedback_store
from ..utils.ws_broadcaster import broadcaster
from ..utils.agent_log_synth import synthesize_agent_log

router = APIRouter(prefix="/investigations", tags=["Investigations"])


class ApproveRequest(BaseModel):
    reviewer: str


class RejectRequest(BaseModel):
    reviewer: str
    reason: str


@router.get("")
@router.get("/")
async def list_investigations():
    return [
        {
            "scan_id":       inv["scan_id"],
            "timestamp":     inv["timestamp"],
            "final_verdict": inv["final_verdict"],
            "human_required": inv["human_required"],
            "approved":      inv.get("approved"),
            "investigation_hash": inv.get("investigation_hash"),
        }
        for inv in get_investigations(20)
    ]


@router.get("/audit-chain")
async def audit_chain_integrity():
    """Verify SHA-256 hash chain integrity across all stored investigations."""
    return verify_audit_chain()


@router.get("/{scan_id}")
async def investigation_detail(scan_id: str):
    inv = get_investigation(scan_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    agent_log = broadcaster.get_history(scan_id)
    if not agent_log:
        agent_log = synthesize_agent_log(inv)
    return {**inv, "agent_log": agent_log}


@router.post("/{scan_id}/approve")
async def approve(scan_id: str, body: ApproveRequest):
    inv = approve_investigation(scan_id, body.reviewer)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _record_investigation_feedback(inv, "correct", body.reviewer)
    return {"ok": True, "scan_id": scan_id, "reviewer": body.reviewer}


@router.post("/{scan_id}/reject")
async def reject(scan_id: str, body: RejectRequest):
    inv = reject_investigation(scan_id, body.reviewer, body.reason)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _record_investigation_feedback(inv, "false_positive", body.reviewer)
    return {"ok": True, "scan_id": scan_id, "reviewer": body.reviewer, "reason": body.reason}


def _record_investigation_feedback(inv: dict, verdict: str, reviewer: str) -> None:
    """Auto-record human verdict into FeedbackStore for active retraining."""
    forensics = inv.get("forensics_result") or {}
    ml = inv.get("multilingual_result") or {}
    patterns = forensics.get("matched_signatures", [])
    scan_result = {
        "scan_id": inv.get("scan_id", ""),
        "original_input": inv.get("payload", ""),
        "normalised_input": inv.get("payload", ""),
        "tier1_score": float(inv.get("risk_score", 0.0)),
        "tier2_score": 0.0,
        "llm_score": 0.0,
        "final_decision": inv.get("decision", "BLOCK"),
        "matched_patterns": patterns,
        "risk_score": float(inv.get("risk_score", 0.0)),
        "tier_used": 1,
        "script_detected": ml.get("script_detected", "latin"),
    }
    get_feedback_store().record(scan_result, verdict, reviewer)

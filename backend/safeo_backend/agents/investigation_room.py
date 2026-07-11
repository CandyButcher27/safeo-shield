"""InvestigationRoom — stores LangGraph-orchestrated SafeO investigations."""
from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Optional

from .langgraph_orchestrator import build_initial_state, run_langgraph_investigation

logger = logging.getLogger("safeo.investigation_room")

_MAX_STORED = 100
_investigations: Deque[Dict[str, Any]] = deque(maxlen=_MAX_STORED)

# Tracks the last hash so each new record chains to the previous one.
# Initialised to a deterministic genesis value.
_GENESIS_HASH = "0" * 64
_last_investigation_hash: str = _GENESIS_HASH


# ---------------------------------------------------------------------------
# Main async orchestrator
# ---------------------------------------------------------------------------

async def run_investigation(
    scan_id: str,
    payload: str,
    risk_score: float,
    decision: str,
    patterns: list,
    meta: Dict[str, Any],
    context: Dict[str, Any],
    behavior_score: float = 0.0,
) -> Dict[str, Any]:
    global _last_investigation_hash
    t0 = time.perf_counter()
    state = build_initial_state(
        scan_id=scan_id,
        original_input=payload,
        context={
            "source_system": context.get("source_system", "api"),
            "jurisdiction": context.get("jurisdiction", "UAE"),
            "user_id": context.get("user_id", "anonymous"),
        },
        risk_score=risk_score,
        tier_used=int(meta.get("tier_used", 1) or 1),
        matched_patterns=patterns,
        decision=decision,
    )
    final_state = await run_langgraph_investigation(state)

    multilingual_result = final_state.get("multilingual_output") or {}
    policy_result = final_state.get("policy_output") or {}
    forensics_result = final_state.get("forensics_output") or {}
    verifier_result = final_state.get("verifier_output") or {}
    remediation_result = final_state.get("remediation_output") or {}

    final_decision = verifier_result.get("final_decision", decision).upper()
    action = remediation_result.get("action", "none")
    human_required = bool(remediation_result.get("irreversible", False))
    verdict = f"{final_decision} — {action}"
    investigation_ms = int((time.perf_counter() - t0) * 1000)
    timestamp = datetime.now(timezone.utc).isoformat()

    # ── SHA-256 hash chain ────────────────────────────────────────────────────
    # Hash commits to: scan_id, final verdict, each agent's verdict, the previous
    # record's hash, and the ISO timestamp. Tampering any field breaks the chain.
    prev_hash = _last_investigation_hash
    chain_payload = json.dumps({
        "scan_id": scan_id,
        "verdict": verdict,
        "agent_verdicts": {
            "policy_severity": policy_result.get("severity"),
            "forensics_attack_type": forensics_result.get("attack_class"),
            "verifier_convergence": verifier_result.get("convergence"),
            "remediation_action": action,
        },
        "prev_hash": prev_hash,
        "timestamp": timestamp,
    }, sort_keys=True)
    investigation_hash = hashlib.sha256(chain_payload.encode()).hexdigest()
    _last_investigation_hash = investigation_hash

    record: Dict[str, Any] = {
        "scan_id": scan_id,
        "payload": payload,
        "risk_score": risk_score,
        "decision": decision,
        "timestamp": timestamp,
        "multilingual_result": multilingual_result,
        "policy_result": policy_result,
        "forensics_result": forensics_result,
        "verifier_result": verifier_result,
        "remediation_result": remediation_result,
        "langgraph_state": final_state,
        "checkpoint_hash": final_state.get("checkpoint_hash"),
        "prev_checkpoint_hash": final_state.get("prev_checkpoint_hash"),
        "node_trace": final_state.get("node_trace", []),
        "final_verdict": verdict,
        "human_required": human_required,
        "investigation_ms": investigation_ms,
        # Audit trail integrity fields
        "investigation_hash": investigation_hash,
        "prev_hash": prev_hash,
        "approved": None,
        "reviewer": None,
        "reject_reason": None,
    }
    _investigations.append(record)
    logger.info(
        "investigation scan_id=%s verdict=%s ms=%s human=%s hash=%s",
        scan_id, verdict, investigation_ms, human_required, investigation_hash[:16],
    )
    return record


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_investigations(limit: int = 20) -> list:
    return list(_investigations)[-limit:]


def get_investigation(scan_id: str) -> Optional[Dict[str, Any]]:
    for inv in _investigations:
        if inv["scan_id"] == scan_id:
            return inv
    return None


def verify_audit_chain() -> Dict[str, Any]:
    """
    Walk the stored investigation chain and verify hash integrity.
    Returns a summary: total records, valid chain length, first broken link (if any).
    """
    records = list(_investigations)
    if not records:
        return {"total": 0, "valid": 0, "broken_at": None, "intact": True}

    valid = 0
    broken_at: Optional[str] = None
    prev = records[0].get("prev_hash", _GENESIS_HASH)

    for rec in records:
        if rec.get("prev_hash") != prev:
            broken_at = rec["scan_id"]
            break
        chain_payload = json.dumps({
            "scan_id": rec["scan_id"],
            "verdict": rec.get("final_verdict"),
            "agent_verdicts": {
                "policy_severity": rec.get("policy_result", {}).get("severity"),
                "forensics_attack_type": rec.get("forensics_result", {}).get("attack_class"),
                "verifier_convergence": rec.get("verifier_result", {}).get("convergence"),
                "remediation_action": rec.get("remediation_result", {}).get("action"),
            },
            "prev_hash": rec.get("prev_hash"),
            "timestamp": rec.get("timestamp"),
        }, sort_keys=True)
        expected = hashlib.sha256(chain_payload.encode()).hexdigest()
        if expected != rec.get("investigation_hash"):
            broken_at = rec["scan_id"]
            break
        prev = rec["investigation_hash"]
        valid += 1

    return {
        "total": len(records),
        "valid": valid,
        "broken_at": broken_at,
        "intact": broken_at is None,
    }


def approve_investigation(scan_id: str, reviewer: str) -> Optional[Dict[str, Any]]:
    inv = get_investigation(scan_id)
    if inv:
        inv["approved"] = True
        inv["reviewer"] = reviewer
    return inv


def reject_investigation(scan_id: str, reviewer: str, reason: str) -> Optional[Dict[str, Any]]:
    inv = get_investigation(scan_id)
    if inv:
        inv["approved"] = False
        inv["reviewer"] = reviewer
        inv["reject_reason"] = reason
    return inv

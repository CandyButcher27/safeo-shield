"""Build agent-log messages from a stored investigation record (WS history fallback)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def _msg(scan_id: str, agent: str, content: str, status: str = "info", metadata: dict | None = None) -> dict:
    return {
        "scan_id": scan_id,
        "agent": agent,
        "content": content,
        "status": status,
        "metadata": metadata or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def synthesize_agent_log(inv: Dict[str, Any]) -> List[dict]:
    """Reconstruct agent conversation from persisted investigation fields."""
    scan_id = inv.get("scan_id", "")
    if not scan_id:
        return []

    msgs: List[dict] = []
    ml = inv.get("multilingual_result") or {}
    policy = inv.get("policy_result") or {}
    forensics = inv.get("forensics_result") or {}
    remediation = inv.get("remediation_result") or {}

    msgs.append(_msg(scan_id, "MultilingualAgent", "Analysing input script..."))
    script = ml.get("script_detected", "latin")
    msgs.append(_msg(scan_id, "MultilingualAgent", f"Script detected: {script}"))
    msgs.append(_msg(scan_id, "MultilingualAgent", "Normalised payload ready"))
    if ml.get("evasion_suspected"):
        method = ml.get("method", "unknown")
        msgs.append(_msg(
            scan_id, "MultilingualAgent",
            f"⚠ Evasion suspected — {method}",
            status="warning",
        ))
    msgs.append(_msg(
        scan_id, "MultilingualAgent", "Multilingual analysis complete",
        status="done", metadata=ml,
    ))

    msgs.append(_msg(scan_id, "PolicyAgent", "Checking compliance policies..."))
    severity = policy.get("severity", "info")
    for policy_name in policy.get("policies_violated", []):
        st = "critical" if severity in ("high", "critical") else "warning"
        msgs.append(_msg(scan_id, "PolicyAgent", f"Violation: {policy_name} — {severity}", status=st))
    msgs.append(_msg(scan_id, "PolicyAgent", "Policy check complete", status="done", metadata=policy))

    msgs.append(_msg(scan_id, "ForensicsAgent", "Reconstructing attack pattern..."))
    for sig in forensics.get("matched_signatures", [])[:8]:
        msgs.append(_msg(scan_id, "ForensicsAgent", f"Matched signature: {sig}"))
    obf = forensics.get("obfuscation_method")
    if obf:
        msgs.append(_msg(scan_id, "ForensicsAgent", f"Obfuscation method: {obf}"))
    else:
        msgs.append(_msg(scan_id, "ForensicsAgent", "No obfuscation detected"))
    if forensics.get("graph_evidence"):
        mitre = forensics.get("mitre_techniques", [])
        msgs.append(_msg(
            scan_id, "ForensicsAgent",
            f"KG grounded — MITRE: {', '.join(mitre)}",
            metadata=forensics.get("graph_evidence"),
        ))
    msgs.append(_msg(scan_id, "ForensicsAgent", "Forensics complete", status="done", metadata=forensics))

    verifier = inv.get("verifier_result") or {}
    msgs.append(_msg(scan_id, "VerifierAgent", "Verifying convergence between Policy and Forensics..."))
    convergence = verifier.get("convergence", "partial")
    if convergence == "converged":
        msgs.append(_msg(scan_id, "VerifierAgent", "Policy + Forensics converged — high confidence"))
    else:
        discrepancy = verifier.get("discrepancy", "")
        status = "warning" if convergence == "partial" else "warning"
        msgs.append(_msg(scan_id, "VerifierAgent", f"{convergence.title()} — {discrepancy}", status=status))
    if verifier.get("false_positive_suspected"):
        msgs.append(_msg(
            scan_id, "VerifierAgent",
            f"⚠ Possible false positive — {verifier.get('fp_reason', '')}",
            status="warning",
        ))
    msgs.append(_msg(scan_id, "VerifierAgent", "Verification complete", status="done", metadata=verifier))

    msgs.append(_msg(scan_id, "RemediationAgent", "Evaluating remediation options..."))
    action = remediation.get("action", "unknown")
    msgs.append(_msg(scan_id, "RemediationAgent", f"Proposed action: {action}"))
    if remediation.get("irreversible"):
        msgs.append(_msg(
            scan_id, "RemediationAgent",
            "⚠ Action is irreversible — human approval required",
            status="critical",
        ))
    msgs.append(_msg(
        scan_id, "RemediationAgent", "Remediation verdict ready",
        status="done", metadata=remediation,
    ))
    return msgs

"""
VerifierAgent — meta-judge that checks convergence between PolicyAgent and
ForensicsAgent findings before RemediationAgent acts.

Inspired by Drift Agent's meta-judge concept. The Verifier asks:
  1. Do Policy and Forensics agree on the threat level?
  2. Does the flagged attack pattern actually apply to this specific input's context?
  3. Is there evidence of a false positive (e.g. benign input misclassified)?

Convergence levels
------------------
  converged   — Both agents agree on severity + attack type. High confidence.
  partial     — Minor discrepancy (e.g. different severity scale) but same
                general conclusion. Proceed with slight caution.
  diverged    — Agents disagree substantially. Flag for human review; do not
                auto-execute irreversible actions.

False-positive signals
----------------------
  - Policy says "no violation" but Forensics says "high confidence attack"
  - Forensics returns "unknown" attack type with very few pattern matches
  - Risk score is high but payload is extremely short (< 10 chars)
  - All matched patterns are from a single low-weight category (obfuscation only)

When SAFEO_ENABLE_AGENT_LLM=true the agent additionally queries
Llama-3-70B-Instruct for contextual false-positive reasoning.

agent_post logging is handled by investigation_room.py.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("safeo.verifier_agent")

# Severity ordering for convergence comparison
_SEVERITY_RANK: Dict[str, int] = {
    "info":     0,
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}

# Attack types that are inherently ambiguous and more prone to false positives
_AMBIGUOUS_TYPES = {"obfuscation", "unknown", "erp_social_engineering"}


class VerifierAgent:
    name = "VerifierAgent"

    def verify(
        self,
        payload: str,
        policy_result: Dict[str, Any],
        forensics_result: Dict[str, Any],
        matched_patterns: List[str],
        risk_score: float,
    ) -> Dict[str, Any]:
        policy_severity = policy_result.get("severity", "info")
        forensics_attack = forensics_result.get("attack_type", "unknown")
        forensics_conf = float(forensics_result.get("confidence", 0.5))
        policy_violated = policy_result.get("policies_violated", [])
        graph_evidence = forensics_result.get("graph_evidence")

        # ── Convergence check ─────────────────────────────────────────────────
        policy_rank = _SEVERITY_RANK.get(policy_severity, 0)
        has_violation = len(policy_violated) > 0
        high_forensics = forensics_conf >= 0.75 and forensics_attack != "unknown"
        high_policy = policy_rank >= _SEVERITY_RANK["high"]
        medium_policy = policy_rank >= _SEVERITY_RANK["medium"]

        discrepancy = ""
        if high_forensics and high_policy:
            convergence = "converged"
        elif high_forensics and medium_policy:
            convergence = "converged"
        elif has_violation and forensics_attack != "unknown":
            convergence = "partial"
            if policy_rank == 0:
                discrepancy = "Policy found no violation but Forensics identified an attack."
            else:
                discrepancy = f"Policy severity ({policy_severity}) may understate {forensics_attack} confidence ({forensics_conf:.2f})."
        elif not has_violation and forensics_attack == "unknown":
            convergence = "partial"
            discrepancy = "Neither agent found a clear threat — possible noise or edge case."
        elif has_violation and forensics_attack == "unknown":
            convergence = "diverged"
            discrepancy = "Policy flagged violations but Forensics found no recognisable attack pattern."
        elif not has_violation and high_forensics:
            convergence = "diverged"
            discrepancy = "Forensics is confident about an attack but Policy found no violations."
        else:
            convergence = "partial"
            discrepancy = f"Moderate agreement: policy={policy_severity}, forensics={forensics_attack}."

        # ── False-positive detection ──────────────────────────────────────────
        false_positive_suspected = False
        fp_reason = ""
        fp_discount = 0.0

        # Signal 1: very short payload unlikely to carry a real attack
        if len((payload or "").strip()) < 12 and risk_score >= 0.65:
            false_positive_suspected = True
            fp_reason = f"Payload length {len(payload.strip())} chars is too short for a credible attack."
            fp_discount = 0.20

        # Signal 2: attack type is inherently ambiguous
        elif forensics_attack in _AMBIGUOUS_TYPES and not graph_evidence:
            false_positive_suspected = True
            fp_reason = f"Attack type '{forensics_attack}' is ambiguous with no KG evidence to ground it."
            fp_discount = 0.15

        # Signal 3: only obfuscation patterns matched (no specific attack)
        elif matched_patterns and all("obfuscation" in p or "decoded:" in p for p in matched_patterns):
            false_positive_suspected = True
            fp_reason = "All matched patterns are encoding-only; no attack payload confirmed after decoding."
            fp_discount = 0.10

        # Signal 4: divergence AND low forensics confidence
        elif convergence == "diverged" and forensics_conf < 0.70:
            false_positive_suspected = True
            fp_reason = f"Agents diverged and Forensics confidence is low ({forensics_conf:.2f})."
            fp_discount = 0.12

        # ── KG corroboration boost ────────────────────────────────────────────
        # If the knowledge graph provided evidence, reduce false-positive suspicion.
        if false_positive_suspected and graph_evidence:
            mitre = graph_evidence.get("mitre_techniques", [])
            if mitre:
                false_positive_suspected = False
                fp_reason = ""
                fp_discount = 0.0

        result: Dict[str, Any] = {
            "convergence": convergence,
            "discrepancy": discrepancy,
            "false_positive_suspected": false_positive_suspected,
            "fp_reason": fp_reason,
            "fp_discount": fp_discount,
            "policy_severity": policy_severity,
            "forensics_attack": forensics_attack,
            "forensics_confidence": forensics_conf,
            "kg_grounded": bool(graph_evidence),
            "model_used": "rule-based",
        }

        # ── LLM augmentation — Llama-3-70B ────────────────────────────────────
        from ..config.amd_config import (
            AGENT_LLM_API_KEY,
            AGENT_LLM_SERVER_URL,
            ENABLE_AGENT_LLM,
            VERIFIER_AGENT_MODEL,
        )
        if ENABLE_AGENT_LLM:
            llm_result = self._llm_augment(
                payload=payload,
                policy_result=policy_result,
                forensics_result=forensics_result,
                convergence=convergence,
                false_positive_suspected=false_positive_suspected,
                model=VERIFIER_AGENT_MODEL,
                server_url=AGENT_LLM_SERVER_URL,
                api_key=AGENT_LLM_API_KEY,
            )
            if llm_result:
                result.update(llm_result)
                result["model_used"] = VERIFIER_AGENT_MODEL

        return result

    @staticmethod
    def _llm_augment(
        payload: str,
        policy_result: Dict[str, Any],
        forensics_result: Dict[str, Any],
        convergence: str,
        false_positive_suspected: bool,
        model: str,
        server_url: str,
        api_key: str,
    ) -> Optional[Dict[str, Any]]:
        """Query Llama-3-70B for contextual false-positive reasoning."""
        try:
            from openai import OpenAI

            client = OpenAI(base_url=server_url, api_key=api_key)
            system = (
                "You are a security verification expert acting as a meta-judge. "
                "Given specialist findings from PolicyAgent and ForensicsAgent, determine whether "
                "they converge on the same conclusion, and whether a false positive is plausible. "
                "Return a JSON object with keys: convergence (converged|partial|diverged), "
                "false_positive_suspected (bool), fp_reason (string), discrepancy (string), "
                "llm_notes (string — 1-2 sentences of reasoning)."
            )
            user = json.dumps({
                "payload_excerpt": (payload or "")[:400],
                "policy_summary": {
                    "severity": policy_result.get("severity"),
                    "policies_violated": policy_result.get("policies_violated", []),
                },
                "forensics_summary": {
                    "attack_type": forensics_result.get("attack_type"),
                    "confidence": forensics_result.get("confidence"),
                    "mitre": forensics_result.get("mitre_techniques", []),
                },
                "rule_convergence": convergence,
                "rule_fp_suspected": false_positive_suspected,
            })
            resp = client.chat.completions.create(
                model=model,
                temperature=0,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                response_format={"type": "json_object"},
                timeout=8,
            )
            raw = resp.choices[0].message.content or "{}"
            return json.loads(raw)
        except Exception as exc:
            logger.debug("VerifierAgent LLM augment failed: %s", exc)
            return None

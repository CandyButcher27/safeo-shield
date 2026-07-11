"""
LangGraph-style local orchestration engine for SafeO investigations.

This replaces the Band mirror with an in-process, checkpointed investigation
graph. The graph coordinates five specialist agents:

    multilingual_agent -> policy_agent + forensics_agent (parallel)
        -> verifier_agent -> remediation_agent | END

The implementation intentionally keeps the graph local and dependency-light
while preserving LangGraph semantics: explicit state, conditional routing,
parallel branches, checkpoint hashes, and node trace.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .forensics_agent import ForensicsAgent
from .multilingual_agent import get_multilingual_agent
from .policy_agent import PolicyAgent
from .remediation_agent import RemediationAgent
from .verifier_agent import VerifierAgent
from ..utils.agent_logger import agent_post

logger = logging.getLogger("safeo.langgraph")

GENESIS_CHECKPOINT_HASH = "0" * 64


def contains_non_latin(text: str) -> bool:
    """Return True for Arabic, Urdu, Arabizi mix, or any non-ASCII character."""
    return any(ord(ch) > 127 for ch in text or "")


def build_initial_state(
    *,
    scan_id: str,
    original_input: str,
    context: Dict[str, Any],
    risk_score: float,
    tier_used: int,
    matched_patterns: List[str],
    decision: str,
) -> Dict[str, Any]:
    return {
        "scan_id": scan_id,
        "original_input": original_input,
        "context": {
            "source_system": context.get("source_system", "api"),
            "jurisdiction": context.get("jurisdiction", "UAE"),
            "user_id": context.get("user_id", "anonymous"),
        },
        "ml_result": {
            "risk_score": float(risk_score),
            "tier_used": int(tier_used or 1),
            "matched_patterns": list(matched_patterns or []),
            "decision": (decision or "ALLOW").upper(),
        },
        "multilingual_output": None,
        "policy_output": None,
        "forensics_output": None,
        "verifier_output": None,
        "remediation_output": None,
        "checkpoint_hash": GENESIS_CHECKPOINT_HASH,
        "prev_checkpoint_hash": GENESIS_CHECKPOINT_HASH,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "node_trace": [],
    }


class SafeOLangGraphOrchestrator:
    """Stateful local graph runner for SafeO investigation agents."""

    def __init__(self) -> None:
        self.multilingual_agent = get_multilingual_agent()
        self.policy_agent = PolicyAgent()
        self.forensics_agent = ForensicsAgent()
        self.verifier_agent = VerifierAgent()
        self.remediation_agent = RemediationAgent()

    async def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the full conditional investigation graph.
        Agent failures null that node output and routing continues.
        """
        ml_result = state.get("ml_result") or {}
        risk_score = float(ml_result.get("risk_score", 0.0))
        decision = (ml_result.get("decision") or "ALLOW").upper()
        original_input = state.get("original_input", "")

        if decision == "ALLOW" and risk_score < 0.35 and not contains_non_latin(original_input):
            state = self._checkpoint(state, "END")
            state["last_transition"] = self._transition(
                next_node="END",
                state_updates={},
                checkpoint_hash=state["checkpoint_hash"],
                routing_reason="Low-risk Tier 1 allow.",
            )
            return state

        state = await self._multilingual_node(state)

        if decision == "ALLOW" and risk_score < 0.35:
            state = self._checkpoint(state, "END")
            state["last_transition"] = self._transition(
                next_node="END",
                state_updates={},
                checkpoint_hash=state["checkpoint_hash"],
                routing_reason="Non-Latin checked, risk allowed.",
            )
            return state

        policy_state, forensics_state = await asyncio.gather(
            self._policy_node(deepcopy(state)),
            self._forensics_node(deepcopy(state)),
        )
        state["policy_output"] = policy_state.get("policy_output")
        state["forensics_output"] = forensics_state.get("forensics_output")
        state["node_trace"] = (
            state.get("node_trace", [])
            + ["policy_agent", "forensics_agent"]
        )
        state = self._checkpoint(state, "parallel_join", append_node=False)

        state = await self._verifier_node(state)
        final_decision = (
            (state.get("verifier_output") or {}).get("final_decision")
            or decision
        ).upper()

        if final_decision == "ALLOW":
            state = self._checkpoint(state, "END")
            state["last_transition"] = self._transition(
                next_node="END",
                state_updates={"verifier_output": state.get("verifier_output")},
                checkpoint_hash=state["checkpoint_hash"],
                routing_reason="Verifier allowed; remediation skipped.",
            )
            return state

        state = await self._remediation_node(state)
        state = self._checkpoint(state, "END")
        state["last_transition"] = self._transition(
            next_node="END",
            state_updates={"remediation_output": state.get("remediation_output")},
            checkpoint_hash=state["checkpoint_hash"],
            routing_reason=f"{final_decision} requires remediation.",
        )
        return state

    async def _multilingual_node(self, state: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = state["scan_id"]
        await agent_post(scan_id, "MultilingualAgent", "LangGraph node started")
        try:
            result = await asyncio.to_thread(
                self.multilingual_agent.analyse,
                state.get("original_input", ""),
            )
            output = {
                "script_detected": result.get("script_detected", "latin"),
                "normalised_text": result.get("normalised", state.get("original_input", "")),
                "evasion_suspected": bool(result.get("evasion_suspected")),
                "confidence": float(result.get("confidence", 0.0)),
                "model_used": result.get("model_used", "AraBERT/local"),
            }
            state["multilingual_output"] = output
            await agent_post(scan_id, "MultilingualAgent", "Script normalized", status="done", metadata=output)
        except Exception as exc:
            logger.exception("multilingual node failed: %s", exc)
            state["multilingual_output"] = None
            await agent_post(scan_id, "MultilingualAgent", "Node failed; continuing", status="warning")
        return self._checkpoint(state, "multilingual_agent")

    async def _policy_node(self, state: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = state["scan_id"]
        await agent_post(scan_id, "PolicyAgent", "LangGraph node started")
        try:
            ml = state.get("multilingual_output") or {}
            ml_result = state.get("ml_result") or {}
            result = await asyncio.to_thread(
                self.policy_agent.check,
                state.get("original_input", ""),
                state.get("context") or {},
                ml.get("normalised_text") or state.get("original_input", ""),
                float(ml_result.get("risk_score", 0.0)),
                ml_result.get("decision", "ALLOW"),
            )
            policies = result.get("policies_violated", [])
            uae_articles = self._uae_articles(policies)
            output = {
                "policies_violated": policies,
                "severity": result.get("severity", "low"),
                "uae_law_articles": uae_articles,
                "recommendation": result.get("recommendation"),
                "model_used": result.get("model_used"),
            }
            state["policy_output"] = output
            await agent_post(scan_id, "PolicyAgent", "Policy analysis complete", status="done", metadata=output)
        except Exception as exc:
            logger.exception("policy node failed: %s", exc)
            state["policy_output"] = None
            await agent_post(scan_id, "PolicyAgent", "Node failed; continuing", status="warning")
        return self._checkpoint(state, "policy_agent")

    async def _forensics_node(self, state: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = state["scan_id"]
        await agent_post(scan_id, "ForensicsAgent", "LangGraph node started")
        try:
            ml = state.get("multilingual_output") or {}
            ml_result = state.get("ml_result") or {}
            result = await asyncio.to_thread(
                self.forensics_agent.analyse,
                state.get("original_input", ""),
                ml.get("normalised_text") or state.get("original_input", ""),
                ml.get("script_detected", "latin"),
                ml_result.get("matched_patterns", []),
                0.0,
                {},
            )
            output = {
                "attack_class": result.get("attack_type", "unknown"),
                "mitre_tags": result.get("mitre_techniques", []),
                "kg_evidence": result.get("graph_evidence") or {},
                "confidence": float(result.get("confidence", 0.0)),
                "matched_signatures": result.get("matched_signatures", []),
                "attack_timeline": result.get("attack_timeline"),
                "model_used": result.get("model_used"),
            }
            state["forensics_output"] = output
            await agent_post(scan_id, "ForensicsAgent", "Forensics analysis complete", status="done", metadata=output)
        except Exception as exc:
            logger.exception("forensics node failed: %s", exc)
            state["forensics_output"] = None
            await agent_post(scan_id, "ForensicsAgent", "Node failed; continuing", status="warning")
        return self._checkpoint(state, "forensics_agent")

    async def _verifier_node(self, state: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = state["scan_id"]
        await agent_post(scan_id, "VerifierAgent", "LangGraph node started")
        ml_result = state.get("ml_result") or {}
        policy = self._policy_compat(state.get("policy_output"))
        forensics = self._forensics_compat(state.get("forensics_output"))
        try:
            result = await asyncio.to_thread(
                self.verifier_agent.verify,
                (state.get("multilingual_output") or {}).get("normalised_text") or state.get("original_input", ""),
                policy,
                forensics,
                ml_result.get("matched_patterns", []),
                float(ml_result.get("risk_score", 0.0)),
            )
            agents_agree = result.get("convergence") == "converged"
            false_positive = bool(result.get("false_positive_suspected"))
            final_decision = self._verified_decision(
                ml_result.get("decision", "ALLOW"),
                agents_agree,
                false_positive,
            )
            confidence_delta = 0.0
            if not agents_agree and ml_result.get("decision") == "BLOCK":
                confidence_delta -= 0.20
            if false_positive:
                confidence_delta -= float(result.get("fp_discount", 0.15))
            output = {
                "agents_agree": agents_agree,
                "false_positive_suspected": false_positive,
                "confidence_delta": round(confidence_delta, 3),
                "final_decision": final_decision,
                "convergence": result.get("convergence"),
                "discrepancy": result.get("discrepancy"),
                "model_used": result.get("model_used"),
            }
            state["verifier_output"] = output
            await agent_post(scan_id, "VerifierAgent", "Verification complete", status="done", metadata=output)
        except Exception as exc:
            logger.exception("verifier node failed: %s", exc)
            state["verifier_output"] = {
                "agents_agree": False,
                "false_positive_suspected": False,
                "confidence_delta": 0.0,
                "final_decision": ml_result.get("decision", "WARN"),
            }
            await agent_post(scan_id, "VerifierAgent", "Node failed; using ML decision", status="warning")
        return self._checkpoint(state, "verifier_agent")

    async def _remediation_node(self, state: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = state["scan_id"]
        await agent_post(scan_id, "RemediationAgent", "LangGraph node started")
        verifier = state.get("verifier_output") or {}
        if verifier.get("final_decision") == "ALLOW":
            state["remediation_output"] = None
            return self._checkpoint(state, "remediation_agent")

        ml_result = state.get("ml_result") or {}
        policy = self._policy_compat(state.get("policy_output"))
        forensics = self._forensics_compat(state.get("forensics_output"))
        try:
            risk_score = max(0.0, float(ml_result.get("risk_score", 0.0)) + float(verifier.get("confidence_delta", 0.0)))
            result = await asyncio.to_thread(
                self.remediation_agent.propose,
                policy,
                forensics,
                0.0,
                risk_score,
            )
            action = result.get("action", "flag_for_review")
            actions = result.get("remediation_steps") or [action, result.get("reason", "Review event.")]
            output = {
                "actions": actions,
                "jira_payload": self._jira_payload(state, action, result),
                "whatsapp_reply": self._whatsapp_reply(state, action),
                "action": action,
                "irreversible": bool(result.get("irreversible")),
                "auto_execute": bool(result.get("auto_execute")),
                "reason": result.get("reason"),
                "model_used": result.get("model_used"),
            }
            state["remediation_output"] = output
            await agent_post(scan_id, "RemediationAgent", "Remediation complete", status="done", metadata=output)
        except Exception as exc:
            logger.exception("remediation node failed: %s", exc)
            state["remediation_output"] = None
            await agent_post(scan_id, "RemediationAgent", "Node failed; continuing", status="warning")
        return self._checkpoint(state, "remediation_agent")

    def _checkpoint(self, state: Dict[str, Any], node_name: str, append_node: bool = True) -> Dict[str, Any]:
        previous = state.get("checkpoint_hash") or GENESIS_CHECKPOINT_HASH
        state["prev_checkpoint_hash"] = previous
        state["timestamp"] = datetime.now(timezone.utc).isoformat()
        if append_node:
            state["node_trace"] = list(state.get("node_trace", [])) + [node_name]
        state["checkpoint_hash"] = ""
        payload = json.dumps(state, sort_keys=True, default=str)
        state["checkpoint_hash"] = hashlib.sha256(payload.encode()).hexdigest()
        return state

    @staticmethod
    def _transition(
        *,
        next_node: str,
        state_updates: Dict[str, Any],
        checkpoint_hash: str,
        routing_reason: str,
    ) -> Dict[str, Any]:
        return {
            "next_node": next_node,
            "state_updates": state_updates,
            "checkpoint_hash": checkpoint_hash,
            "routing_reason": routing_reason[:120],
        }

    @staticmethod
    def _verified_decision(original_decision: str, agents_agree: bool, false_positive: bool) -> str:
        decision = (original_decision or "ALLOW").upper()
        if false_positive:
            return "WARN" if decision == "BLOCK" else decision
        if not agents_agree and decision == "BLOCK":
            return "WARN"
        return decision

    @staticmethod
    def _uae_articles(policies: List[str]) -> List[str]:
        if not policies:
            return []
        return [
            "UAE Federal Decree-Law No. 34/2021 Article 5: Unauthorized access to information systems.",
            "UAE Federal Decree-Law No. 34/2021 Article 10: Misuse of electronic systems to obtain data.",
        ]

    @staticmethod
    def _policy_compat(policy_output: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        policy_output = policy_output or {}
        return {
            "policies_violated": policy_output.get("policies_violated", []),
            "severity": policy_output.get("severity", "info"),
            "recommendation": policy_output.get("recommendation"),
        }

    @staticmethod
    def _forensics_compat(forensics_output: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        forensics_output = forensics_output or {}
        return {
            "attack_type": forensics_output.get("attack_class", "unknown"),
            "confidence": forensics_output.get("confidence", 0.5),
            "graph_evidence": forensics_output.get("kg_evidence") or {},
            "mitre_techniques": forensics_output.get("mitre_tags", []),
            "matched_signatures": forensics_output.get("matched_signatures", []),
        }

    @staticmethod
    def _jira_payload(state: Dict[str, Any], action: str, remediation: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "summary": f"SafeO {action}: {state['scan_id']}",
            "labels": ["safeo", "automated-investigation"],
            "severity": (state.get("policy_output") or {}).get("severity", "medium"),
            "description": remediation.get("reason", "SafeO remediation generated."),
            "scan_id": state["scan_id"],
        }

    @staticmethod
    def _whatsapp_reply(state: Dict[str, Any], action: str) -> Optional[str]:
        source = (state.get("context") or {}).get("source_system")
        if source != "whatsapp":
            return None
        if action == "block_input":
            return "Your message was blocked because it matched a security policy. Please rephrase safely."
        return "Your message needs manual review before it can be processed."


async def run_langgraph_investigation(state: Dict[str, Any]) -> Dict[str, Any]:
    return await SafeOLangGraphOrchestrator().run(state)

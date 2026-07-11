"""
Workflow builder API — save, validate, and run visual scan pipelines.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, ConfigDict

from .universal import ScanContext, _run_scan

router = APIRouter(prefix="/workflows", tags=["Workflows"])

_pipeline_store: Dict[str, Dict[str, Any]] = {}

NODE_META: Dict[str, Dict[str, str]] = {
    "erp_form": {"category": "input"},
    "api_payload": {"category": "input"},
    "whatsapp_message": {"category": "input"},
    "website_input": {"category": "input"},
    "free_text": {"category": "input"},
    "url_scanner": {"category": "input"},
    "github_repo": {"category": "input", "status": "new"},
    "slack_message": {"category": "input", "status": "new"},
    "pdf_document": {"category": "input", "status": "new"},
    "arabic_arabizi": {"category": "detection"},
    "language_script": {"category": "detection", "status": "partial"},
    "architecture_scanner": {"category": "detection"},
    "erp_fraud": {"category": "detection"},
    "prompt_injection": {"category": "detection"},
    "pii_scanner": {"category": "detection", "status": "new"},
    "github_repo_scanner": {"category": "detection", "status": "new"},
    "risk_score": {"category": "decision"},
    "pdf_report": {"category": "output", "status": "new"},
    "whatsapp_reply": {"category": "output"},
    "human_review": {"category": "output"},
    "erp_block": {"category": "output"},
    "slack_alert": {"category": "output", "status": "new"},
    "jira_ticket": {"category": "output", "status": "mock"},
    "siem_export": {"category": "output", "status": "mock"},
    "email_alert": {"category": "output", "status": "mock"},
    "start": {"category": "control"},
    "end": {"category": "control"},
}


class PipelineNode(BaseModel):
    id: str
    type: str
    x: float = 0
    y: float = 0


class PipelineEdge(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    from_: str = Field(alias="from")
    to: str


class PipelineModel(BaseModel):
    id: str
    name: str = "Untitled pipeline"
    observe_mode: bool = True
    nodes: List[PipelineNode] = Field(default_factory=list)
    edges: List[PipelineEdge] = Field(default_factory=list)
    viewport: Dict[str, float] = Field(default_factory=lambda: {"x": 0, "y": 0, "zoom": 1})


class RunPipelineRequest(BaseModel):
    pipeline: PipelineModel
    sample_input: str
    context: Dict[str, Any] = Field(default_factory=dict)
    observe_mode: Optional[bool] = None


def _adjacency(edges: List[PipelineEdge]) -> tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    out: Dict[str, List[str]] = {}
    inn: Dict[str, List[str]] = {}
    for e in edges:
        src = e.from_
        out.setdefault(src, []).append(e.to)
        inn.setdefault(e.to, []).append(src)
    return out, inn


def _path_exists(out: Dict[str, List[str]], start: str, end: str) -> bool:
    visited: set[str] = set()
    queue = [start]
    while queue:
        cur = queue.pop(0)
        if cur == end:
            return True
        if cur in visited:
            continue
        visited.add(cur)
        queue.extend(out.get(cur, []))
    return False


def validate_pipeline_dict(pipeline: Dict[str, Any]) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []
    nodes = pipeline.get("nodes") or []
    edges_raw = pipeline.get("edges") or []

    edges = []
    for e in edges_raw:
        edges.append(PipelineEdge(id=e["id"], **{"from": e["from"], "to": e["to"]}))

    by_cat: Dict[str, List[Dict]] = {"input": [], "detection": [], "output": [], "decision": [], "control": []}
    for n in nodes:
        meta = NODE_META.get(n.get("type", ""))
        if not meta:
            errors.append(f"Unknown node type: {n.get('type')}")
            continue
        cat = meta["category"]
        if cat in by_cat:
            by_cat[cat].append(n)

    risk_nodes = [n for n in nodes if n.get("type") == "risk_score"]
    if len(risk_nodes) != 1:
        errors.append("Pipeline must contain exactly one Risk score + decision node.")

    if len(by_cat["input"]) < 1:
        errors.append("Add at least one Input node.")
    if len(by_cat["output"]) < 1:
        errors.append("Add at least one Output node.")

    if not any(n.get("type") == "start" for n in nodes):
        warnings.append("Consider adding a Start node.")
    if not any(n.get("type") == "end" for n in nodes):
        warnings.append("Consider adding an End node.")

    out, inn = _adjacency(edges)
    risk_id = risk_nodes[0]["id"] if risk_nodes else None
    if risk_id:
        inputs_reach = any(_path_exists(out, n["id"], risk_id) for n in by_cat["input"])
        if by_cat["input"] and not inputs_reach:
            errors.append("At least one Input node must connect to Risk score (directly or via Detection).")

        outputs_from_risk = any(
            risk_id in inn.get(n["id"], []) or _path_exists(out, risk_id, n["id"])
            for n in by_cat["output"]
        )
        if by_cat["output"] and not outputs_from_risk:
            errors.append("At least one Output node must be reachable from Risk score.")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}


def _detection_agents(nodes: List[Dict]) -> List[str]:
    return [n["type"] for n in nodes if NODE_META.get(n.get("type", ""), {}).get("category") == "detection"]


def _output_actions(nodes: List[Dict], decision: str, observe_mode: bool) -> List[Dict[str, Any]]:
    outputs = [n for n in nodes if NODE_META.get(n.get("type", ""), {}).get("category") == "output"]
    actions = []
    for n in outputs:
        meta = NODE_META.get(n["type"], {})
        status = meta.get("status", "real")
        action = {
            "node_id": n["id"],
            "type": n["type"],
            "status": status,
            "executed": False,
            "message": "",
        }
        if status in ("mock", "new"):
            action["message"] = "Coming soon — skipped"
            actions.append(action)
            continue

        if observe_mode and n["type"] in ("erp_block", "whatsapp_reply"):
            action["message"] = "Observe mode — logged only, not enforced"
            action["executed"] = False
            actions.append(action)
            continue

        if decision == "BLOCK" and n["type"] == "erp_block":
            action["executed"] = True
            action["message"] = "Transaction blocked before Odoo persistence"
        elif decision in ("WARN", "BLOCK") and n["type"] == "human_review":
            action["executed"] = True
            action["message"] = "Queued for analyst review via /investigations/{id}/approve"
        elif decision == "BLOCK" and n["type"] == "whatsapp_reply":
            action["executed"] = True
            action["message"] = "Safe reply sent to WhatsApp source"
        else:
            action["message"] = f"No action for decision={decision}"
        actions.append(action)
    return actions


@router.get("")
async def list_pipelines():
    return {"pipelines": list(_pipeline_store.values())}


@router.get("/{pipeline_id}")
async def get_pipeline(pipeline_id: str):
    p = _pipeline_store.get(pipeline_id)
    if not p:
        raise HTTPException(status_code=404, detail="Pipeline not found")
    return p


@router.post("")
async def save_pipeline(pipeline: PipelineModel):
    validation = validate_pipeline_dict(pipeline.model_dump(by_alias=True))
    record = {
        **pipeline.model_dump(by_alias=True),
        "validation": validation,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if pipeline.id not in _pipeline_store:
        record["created_at"] = record["updated_at"]
    _pipeline_store[pipeline.id] = record
    return record


@router.post("/validate")
async def validate_pipeline(pipeline: PipelineModel):
    return validate_pipeline_dict(pipeline.model_dump(by_alias=True))


@router.post("/run")
async def run_pipeline(req: RunPipelineRequest):
    t0 = time.perf_counter()
    pipeline = req.pipeline.model_dump(by_alias=True)
    validation = validate_pipeline_dict(pipeline)
    if not validation["valid"]:
        raise HTTPException(status_code=400, detail="; ".join(validation["errors"]))

    observe_mode = req.observe_mode if req.observe_mode is not None else req.pipeline.observe_mode
    ctx = ScanContext(
        user_id=str(req.context.get("user_id", "workflow_user")),
        source_system=str(req.context.get("source_system", "api")),
        field_name=req.context.get("field_name"),
        ip=req.context.get("ip"),
    )

    scan_result = await _run_scan(req.sample_input, ctx)
    raw_decision = scan_result.get("decision", "ALLOW")
    effective_decision = raw_decision
    if observe_mode and raw_decision in ("BLOCK", "WARN"):
        effective_decision = "ALLOW"

    detection_nodes = _detection_agents(pipeline.get("nodes", []))
    output_actions = _output_actions(pipeline.get("nodes", []), raw_decision, observe_mode)

    latency_ms = round((time.perf_counter() - t0) * 1000, 1)

    from ..core.ml.bayesian_threshold import get_bayesian_engine
    attack_class = scan_result.get("attack_class", "generic")
    threshold = get_bayesian_engine().get_block_threshold(attack_class)

    return {
        "pipeline_id": req.pipeline.id,
        "pipeline_name": req.pipeline.name,
        "observe_mode": observe_mode,
        "scan_id": scan_result.get("scan_id"),
        "risk_score": scan_result.get("risk_score"),
        "uncertainty_score": round(1.0 - min(scan_result.get("risk_score", 0), 0.99), 3),
        "decision": raw_decision,
        "effective_decision": effective_decision,
        "block_threshold": threshold,
        "attack_class": attack_class,
        "matched_patterns": scan_result.get("matched_patterns", []),
        "explanations": scan_result.get("explanations", []),
        "tier_used": scan_result.get("tier_used"),
        "decision_latency_ms": latency_ms,
        "detection_nodes": detection_nodes,
        "output_actions": output_actions,
        "validation_warnings": validation.get("warnings", []),
    }

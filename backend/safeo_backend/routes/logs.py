"""Request log utilities — Jira escalation for in-memory engine logs."""
from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from ..clients.jira_client import create_jira_ticket
from .waf import find_request_log_entry

router = APIRouter(tags=["Logs"])


@router.post("/logs/{request_id}/create-jira-ticket")
async def create_jira_ticket_for_log(request_id: str) -> Dict[str, Any]:
    """Look up a log entry by request_id and create a Jira Task."""
    entry = find_request_log_entry(request_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Log entry {request_id!r} not found")

    existing = entry.get("jira_ticket_key")
    if existing:
        base = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
        return {
            "ticket_key": existing,
            "ticket_url": entry.get("jira_ticket_url") or f"{base}/browse/{existing}",
            "already_exists": True,
        }

    result = create_jira_ticket(entry)
    if isinstance(result, dict) and result.get("error"):
        raise HTTPException(status_code=502, detail=result["error"])

    ticket_key = str(result)
    base = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
    ticket_url = f"{base}/browse/{ticket_key}"
    entry["jira_ticket_key"] = ticket_key
    entry["jira_ticket_url"] = ticket_url

    return {"ticket_key": ticket_key, "ticket_url": ticket_url, "already_exists": False}

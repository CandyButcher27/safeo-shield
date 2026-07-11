"""Jira Cloud REST client for escalating SafeO log entries."""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Union

import requests

logger = logging.getLogger("safeo.jira_client")


def _jira_email() -> str:
    return (
        os.environ.get("JIRA_EMAIL", "").strip()
        or os.environ.get("JIRA_USER_EMAIL", "").strip()
    )


def _jira_config() -> Dict[str, str]:
    return {
        "base_url": os.environ.get("JIRA_BASE_URL", "").rstrip("/"),
        "email": _jira_email(),
        "token": os.environ.get("JIRA_API_TOKEN", "").strip(),
        "project_key": os.environ.get("JIRA_PROJECT_KEY", "AMD").strip(),
    }


def create_jira_ticket(log_entry: Dict[str, Any]) -> Union[str, Dict[str, str]]:
    """
    Create a Jira Task for a SafeO request log entry.

    Returns the created issue key (e.g. ``AMD-2``) on success, or
    ``{"error": "<message>"}`` on failure.
    """
    cfg = _jira_config()
    if not all([cfg["base_url"], cfg["email"], cfg["token"], cfg["project_key"]]):
        return {"error": "Jira is not configured (set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY)"}

    source = log_entry.get("source_system") or log_entry.get("module") or "unknown"
    risk_pct = round(float(log_entry.get("risk_score", 0) or 0) * 100)
    decision = str(log_entry.get("decision", "unknown")).upper()
    request_id = log_entry.get("request_id", "—")
    timestamp = log_entry.get("timestamp") or "—"
    tier = log_entry.get("tier_used", 1)

    summary = f"Security Alert: {source} — Risk {risk_pct}% — {decision}"
    description_text = (
        f"SafeO security log escalation\n\n"
        f"Request ID: {request_id}\n"
        f"Timestamp: {timestamp}\n"
        f"Tier: {tier}\n"
        f"Risk score: {log_entry.get('risk_score', 0)}\n"
        f"Decision: {decision}\n"
        f"Source: {source}\n"
        f"User: {log_entry.get('user_id', '—')}\n"
        f"Patterns: {', '.join((log_entry.get('patterns') or [])[:8]) or '—'}"
    )

    payload = {
        "fields": {
            "project": {"key": cfg["project_key"]},
            "summary": summary[:255],
            "issuetype": {"name": "Task"},
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description_text}],
                    }
                ],
            },
        }
    }

    try:
        resp = requests.post(
            f"{cfg['base_url']}/rest/api/3/issue",
            json=payload,
            auth=(cfg["email"], cfg["token"]),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=15,
        )
        if resp.status_code in (200, 201):
            key = resp.json().get("key")
            if key:
                logger.info("Jira ticket created: %s for request %s", key, request_id)
                return key
            return {"error": "Jira returned success but no issue key"}
        try:
            detail = resp.json()
            msg = detail.get("errorMessages") or detail.get("errors") or resp.text
        except Exception:
            msg = resp.text or f"HTTP {resp.status_code}"
        logger.warning("Jira ticket creation failed (%s): %s", resp.status_code, msg)
        return {"error": str(msg)[:500]}
    except requests.RequestException as exc:
        logger.warning("Jira request failed: %s", exc)
        return {"error": str(exc)}

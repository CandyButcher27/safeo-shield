"""Agent log helper — posts structured messages to the WebSocket broadcaster."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .ws_broadcaster import broadcaster


def _build_message(
    scan_id: str,
    agent_name: str,
    content: str,
    status: str,
    metadata: dict,
) -> dict:
    return {
        "scan_id": scan_id,
        "agent": agent_name,
        "content": content,
        "status": status,
        "metadata": metadata,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def agent_post(
    scan_id: str,
    agent_name: str,
    content: str,
    status: str = "info",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    if not scan_id:
        return
    message = _build_message(scan_id, agent_name, content, status, metadata or {})
    await broadcaster.broadcast(scan_id, message)


def schedule_agent_post(
    scan_id: Optional[str],
    agent_name: str,
    content: str,
    status: str = "info",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Fire agent_post from sync code when an event loop is running."""
    if not scan_id:
        return
    coro = agent_post(scan_id, agent_name, content, status, metadata)
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro)
    except RuntimeError:
        asyncio.run(coro)

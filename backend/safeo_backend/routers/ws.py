"""WebSocket routes for live agent investigation streams."""
from __future__ import annotations

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..utils.ws_broadcaster import broadcaster

logger = logging.getLogger("safeo.ws")

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/investigation/{scan_id}")
async def investigation_ws(websocket: WebSocket, scan_id: str) -> None:
    await websocket.accept()
    await broadcaster.connect(scan_id, websocket)
    try:
        for msg in broadcaster.get_history(scan_id):
            await websocket.send_json(msg)
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("ws investigation %s closed: %s", scan_id, exc)
    finally:
        await broadcaster.disconnect(scan_id, websocket)

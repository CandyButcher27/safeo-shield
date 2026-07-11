"""In-memory WebSocket broadcaster for live agent investigation logs."""

from __future__ import annotations

from collections import deque
from typing import Any, Deque, Dict, List

from fastapi import WebSocket


class WsBroadcaster:
    def __init__(self) -> None:
        self.connections: Dict[str, List[WebSocket]] = {}
        self._history: Dict[str, Deque[dict]] = {}
        self._max_history = 200

    def _history_for(self, scan_id: str) -> Deque[dict]:
        if scan_id not in self._history:
            self._history[scan_id] = deque(maxlen=self._max_history)
        return self._history[scan_id]

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        self.connections.setdefault(scan_id, []).append(websocket)

    async def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        conns = self.connections.get(scan_id, [])
        if websocket in conns:
            conns.remove(websocket)
        if not conns and scan_id in self.connections:
            del self.connections[scan_id]

    def get_history(self, scan_id: str) -> List[dict]:
        return list(self._history_for(scan_id))

    async def broadcast(self, scan_id: str, message: dict) -> None:
        self._history_for(scan_id).append(message)
        dead: List[WebSocket] = []
        for ws in self.connections.get(scan_id, []):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(scan_id, ws)


broadcaster = WsBroadcaster()

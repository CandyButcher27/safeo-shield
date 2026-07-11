"""
SafeO Python SDK — thin HTTP client for the /v1 universal API.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests


class SafeOError(Exception):
    """Raised when the SafeO API returns a non-2xx response."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"[{status_code}] {message}")


class SafeOClient:
    def __init__(self, api_key: str, base_url: str = "http://localhost:8001"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })

    def _request(self, method: str, path: str, **kwargs) -> Any:
        url = f"{self.base_url}{path}"
        resp = self._session.request(method, url, timeout=30, **kwargs)
        if not resp.ok:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            raise SafeOError(resp.status_code, str(detail))
        return resp.json()

    def scan(self, input_text: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = {"input": input_text, "context": context or {}}
        return self._request("POST", "/v1/scan", json=payload)

    def scan_batch(
        self, inputs: List[str], context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        payload = {"inputs": inputs, "context": context or {}}
        return self._request("POST", "/v1/scan/batch", json=payload)

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/health")

    def submit_feedback(
        self, scan_id: str, verdict: str, reviewer: str = "sdk"
    ) -> Dict[str, Any]:
        payload = {"scan_id": scan_id, "verdict": verdict, "reviewer": reviewer}
        return self._request("POST", "/v1/feedback", json=payload)

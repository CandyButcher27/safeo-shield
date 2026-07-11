"""
Bearer-token auth for /v1/* routes only.

Reads SAFEO_API_KEYS (comma-separated). Token ``internal`` is always valid for Odoo.
"""
from __future__ import annotations

import os
from typing import Set

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


def _valid_tokens() -> Set[str]:
    raw = os.getenv("SAFEO_API_KEYS", "internal")
    tokens = {t.strip() for t in raw.split(",") if t.strip()}
    tokens.add("internal")
    return tokens


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Reject unauthenticated requests to /v1/* with 401."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith("/v1/"):
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={
                    "detail": "Missing or invalid Authorization header. "
                    "Use: Authorization: Bearer <your-api-key>",
                },
            )

        token = auth[7:].strip()
        if token not in _valid_tokens():
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid API key. Check SAFEO_API_KEYS configuration."},
            )

        return await call_next(request)

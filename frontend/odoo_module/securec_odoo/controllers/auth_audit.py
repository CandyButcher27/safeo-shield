import logging

from odoo import http
from odoo.http import request
from odoo.addons.web.controllers.home import Home
from odoo.addons.web.controllers.session import Session

_logger = logging.getLogger(__name__)


def _client_ip():
    forwarded = request.httprequest.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.httprequest.remote_addr


def _safe_log_event(values):
    try:
        request.env["securec.audit.log"].sudo().log_event(values)
    except Exception as exc:
        _logger.debug("SafeO audit event logging skipped: %s", exc)


class SafeOHomeAudit(Home):
    @http.route("/web/login", type="http", auth="none", readonly=False)
    def web_login(self, redirect=None, **kw):
        method = request.httprequest.method
        attempted_login = kw.get("login") or request.params.get("login")
        route = request.httprequest.path
        user_agent = request.httprequest.headers.get("User-Agent")

        response = super().web_login(redirect=redirect, **kw)

        if method == "POST":
            success = bool(request.params.get("login_success"))
            uid = request.session.uid if success and request.session.uid else False
            _safe_log_event({
                "event_type": "login_success" if success else "login_failed",
                "application": "Authentication",
                "status": "success" if success else "failed",
                "user_id": uid,
                "login": attempted_login,
                "route": route,
                "http_method": "POST",
                "ip_address": _client_ip(),
                "user_agent": user_agent,
                "details": "Authentication via /web/login",
            })
        return response


class SafeOSessionAudit(Session):
    @http.route("/web/session/destroy", type="jsonrpc", auth="user", readonly=True)
    def destroy(self):
        uid = request.session.uid
        _safe_log_event({
            "event_type": "session_destroy",
            "application": "Authentication",
            "status": "success",
            "user_id": uid or False,
            "login": request.env.user.login if request.env.user else False,
            "route": "/web/session/destroy",
            "http_method": "JSONRPC",
            "ip_address": _client_ip(),
            "user_agent": request.httprequest.headers.get("User-Agent"),
            "details": "Session destroyed by user action",
        })
        return super().destroy()

    @http.route("/web/session/logout", type="http", auth="none", readonly=True)
    def logout(self, redirect="/odoo"):
        uid = request.session.uid
        login = False
        try:
            if uid:
                login = request.env["res.users"].sudo().browse(uid).login
        except Exception:
            login = False
        _safe_log_event({
            "event_type": "logout",
            "application": "Authentication",
            "status": "success",
            "user_id": uid or False,
            "login": login,
            "route": "/web/session/logout",
            "http_method": "GET",
            "ip_address": _client_ip(),
            "user_agent": request.httprequest.headers.get("User-Agent"),
            "details": "Logout via web session route",
        })
        return super().logout(redirect=redirect)

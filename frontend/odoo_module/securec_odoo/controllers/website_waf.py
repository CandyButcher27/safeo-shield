import json
import logging

import requests

from odoo import _, http
from odoo.addons.auth_signup.controllers.main import AuthSignupHome
from odoo.addons.website.controllers.form import WebsiteForm
from odoo.http import request

from ..models.securec_language import build_language_payload

_logger = logging.getLogger(__name__)

_SKIPPED_FORM_KEYS = {
    "csrf_token",
    "model_name",
    "website_form_signature",
    "context",
    "g-recaptcha-response",
    "cf-turnstile-response",
    "redirect",
    "success_page",
    "success_mode",
}


def _icp():
    return request.env["ir.config_parameter"].sudo()


def _enabled(key, default="True"):
    return _icp().get_param(key, default) == "True"


def _api_url():
    return _icp().get_param("securec.api_url", "http://localhost:8001")


def _client_ip():
    forwarded = request.httprequest.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.httprequest.remote_addr


def _active_policy():
    policy_id = int(_icp().get_param("securec.active_policy_id", 0) or 0)
    if not policy_id:
        return None
    policy = request.env["securec.policy"].sudo().browse(policy_id)
    return policy if policy.exists() else None


def _payload_from_form(values):
    parts = []
    for key, value in (values or {}).items():
        if key in _SKIPPED_FORM_KEYS:
            continue
        if hasattr(value, "filename"):
            parts.append(f"{key}=[file:{value.filename}]")
            continue
        if value in (None, False):
            continue
        text = str(value).strip()
        if text:
            parts.append(f"{key}={text}")
    return " | ".join(parts)[:3000]


def _audit_log(event_type, status, details, decision=None, risk_score=0.0, route=None, module="Website"):
    try:
        request.env["securec.audit.log"].sudo().log_event({
            "event_type": event_type,
            "application": module,
            "status": status,
            "user_id": request.session.uid or False,
            "login": request.env.user.login if request.env.user else False,
            "route": route or request.httprequest.path,
            "http_method": request.httprequest.method,
            "ip_address": _client_ip(),
            "user_agent": request.httprequest.headers.get("User-Agent"),
            "details": details,
            "risk_score": risk_score,
            "decision": decision,
            "policy_region": _active_policy().region if _active_policy() else False,
        })
    except Exception as exc:
        _logger.debug("SafeO website audit logging skipped: %s", exc)


def _scan_payload(payload, module, route):
    if not payload:
        return {"risk_score": 0.0, "decision": "allow", "explanation": "No payload"}

    policy = _active_policy()
    lang_payload = build_language_payload(payload)
    api_payload = {
        "input_text": payload,
        "normalized_input": lang_payload["normalized_input"],
        "language": lang_payload["language"],
        "user_id": str(request.session.uid or "public"),
        "module": module,
        "context": {"route": route, "public": not bool(request.session.uid)},
    }
    if policy:
        api_payload["region"] = policy.region
        api_payload["policy"] = policy.get_policy_dict()

    try:
        response = requests.post(f"{_api_url()}/waf/input", json=api_payload, timeout=5)
        if response.status_code != 200:
            raise RuntimeError(f"status={response.status_code}")
        data = response.json()
    except Exception as exc:
        _audit_log(
            event_type="api_failure",
            status="warning",
            details=f"Website WAF API failure (fail-safe allow): {exc}",
            route=route,
            module=module,
        )
        return {"risk_score": 0.0, "decision": "allow", "explanation": f"API failure: {exc}", "detected_patterns": []}

    risk_score = float(data.get("risk_score", 0.0))
    decision = data.get("decision", "allow")
    explanation = data.get("explanation", "")
    patterns = data.get("detected_patterns", [])

    block_threshold = float(_icp().get_param("securec.block_threshold", "0.70"))
    if policy:
        block_threshold = policy.block_threshold
    if risk_score >= block_threshold and decision != "block":
        decision = "block"

    if decision == "block":
        event_type = "waf_block"
        status = "blocked"
    elif decision in ("warn", "sanitize"):
        event_type = "waf_scan"
        status = "warning"
    else:
        event_type = "waf_scan"
        status = "success"

    _audit_log(
        event_type=event_type,
        status=status,
        details=f"{module} payload scanned. Decision={decision}. Patterns={', '.join(patterns) or 'none'}",
        decision=decision,
        risk_score=risk_score,
        route=route,
        module=module,
    )
    return data | {"decision": decision}


class SafeOWebsiteForm(WebsiteForm):
    @http.route(
        "/website/form/<string:model_name>",
        type="http",
        auth="public",
        methods=["POST"],
        website=True,
        csrf=False,
        captcha="website_form",
    )
    def website_form(self, model_name, **kwargs):
        if _enabled("securec.enable_website_form", "True"):
            route = f"/website/form/{model_name}"
            payload = _payload_from_form(dict(request.params))
            result = _scan_payload(payload, module="Website", route=route)
            if result.get("decision") == "block":
                return json.dumps({
                    "error": _(
                        "SafeO blocked this website form submission. "
                        "Please remove suspicious content and try again."
                    )
                })
        return super().website_form(model_name, **kwargs)


class SafeOSignupWAF(AuthSignupHome):
    @http.route(
        "/web/signup",
        type="http",
        auth="public",
        website=True,
        sitemap=False,
        captcha="signup",
    )
    def web_auth_signup(self, *args, **kw):
        if request.httprequest.method == "POST" and _enabled("securec.enable_signup_protection", "True"):
            payload = _payload_from_form({
                "login": kw.get("login") or request.params.get("login"),
                "name": kw.get("name") or request.params.get("name"),
                "password": kw.get("password") or request.params.get("password"),
            })
            result = _scan_payload(payload, module="Website", route="/web/signup")
            if result.get("decision") == "block":
                qcontext = self.get_auth_signup_qcontext()
                qcontext["error"] = _(
                    "SafeO blocked this signup attempt due to a high-risk payload."
                )
                response = request.render("auth_signup.signup", qcontext)
                response.headers["X-Frame-Options"] = "SAMEORIGIN"
                response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
                return response
        return super().web_auth_signup(*args, **kw)

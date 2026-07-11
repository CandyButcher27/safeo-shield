"""
securec.audit.log — ERP Audit Trail
=====================================
Records every security-relevant event in the ERP system:
- Authentication: login / logout / failed login (with IP)
- Decision Engine scans: every input checked by the risk engine
- API health events: when the backend is unreachable

WHY keep this separate from safeo.erp.decision?
------------------------------------------------
erp.decision stores structured ERP-context outcomes (module, impact, score).
audit.log captures raw events including auth events that have no ERP module
context (e.g. a failed login attempt).  Together they give a complete picture:
the audit log is the "what happened", the decision log is the "what was decided".
"""

from odoo import models, fields, api


class SafeOAuditLog(models.Model):
    _name = "securec.audit.log"
    _description = "ERP Audit Trail"
    _order = "timestamp desc"
    _rec_name = "event_type"

    timestamp = fields.Datetime(string="Timestamp", default=fields.Datetime.now, required=True, index=True)
    event_type = fields.Selection([
        ("login_success", "Login Success"),
        ("login_failed", "Login Failed"),
        ("logout", "Logout"),
        ("session_destroy", "Session Destroy"),
        ("waf_scan", "WAF Scan"),
        ("waf_block", "WAF Block"),
        ("api_failure", "API Failure"),
    ], string="Event Type", required=True, index=True)
    application = fields.Char(string="Application", default="Authentication", index=True)
    status = fields.Selection([
        ("success", "Success"),
        ("warning", "Warning"),
        ("failed", "Failed"),
        ("blocked", "Blocked"),
    ], string="Status", default="success", index=True)

    user_id = fields.Many2one("res.users", string="User", ondelete="set null", index=True)
    login = fields.Char(string="Login")
    route = fields.Char(string="Route")
    http_method = fields.Char(string="HTTP Method")
    ip_address = fields.Char(string="IP Address")
    user_agent = fields.Char(string="User Agent")
    details = fields.Text(string="Details")

    risk_score = fields.Float(string="Risk Score", digits=(3, 3))
    decision = fields.Selection([
        ("allow", "Allow"),
        ("warn", "Warn"),
        ("block", "Block"),
        ("sanitize", "Sanitize"),
    ], string="Decision")
    detected_language = fields.Selection([
        ("en", "English"),
        ("ar", "Arabic"),
        ("mixed", "Mixed / Arabizi"),
    ], string="Language")
    policy_region = fields.Char(string="Policy Region")
    securec_log_id = fields.Many2one("securec.log", string="Security Log", ondelete="set null")

    @api.model
    def log_event(self, vals):
        payload = dict(vals or {})
        payload.setdefault("timestamp", fields.Datetime.now())
        return self.sudo().create(payload)

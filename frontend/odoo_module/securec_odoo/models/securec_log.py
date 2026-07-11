import logging
import requests
from odoo import models, fields, api

_logger = logging.getLogger(__name__)


class SafeOLog(models.Model):
    _name = 'securec.log'
    _description = 'SafeO Security Audit Log'
    _order = 'timestamp desc'
    _rec_name = 'input_preview'

    input_text = fields.Text('Input Text', required=True)
    input_preview = fields.Char('Input Preview', compute='_compute_preview', store=True)
    risk_score = fields.Float('Risk Score', digits=(3, 3), required=True)
    risk_level = fields.Selection([
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ], string='Risk Level', compute='_compute_risk_level', store=True)
    decision = fields.Selection([
        ('allow', 'Allow'),
        ('warn', 'Warn'),
        ('block', 'Block'),
        ('sanitize', 'Sanitize'),
    ], string='Decision', required=True, default='allow')
    explanation = fields.Text('AI Explanation')
    detected_patterns = fields.Text('Detected Patterns')
    sanitized_text = fields.Text('Sanitized Input')
    timestamp = fields.Datetime('Timestamp', default=fields.Datetime.now, required=True)
    user_id = fields.Many2one('res.users', string='User', default=lambda self: self.env.user)
    module = fields.Char('Module', default='generic')
    jira_ticket_id = fields.Char('Jira Ticket ID')
    jira_ticket_url = fields.Char('Jira Ticket URL')

    # ── Multilingual Detection ─────────────────────────────────────────────
    detected_language = fields.Selection([
        ('en', 'English'),
        ('ar', 'Arabic'),
        ('mixed', 'Mixed / Arabizi'),
    ], string='Detected Language', default='en', index=True)
    normalized_text = fields.Text('Normalized Input',
        help='Arabizi-normalized version of the input, if applicable.')

    # ── Region Policy ──────────────────────────────────────────────────────
    policy_id = fields.Many2one('securec.policy', string='Applied Policy', ondelete='set null')
    policy_region = fields.Char('Policy Region', help='Snapshot of region code at time of event.')
    policy_decision_reason = fields.Char('Policy Decision Reason',
        help='Human-readable reason for the adjusted decision (e.g. Blocked due to UAE policy).')

    # ── ML pipeline signals (from FastAPI backend) ─────────────────────────
    script_detected = fields.Char('Script Detected', readonly=True)
    evasion_suspected = fields.Boolean('Evasion Suspected', default=False)
    tier_used = fields.Selection([
        ('1', 'Tier 1 — Heuristic'),
        ('2', 'Tier 2 — distilBERT'),
        ('llm', 'Tier 3 — Local LLM'),
    ], string='ML Tier Used')
    behavioural_risk_score = fields.Float('Behavioural Risk Score', digits=(3, 2))
    temporal_signals = fields.Text('Temporal Signals (JSON)')
    investigation_id = fields.Char('Investigation ID')
    investigation_verdict = fields.Selection([
        ('pending', 'Pending'),
        ('cleared', 'Cleared'),
        ('confirmed', 'Confirmed Block'),
    ], string='Investigation Verdict')

    @api.depends('input_text')
    def _compute_preview(self):
        for rec in self:
            rec.input_preview = (rec.input_text or '')[:80] + ('...' if len(rec.input_text or '') > 80 else '')

    @api.depends('risk_score')
    def _compute_risk_level(self):
        for rec in self:
            if rec.risk_score >= 0.70:
                rec.risk_level = 'high'
            elif rec.risk_score >= 0.30:
                rec.risk_level = 'medium'
            else:
                rec.risk_level = 'low'

    @api.model_create_multi
    def create(self, vals_list):
        records = super().create(vals_list)
        for record in records:
            if record.risk_score >= 0.70:
                record._try_create_jira_ticket()
                record._send_odoo_notification()
        return records

    def _try_create_jira_ticket(self):
        """Auto-create a Jira issue for high-risk threats."""
        params = self.env['ir.config_parameter'].sudo()
        jira_url = params.get_param('securec.jira_url')
        jira_user = params.get_param('securec.jira_user')
        jira_token = params.get_param('securec.jira_token')
        jira_project = params.get_param('securec.jira_project', 'SEC')

        if not all([jira_url, jira_user, jira_token]):
            return

        try:
            payload = {
                "fields": {
                    "project": {"key": jira_project},
                    "summary": f"[SafeO] High-risk threat detected — {self.module} module",
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [{
                            "type": "paragraph",
                            "content": [{
                                "type": "text",
                                "text": (
                                    f"SafeO detected a high-risk security threat.\n\n"
                                    f"Risk Score: {self.risk_score:.0%}\n"
                                    f"Decision: {self.decision}\n"
                                    f"Module: {self.module}\n"
                                    f"User: {self.user_id.name or 'Unknown'}\n"
                                    f"Timestamp: {self.timestamp}\n\n"
                                    f"Input (truncated): {self.input_text[:300]}\n\n"
                                    f"AI Explanation: {self.explanation or 'N/A'}\n"
                                    f"Patterns: {self.detected_patterns or 'N/A'}"
                                )
                            }]
                        }]
                    },
                    "issuetype": {"name": "Bug"},
                    "priority": {"name": "High"},
                }
            }
            resp = requests.post(
                f"{jira_url}/rest/api/3/issue",
                json=payload,
                auth=(jira_user, jira_token),
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                self.sudo().write({
                    'jira_ticket_id': data.get('key'),
                    'jira_ticket_url': f"{jira_url}/browse/{data.get('key')}",
                })
                _logger.info(f"SafeO: Jira ticket created — {data.get('key')}")
        except Exception as e:
            _logger.warning(f"SafeO: Jira ticket creation failed — {e}")

    def _send_odoo_notification(self):
        """Send Odoo bus notification for high-risk threats."""
        try:
            self.env['bus.bus']._sendone(
                self.env.user.partner_id,
                'securec.alert',
                {
                    'type': 'danger',
                    'title': '🛡️ SafeO Alert',
                    'message': f'High-risk threat blocked in {self.module} (score: {self.risk_score:.0%})',
                }
            )
        except Exception:
            pass

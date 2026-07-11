"""
ERP Protection Layer — CRM Lead Risk Interception
==================================================
WHY intercept at the ORM level rather than the controller layer?
CRM leads arrive from multiple sources: website forms, CRM kanban, API
clients, and email aliases.  Hooking into ``create``/``write`` at the model
layer guarantees every lead passes through the risk engine regardless of
entry point — no controller can be bypassed.

HOW decisions affect the ERP flow
----------------------------------
ALLOW   → lead is saved normally; risk metadata stored on the record.
WARN    → lead saved but flagged (securec_flagged = True) for review.
BLOCK   → UserError raised before super().create() runs; nothing is saved.
SANITIZE → cleaned text replaces vals content before super().create().
"""

import logging
import requests
from odoo import models, fields, api
from odoo.exceptions import UserError
from .securec_language import build_language_payload, detect_language

_logger = logging.getLogger(__name__)

# Fields inspected for risk content.  Phone/email are included because
# attackers sometimes embed injection payloads in structured fields to
# bypass name-only filters.
CHECKED_FIELDS = ['name', 'description', 'partner_name', 'email_from', 'phone', 'street', 'city']

# Human-readable region names for policy decision messages
REGION_LABELS = {
    'uae': 'UAE',
    'eu': 'EU (GDPR)',
    'us': 'US',
    'global': 'Global',
}

PII_STRICTNESS_LABELS = {
    'low': 'low PII sensitivity',
    'medium': 'medium PII sensitivity',
    'high': 'high PII sensitivity',
    'very_high': 'very high PII sensitivity (GDPR)',
}


class CrmLead(models.Model):
    # _inherit extends crm.lead without touching Odoo source files.
    # All new fields are prefixed 'securec_' to avoid naming collisions.
    _inherit = 'crm.lead'

    # Risk metadata stored on each lead so sales teams can filter flagged leads
    # directly from the CRM kanban or pipeline view.
    securec_risk_score = fields.Float('ERP Risk Score', default=0.0, digits=(3, 3))
    securec_decision = fields.Selection([
        ('allow', 'Approved'),
        ('warn', 'Flagged for Review'),
        ('block', 'Blocked'),
        ('sanitize', 'Sanitized'),
    ], string='ERP Decision', default='allow')
    securec_explanation = fields.Text('Risk Explanation')
    securec_flagged = fields.Boolean('Risk Flagged', default=False)
    securec_log_id = fields.Many2one('securec.log', string='Risk Log Entry')

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            self._run_waf_check(vals)
        return super().create(vals_list)

    def write(self, vals):
        if any(f in vals for f in CHECKED_FIELDS):
            self._run_waf_check(vals)
        return super().write(vals)

    # ── Helper: get active policy ─────────────────────────────────────────

    def _get_active_policy(self):
        """Return the active securec.policy record or None."""
        params = self.env['ir.config_parameter'].sudo()
        policy_id = int(params.get_param('securec.active_policy_id', 0))
        if policy_id:
            policy = self.env['securec.policy'].sudo().browse(policy_id)
            if policy.exists():
                return policy
        return None

    # ── Main WAF check ────────────────────────────────────────────────────

    def _run_waf_check(self, vals):
        """
        Intercept lead data and route it through the ERP risk engine before saving.

        Called synchronously from create() and write() so the UserError raised
        on BLOCK halts the ORM operation before any database commit occurs.
        On API failures we fail-open (fail-safe allow) to avoid blocking
        legitimate business activity during engine downtime.
        """
        params = self.env['ir.config_parameter'].sudo()

        if not params.get_param('securec.enable_crm', 'True') == 'True':
            return

        text_parts = [str(vals[f]) for f in CHECKED_FIELDS if vals.get(f)]
        if not text_parts:
            return

        input_text = ' | '.join(text_parts)
        api_url = params.get_param('securec.api_url', 'http://localhost:8001')

        # ── Fetch active policy (may be None) ────────────────────────────
        policy = self._get_active_policy()
        block_threshold = (
            policy.block_threshold
            if policy
            else float(params.get_param('securec.block_threshold', '0.70'))
        )
        warn_threshold = float(params.get_param('securec.warn_threshold', '0.30'))

        # ── Language detection + Arabizi normalization ────────────────────
        lang_payload = build_language_payload(input_text)
        language = lang_payload['language']
        normalized = lang_payload['normalized_input']

        # ── Build API request payload ─────────────────────────────────────
        api_payload = {
            "input_text": input_text,
            "normalized_input": normalized,
            "language": language,
            "user_id": str(self.env.user.id),
            "module": "CRM",
            "context": {"lead_stage": vals.get('stage_id')},
        }
        if policy:
            api_payload["region"] = policy.region
            api_payload["policy"] = policy.get_policy_dict()

        try:
            resp = requests.post(
                f"{api_url}/waf/input",
                json=api_payload,
                timeout=5,
            )

            if resp.status_code != 200:
                _logger.warning(f"SafeO API returned {resp.status_code}")
                return

            data = resp.json()
            risk_score = data.get('risk_score', 0.0)
            decision = data.get('decision', 'allow')
            explanation = data.get('explanation', '')
            patterns = data.get('detected_patterns', [])
            sanitized = data.get('sanitized_text')

            # ── Post-response: apply policy decision overrides ────────────
            policy_decision_reason = ''
            if policy:
                region_label = REGION_LABELS.get(policy.region, policy.region.upper())
                pii_label = PII_STRICTNESS_LABELS.get(policy.pii_strictness, policy.pii_strictness)

                if risk_score > policy.block_threshold and decision != 'block':
                    decision = 'block'
                    policy_decision_reason = (
                        f"Forced BLOCK by {region_label} policy: "
                        f"{pii_label} (threshold {policy.block_threshold:.0%})"
                    )
                elif decision == 'block':
                    policy_decision_reason = (
                        f"Blocked due to {region_label} policy: {pii_label}"
                    )

                if policy.masking_enabled and sanitized:
                    decision = 'sanitize'
                    policy_decision_reason += f" | PII masking active ({region_label})"

                if lang_payload.get('has_threat_signals'):
                    policy_decision_reason += f" | Multilingual threat signal detected [{language.upper()}]"
            else:
                if risk_score >= block_threshold:
                    decision = 'block'

            # ── Write security metadata back into vals ────────────────────
            vals['securec_risk_score'] = risk_score
            vals['securec_decision'] = decision
            vals['securec_explanation'] = explanation
            vals['securec_flagged'] = risk_score >= warn_threshold

            # ── Write ERP-native decision record ──────────────────────────
            # safeo.erp.decision is our primary ERP model — writing here
            # makes the decision queryable in any Odoo view or report.
            try:
                self.env['safeo.erp.decision'].sudo().log_erp_decision({
                    'affected_module': 'CRM',
                    'action': 'crm_lead_submission',
                    'user_id': str(self.env.user.login),
                    'risk_score': round(risk_score * 100),
                    'risk_score_raw': risk_score,
                    'decision': decision.upper() if decision.upper() in ('ALLOW', 'WARN', 'BLOCK') else 'ALLOW',
                    'reason': explanation,
                    'erp_impact': 'transaction_blocked' if decision == 'block' else 'flagged_for_review' if decision == 'warn' else 'transaction_approved',
                    'detected_patterns': patterns,
                    'network_signal': 'safe',
                    'request_id': data.get('request_id', ''),
                })
            except Exception as exc:
                _logger.debug("SafeO: could not write ERP decision record — %s", exc)

            # ── Persist risk engine audit log ─────────────────────────────
            log_vals = {
                'input_text': input_text[:1000],
                'risk_score': risk_score,
                'decision': decision,
                'explanation': explanation,
                'detected_patterns': ', '.join(patterns),
                'sanitized_text': sanitized,
                'user_id': self.env.user.id,
                'module': 'CRM',
                # Language fields
                'detected_language': language,
                'normalized_text': normalized if normalized != input_text else False,
                # Policy fields
                'policy_id': policy.id if policy else False,
                'policy_region': policy.region if policy else False,
                'policy_decision_reason': policy_decision_reason or False,
            }
            log = self.env['securec.log'].sudo().create(log_vals)
            vals['securec_log_id'] = log.id

            audit_event_type = 'waf_block' if decision == 'block' else 'waf_scan'
            audit_status = 'blocked' if decision == 'block' else ('warning' if decision == 'warn' else 'success')
            self.env['securec.audit.log'].log_event({
                'event_type': audit_event_type,
                'application': 'CRM',
                'status': audit_status,
                'user_id': self.env.user.id,
                'login': self.env.user.login,
                'route': 'crm.lead',
                'http_method': 'ORM',
                'details': f"Lead input scanned. Decision={decision}. Patterns={', '.join(patterns) or 'none'}",
                'risk_score': risk_score,
                'decision': decision,
                'detected_language': language,
                'policy_region': policy.region if policy else False,
                'securec_log_id': log.id,
            })

            # ── Track behavior ────────────────────────────────────────────
            try:
                requests.post(
                    f"{api_url}/waf/behavior",
                    json={"user_id": str(self.env.user.id), "action": "crm_lead_save", "module": "CRM"},
                    timeout=2,
                )
            except Exception:
                pass

            if decision == 'block':
                # Raising UserError here aborts the ORM transaction.
                # The lead record is never committed to the database.
                lang_info = f"[{language.upper()}]" if language != 'en' else ''
                raise UserError(
                    f"SafeO ERP Protection blocked this lead {lang_info}\n\n"
                    f"Risk Score: {risk_score:.0%}  |  Decision: {decision.upper()}\n\n"
                    f"Reason: {explanation}\n\n"
                    f"Detected patterns: {', '.join(patterns) or 'N/A'}\n\n"
                    + (f"Policy: {policy_decision_reason}\n\n" if policy_decision_reason else "")
                    + "Please remove the flagged content and try again.\n"
                    + (f"\nSuggested safe version:\n{sanitized}" if sanitized else "")
                )

        except UserError:
            raise
        except Exception as e:
            _logger.warning(f"SafeO WAF check failed (fail-safe allowing): {e}")
            self.env['securec.audit.log'].log_event({
                'event_type': 'api_failure',
                'application': 'CRM',
                'status': 'warning',
                'user_id': self.env.user.id,
                'login': self.env.user.login,
                'route': 'crm.lead',
                'http_method': 'ORM',
                'details': f"SafeO backend error (fail-safe allow): {e}",
            })

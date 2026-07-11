"""
SafeO Settings — extends Odoo's native Settings page
=====================================================
Uses _inherit on res.config.settings (TransientModel) to add SafeO
configuration fields directly to the standard Odoo Settings menu.

WHY TransientModel for settings?
---------------------------------
Odoo's settings pattern stores values via ir.config_parameter under the
hood.  The config_parameter= attribute on each field handles the
read/write mapping automatically.  No separate DB table is needed.
"""

from odoo import models, fields, api


class ResConfigSettings(models.TransientModel):
    # _inherit adds our fields to the existing Settings form without
    # creating a new model or modifying any Odoo core file.
    _inherit = 'res.config.settings'

    securec_api_url = fields.Char(
        string='Decision Engine API URL',
        config_parameter='securec.api_url',
        default='http://localhost:8001',
    )
    securec_block_threshold = fields.Float(
        string='Block Threshold',
        config_parameter='securec.block_threshold',
        default=0.70,
        help='Risk score above which inputs are blocked (0.0 – 1.0)',
    )
    securec_warn_threshold = fields.Float(
        string='Warn Threshold',
        config_parameter='securec.warn_threshold',
        default=0.30,
        help='Risk score above which a warning is shown (0.0 – 1.0)',
    )
    securec_estimated_exposure_aed_per_block = fields.Float(
        string='Illustrative exposure (AED per block)',
        config_parameter='securec.estimated_exposure_aed_per_block',
        default=500.0,
        help='Dashboard only: multiplied by today’s WAF block count for estimated exposure signal (not actual loss).',
    )
    securec_enable_crm = fields.Boolean(
        string='Enable CRM Lead Protection',
        config_parameter='securec.enable_crm',
        default=True,
    )
    securec_enable_output = fields.Boolean(
        string='Enable Output Leakage Protection',
        config_parameter='securec.enable_output',
        default=True,
    )
    securec_enable_behavior = fields.Boolean(
        string='Enable Employee Activity Monitoring',
        config_parameter='securec.enable_behavior',
        default=True,
    )
    securec_enable_website_form = fields.Boolean(
        string='Enable Website Form Protection',
        config_parameter='securec.enable_website_form',
        default=True,
    )
    securec_enable_signup_protection = fields.Boolean(
        string='Enable Signup Protection',
        config_parameter='securec.enable_signup_protection',
        default=True,
    )
    securec_enable_global_monitor = fields.Boolean(
        string='Enable Global App Monitor',
        config_parameter='securec.enable_global_monitor',
        default=True,
        help='When enabled, SafeO inspects suspicious mutating payloads from installed Odoo apps.',
    )
    securec_monitored_apps = fields.Char(
        string="Protected Applications",
        config_parameter="securec.monitored_apps",
        default="CRM,Authentication,Website,AttackLab,GlobalMonitor",
        help="Comma-separated app list shown in the SafeO dashboard scope panel.",
    )
    # Jira integration
    securec_jira_url = fields.Char(
        string='Jira Base URL',
        config_parameter='securec.jira_url',
        help='e.g. https://yourorg.atlassian.net',
    )
    securec_jira_user = fields.Char(
        string='Jira User Email',
        config_parameter='securec.jira_user',
    )
    securec_jira_token = fields.Char(
        string='Jira API Token',
        config_parameter='securec.jira_token',
    )
    securec_jira_project = fields.Char(
        string='Jira Project Key',
        config_parameter='securec.jira_project',
        default='SEC',
    )

    amd_gpu_enabled = fields.Boolean(
        string='AMD GPU Acceleration',
        config_parameter='securec.amd_gpu_enabled',
        default=True,
    )
    local_llm_url = fields.Char(
        string='Local LLM URL',
        config_parameter='securec.local_llm_url',
        default='http://localhost:8000/v1',
    )

    # ── Region & Policy ────────────────────────────────────────────────
    securec_active_policy_id = fields.Many2one(
        'securec.policy',
        string='Active Compliance Policy',
        help='Region-specific policy applied to all WAF checks.',
    )

    def get_values(self):
        res = super().get_values()
        param = self.env['ir.config_parameter'].sudo()
        policy_id = int(param.get_param('securec.active_policy_id', 0))
        res['securec_active_policy_id'] = policy_id
        return res

    def set_values(self):
        super().set_values()
        self.env['ir.config_parameter'].sudo().set_param(
            'securec.active_policy_id',
            str(self.securec_active_policy_id.id) if self.securec_active_policy_id else '0',
        )

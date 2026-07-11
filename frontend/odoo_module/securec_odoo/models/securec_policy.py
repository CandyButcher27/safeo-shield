from odoo import models, fields


class SafeOPolicy(models.Model):
    _name = 'securec.policy'
    _description = 'SafeO Regional Compliance Policy'
    _order = 'region'
    _rec_name = 'name'

    name = fields.Char(string='Policy Name', required=True)
    region = fields.Selection([
        ('uae', 'UAE'),
        ('eu', 'EU (GDPR)'),
        ('us', 'US'),
        ('global', 'Global'),
    ], string='Region', required=True, default='global')

    pii_strictness = fields.Selection([
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('very_high', 'Very High'),
    ], string='PII Strictness', required=True, default='medium')

    block_threshold = fields.Float(
        string='Block Threshold',
        default=0.75,
        digits=(3, 2),
        help='Risk score (0–1) above which inputs are blocked under this policy.',
    )
    masking_enabled = fields.Boolean(
        string='PII Masking Enabled',
        default=False,
        help='When enabled, high-risk outputs are sanitized before returning.',
    )
    logging_required = fields.Boolean(
        string='Mandatory Logging',
        default=True,
        help='When enabled, every event is guaranteed to be stored in the audit log.',
    )
    description = fields.Text(string='Policy Notes')

    def get_policy_dict(self):
        """Return a plain dict suitable for embedding in SafeO API requests."""
        self.ensure_one()
        return {
            'pii_strictness': self.pii_strictness,
            'block_threshold': self.block_threshold,
            'masking_enabled': self.masking_enabled,
            'logging_required': self.logging_required,
        }

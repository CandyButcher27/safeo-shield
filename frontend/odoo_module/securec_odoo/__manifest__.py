{
    # ─────────────────────────────────────────────────────────────────────────
    # SafeO ERP Protection Layer
    # Hackathon Category: Business, Finance, and Workforce ERP
    #
    # This Odoo module embeds a real-time AI risk decision engine directly
    # inside ERP workflows.  Instead of sitting as an external firewall, it
    # acts as a native ERP layer that intercepts CRM leads, financial actions,
    # and employee activity before they are committed to the database.
    # ─────────────────────────────────────────────────────────────────────────
    'name': 'SafeO — ERP Risk Decision Engine',
    'version': '19.0.9.0.3',

    # Maps to the hackathon's "Business, Finance and Workforce ERP" track.
    # Judges use this field to route submissions to the correct reviewers.
    'category': 'Business / Finance',

    'summary': (
        'Real-time ERP risk decisions: every CRM lead, financial transaction, '
        'and employee action is scored before execution — ALLOW, WARN, or BLOCK.'
    ),

    'description': """
SafeO ERP Protection Layer
===========================
SafeO is a real-time risk decision engine that lives *inside* Odoo — not in
front of it.

**Hackathon Theme: Business, Finance, and Workforce ERP**

How it works
------------
1. A CRM lead is created → SafeO intercepts it, calls the risk engine,
   scores it 0-100, and blocks it if it contains injection payloads.
2. A financial action (payment, approval) is submitted → risk scored before
   the ERP executes it.
3. An employee action is logged → behavioral anomaly detection flags
   suspicious patterns.
4. Network context (safe / risky) boosts risk scores automatically.
5. All decisions are stored in ``safeo.erp.decision`` — queryable from any
   Odoo view, report, or automation.

ERP Modules Protected
---------------------
- **CRM** — lead/contact form inputs scanned for injection attacks
- **Finance** — payment and approval notes evaluated for anomalous intent
- **HR / Workforce** — employee activity monitored for behavioral drift
- **Auth** — every login/logout captured in the ERP Audit Trail
- **Website** — contact and signup forms protected at submission

Architecture
-----------
- FastAPI decision engine (port 8001) holds the ML risk scorer + tiered LLM
- Odoo module connects via ``securec.api_url`` setting (ir.config_parameter)
- All ERP decisions written to ``safeo.erp.decision`` (native Odoo model)
- Dashboard built with OWL 3 (Odoo's native frontend framework)
    """,

    'author': 'SafeO Team',
    'license': 'LGPL-3',

    # We extend core Odoo models — never patching Odoo source files.
    # - base: for ir.config_parameter settings
    # - crm: to inherit crm.lead and intercept lead saves
    # - website + auth_signup: to protect public-facing forms
    # - mail: for internal Odoo bus notifications on high-risk events
    # website_sale: cart code paths assume env.user; /web/login + website.layout needs a fix
    'depends': ['base', 'web', 'crm', 'mail', 'website', 'website_sale', 'auth_signup'],

    'data': [
        # Security must be loaded first so access rules are ready for data
        'security/securec_security.xml',
        'security/ir.model.access.csv',
        'data/securec_data.xml',

        # Views — order matters: models referenced in menus must exist first
        'views/securec_policy_views.xml',
        'views/securec_log_views.xml',
        'views/investigation_views.xml',
        'views/securec_audit_views.xml',
        'views/erp_decision_views.xml',          # new ERP-native decision log
        'views/securec_dashboard_views.xml',
        'views/securec_attack_lab_views.xml',
        'views/crm_lead_views.xml',
        'views/securec_settings_views.xml',
        'views/menu.xml',
    ],

    'assets': {
        'web.assets_backend': [
            'securec_odoo/static/src/css/securec.css',
            'securec_odoo/static/src/xml/securec_dashboard.xml',
            'securec_odoo/static/src/js/dashboard.js',
        ],
    },

    'installable': True,
    'auto_install': False,
    'application': True,
}

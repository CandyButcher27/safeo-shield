# SafeO — Architecture

## System diagram

```
┌─────────────────────────────────────────────────────────────┐
│  Odoo 19 (e.g. http://127.0.0.1:8069)                        │
│  • OWL dashboard (static/src/js/dashboard.js)                │
│  • JSON-RPC /safeo/*  →  proxies to FastAPI                  │
│  • crm.lead inherit → POST /erp/crm/lead                     │
│  • Models: safeo.erp.decision, securec.log, audit, …         │
└────────────────────────────┬────────────────────────────────┘
                             │  HTTP  (default http://127.0.0.1:8001)
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  FastAPI — safeo_backend (SafeO/backend/safeo_backend)       │
│  routes/erp.py     — transaction, HR, CRM, finance, summary  │
│  routes/waf.py     — legacy /waf/input + shared request log  │
│  core/ml/*         — risk_scorer, entropy, keywords, n-gram  │
│  agents/*          — input/output/behavior (CUSUM)           │
└─────────────────────────────────────────────────────────────┘
```

## Backend layout (logical)

| Package / folder | Role |
|------------------|------|
| `routes/` | FastAPI routers (HTTP surface) |
| `core/ml/` | Risk engine: fusion scoring, patterns, optional LLM gate |
| `agents/` | Pluggable scanners (WAF-style + behavior) |
| `models/` | Pydantic request/response schemas |
| `utils/` | Reserved for small shared helpers |

## Data flow (CRM lead)

1. User submits lead in Odoo.
2. `crm_lead.py` builds text, POSTs to FastAPI `/erp/crm/lead`.
3. Engine returns ALLOW / WARN / BLOCK + score.
4. Odoo saves or blocks; may log `safeo.erp.decision` / `securec.log`.

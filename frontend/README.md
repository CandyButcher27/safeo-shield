# Frontend — Demo UI

Two surfaces share the same FastAPI backend on port **8001**.

## Structure

```
frontend/
├── odoo_module/              # Odoo 19 addon (securec_odoo) — primary demo
│   └── securec_odoo/
│       ├── static/src/js/dashboard.js
│       ├── static/src/xml/securec_dashboard.xml
│       └── controllers/main.py
└── website/                  # Vite + React standalone (:5174)
    ├── src/pages/Dashboard.jsx
    └── vite.config.js
```

## 1. Odoo dashboard (main hackathon demo)

**Port:** 8069

```bash
# odoo.conf addons_path must include:
# /path/to/repo/frontend/odoo_module
./venv/bin/python odoo-bin -c odoo.conf --http-port=8069
```

Install `securec_odoo` → Settings → API URL `http://127.0.0.1:8001`

| URL | Tab |
|-----|-----|
| http://127.0.0.1:8069/odoo/safeo | Dashboard |
| Sandbox | Live payload injection |
| Investigations | WebSocket agent timeline |
| Risk → Action | Jira escalation panel |

## 2. Standalone website

**Port:** 5174

```bash
cd frontend/website
npm install && npm run dev
```

Open http://localhost:5174 — backend/Odoo health cards + connect flow.

## API URL

Odoo reads `securec.api_url` from Settings (default `http://127.0.0.1:8001`).  
JSON-RPC routes `/safeo/*` proxy to the backend.

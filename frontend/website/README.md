# SafeO Standalone Website

Standalone demo dashboard at **http://localhost:5174** — connects to the same FastAPI backend (port 8001) and Odoo SafeO (port 8069).

## Quick start

```bash
cd safeo_website
npm install
npm run dev
```

Open http://localhost:5174

## Demo flow

1. Open the standalone dashboard
2. Click **Connect to Your ERP →** (nav or banner)
3. Odoo card shows **● Connected** when Odoo is running
4. Click **Open SafeO in Odoo →** — opens http://127.0.0.1:8069/odoo/safeo in a new tab

## Prerequisites

- FastAPI backend on `127.0.0.1:8001`
- Odoo with `securec_odoo` on `127.0.0.1:8069` (optional, for ERP connect demo)

Vite proxies `/api/*` → backend and `/odoo-health` → Odoo `/web/health` to avoid CORS in dev.

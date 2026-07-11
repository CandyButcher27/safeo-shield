# SafeO — Odoo integration module

**Technical folder name:** `securec_odoo` (Odoo uses the directory name as the add-on technical name — do not rename without updating all XML IDs and imports).

This is the **SafeO ERP Protection Layer** for **Odoo 19**: native models, menus, OWL dashboard, HTTP hooks, and CRM integration that call the FastAPI decision engine.

## What it hooks into

| Area | Mechanism |
|------|-----------|
| **CRM** | `crm.lead` inherit — scores lead text before save |
| **HTTP / website** | `ir.http` inherit + website controllers — optional global monitor |
| **Auth / audit** | Login events → `securec.audit.log` |
| **Settings** | `res.config.settings` — `securec.api_url` points to FastAPI |
| **Dashboard** | Client action loads OWL `SafeODashboard` |

## Install (judge checklist)

1. **PostgreSQL** running; create a database.
2. **Backend** running on `http://127.0.0.1:8001` (see `SafeO/README.md`).
3. Start Odoo with addons path including **this folder’s parent** `odoo_module`:

   ```bash
   ./odoo-bin -c odoo.conf -d your_db
   ```

   Example `addons_path` fragment:

   `...,/path/to/repo/SafeO/odoo_module`

4. **Apps** → remove “Apps” filter → search **SafeO** → **Install**.
5. **Settings → SafeO / General** → confirm **API URL** = `http://127.0.0.1:8001`.

## Connection to FastAPI

- `controllers/main.py` — JSON-RPC `/safeo/metrics`, `/safeo/logs`, `/safeo/context`, `/safeo/erp_module_summary`, etc., forwarding to the configured `securec.api_url`.
- `models/crm_lead.py` — POSTs lead payload to `/erp/crm/lead` on the engine.

No secrets in the module; optional LLM keys live only on the FastAPI host (`.env`).

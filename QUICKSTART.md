# SafeO — Demo Quickstart

Run from the **repo root**. Main folders: `backend/` · `frontend/`

---

## Section 1 — AMD GPU setup (optional, run once)

```bash
bash backend/amd_setup/install_rocm.sh
python backend/amd_setup/check_gpu.py
```

---

## Section 2 — Start local LLM on AMD GPU (optional)

```bash
bash backend/amd_setup/start_vllm.sh
```

Wait until: `Uvicorn running on http://0.0.0.0:8000`

---

## Section 3 — Start FastAPI backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env          # API keys, optional Fireworks/vLLM settings
export PYTHONPATH="$(pwd)"
uvicorn safeo_backend.main:app --host 127.0.0.1 --port 8001 --reload
```

Or: `backend/scripts/run_all.sh`

---

## Section 4 — Start Odoo

`addons_path` must include **`frontend/odoo_module`** (see `odoo.conf.example`).

```bash
cd /path/to/your/odoo
./venv/bin/python odoo-bin -c odoo.conf --http-port=8069
```

Install **SafeO — ERP Risk Decision Engine** (`securec_odoo`).  
Settings → API URL = `http://127.0.0.1:8001`

---

## Section 5 — Standalone website (optional)

```bash
cd frontend/website && npm install && npm run dev
```

Open http://localhost:5174

---

## Section 6 — Local agent graph

SafeO now uses an in-process LangGraph-style investigation graph:

```
Multilingual -> Policy + Forensics in parallel -> Verifier -> Remediation
```

No external Band setup is required. Optional Fireworks agent calls can be enabled
with `SAFEO_ENABLE_AGENT_LLM=true` and `SAFEO_AGENT_LLM_API_KEY`.

---

## Smoke tests

```bash
curl -s -X POST http://127.0.0.1:8001/v1/scan \
  -H "Authorization: Bearer internal" \
  -H "Content-Type: application/json" \
  -d '{"input": "1 OR 1=1; DROP TABLE users;--", "context": {"user_id": "demo"}}' \
  | python3 -m json.tool
```

Expected: `"decision": "BLOCK"`, non-empty `scan_id`

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Odoo offline | Start Odoo on 8069 |
| `401` on `/v1/*` | `Authorization: Bearer internal` |
| Agent logs missing | Check `/ws/investigation/{scan_id}` and investigation detail endpoint |
| Dashboard offline | API URL in Odoo Settings |

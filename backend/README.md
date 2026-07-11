# Backend — FastAPI Decision Engine

Python 3.11 · FastAPI · Uvicorn · port **8001**

## Structure

```
backend/
├── requirements.txt
├── .env.example              # → copy to backend/.env
├── scripts/run_all.sh        # Start uvicorn
├── amd_setup/                # Optional ROCm + vLLM (Tier 3)
├── sdk/python/               # SafeOClient for /v1/scan
└── safeo_backend/
    ├── main.py               # ASGI entry
    ├── routes/               # erp, universal (/v1), investigations, simulate
    ├── agents/               # LangGraph orchestration + specialist agents
    ├── core/ml/              # tiered_llm, risk_scorer, tier2_classifier
    ├── routers/ws.py         # WebSocket agent stream
    └── middleware/auth.py    # Bearer auth on /v1/*
```

## Run

```bash
cd backend
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env
export PYTHONPATH="$(pwd)"
uvicorn safeo_backend.main:app --host 127.0.0.1 --port 8001 --reload
```

Or from repo root: `backend/scripts/run_all.sh`

## Key endpoints

| Path | Auth |
|------|------|
| `/docs` | Open |
| `/v1/scan` | Bearer |
| `/v1/health` | Bearer |
| `/investigations/{scan_id}` | Open |
| `/ws/investigation/{scan_id}` | Open |

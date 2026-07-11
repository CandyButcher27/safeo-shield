"""
SafeO — FastAPI application entry point.

Registers all HTTP routes (ERP gates, legacy WAF compatibility, metrics, simulation)
and CORS. The ASGI app is exposed as `app` for:

    uvicorn safeo_backend.main:app --host 127.0.0.1 --port 8001

Upstream consumers: Odoo module (JSON-RPC proxy + website monitor), curl demos, Swagger at /docs.
"""
import logging
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .routes import waf, simulate, feedback, metrics, erp, investigations, universal, workflows, visual, logs
from .routes.visual import DEMO_PHISHING_HTML
from fastapi.responses import HTMLResponse
from .routers import ws as ws_router
from .middleware.auth import BearerAuthMiddleware
from .agents.behavior_agent import BehaviorAgent
from .models.schemas import BehaviorRequest

logger = logging.getLogger("safeo.startup")

_backend_root = Path(__file__).resolve().parents[2]
load_dotenv(_backend_root.parent / ".env", override=False)
load_dotenv(_backend_root / ".env", override=False)

app = FastAPI(
    title="SafeO ERP Shield — Decision Engine API",
    description=(
        "SafeO ERP Shield: a real-time risk decision engine embedded inside ERP workflows. "
        "Analyzes transactions, employee activity, CRM inputs, and data output for business-context threats."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8069",
        "http://127.0.0.1:8069",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(BearerAuthMiddleware)

app.include_router(waf.router)
app.include_router(simulate.router)
app.include_router(feedback.router)
app.include_router(metrics.router)
app.include_router(metrics.agents_router)
app.include_router(metrics.ml_router)
app.include_router(erp.router)
app.include_router(investigations.router)
app.include_router(universal.router)
app.include_router(workflows.router)
app.include_router(visual.router)
app.include_router(logs.router)
app.include_router(ws_router.router)

_static_dir = Path(__file__).resolve().parent / "static"
_static_dir.mkdir(parents=True, exist_ok=True)
(_static_dir / "screenshots").mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


@app.get("/demo/visual-phishing", response_class=HTMLResponse, include_in_schema=False)
async def demo_visual_phishing_page():
    """Local demo page for homograph URL visual evidence capture."""
    return HTMLResponse(DEMO_PHISHING_HTML)

_behavior_agent = BehaviorAgent()


def _startup_summary() -> None:
    """Print component readiness table on boot."""
    gpu_name = "none"
    gpu_ok = "no"
    try:
        from .utils.gpu_monitor import get_gpu_stats
        gs = get_gpu_stats()
        if gs.get("rocm_available"):
            gpu_ok = "yes"
            gpu_name = gs.get("device_name", "AMD GPU")
    except Exception:
        pass

    vllm_status = "unreachable"
    try:
        from .core.ml.llm_guard import is_llm_available
        vllm_status = "reachable" if is_llm_available() else "unreachable"
    except Exception:
        pass

    tier2_status = "fallback"
    try:
        from .core.ml.tier2_classifier import get_tier2_classifier
        clf = get_tier2_classifier()
        tier2_status = "loaded" if clf._model is not None else "fallback"
    except Exception:
        pass

    ml_status = "fallback"
    try:
        from .agents.multilingual_agent import MultilingualAgent
        ml_status = "loaded" if MultilingualAgent._model is not None else "fallback"
    except Exception:
        pass

    lines = [
        "",
        "╔══════════════════════════════════════════════════════╗",
        "║              SafeO Decision Engine Ready               ║",
        "╠══════════════════════════════════════════════════════╣",
        f"║  AMD GPU detected     : {gpu_ok:<28} ║",
        f"║  Device name          : {gpu_name[:28]:<28} ║",
        f"║  vLLM server          : {vllm_status:<28} ║",
        f"║  Tier 2 model         : {tier2_status:<28} ║",
        f"║  Multilingual model   : {ml_status:<28} ║",
        f"║  Agent graph          : {'LangGraph local':<28} ║",
        "║  SafeO ready on port  : 8001                         ║",
        "╚══════════════════════════════════════════════════════╝",
        "",
    ]
    banner = "\n".join(lines)
    try:
        print(banner)
    except UnicodeEncodeError:
        pass
    logger.info("SafeO startup: gpu=%s vllm=%s tier2=%s ml=%s", gpu_ok, vllm_status, tier2_status, ml_status)


@app.on_event("startup")
async def on_startup():
    try:
        from .utils.gpu_monitor import register_model
        register_model("distilbert-tier2")
        register_model("arabert-multilingual")
    except Exception:
        pass
    _startup_summary()


@app.post("/waf/behavior")
async def track_behavior(req: BehaviorRequest):
    return _behavior_agent.track_action(req.user_id, req.action)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "SafeO ERP Shield", "version": "2.0.0"}


@app.get("/")
async def root():
    return {
        "service": "SafeO ERP Shield — Decision Engine",
        "version": "2.0.0",
        "erp_endpoints": [
            "/erp/transaction",
            "/erp/employee/activity",
            "/erp/crm/lead",
            "/erp/finance/action",
            "/erp/network/signal",
            "/erp/dashboard/summary",
        ],
        "legacy_endpoints": [
            "/waf/input",
            "/waf/output",
            "/waf/behavior",
            "/simulate/attack",
            "/feedback",
            "/metrics",
        ],
        "ml_endpoints": [
            "/ml/tier-stats",
            "/ml/drift-status",
            "/ml/temporal-stats",
            "/ml/bayesian-threshold",
            "/ml/lora-finetune/status",
            "/ml/lora-finetune/decision",
        ],
        "investigation_endpoints": [
            "/investigations",
            "/investigations/{scan_id}",
            "/investigations/{scan_id}/approve",
            "/investigations/{scan_id}/reject",
        ],
        "universal_api": [
            "/v1/scan",
            "/v1/scan/batch",
            "/v1/scan/visual",
            "/v1/health",
            "/v1/feedback",
        ],
    }

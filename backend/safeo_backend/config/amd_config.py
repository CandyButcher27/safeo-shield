"""
AMD / ROCm configuration for SafeO ML tiers.

ROCm exposes HIP devices through PyTorch's CUDA API, so AMD_DEVICE is typically
``cuda`` when a GPU is visible. All settings can be overridden with environment
variables for local vLLM, Hugging Face models, and metrics collection.

Agent Model Specialization
--------------------------
Each investigation agent uses the model best suited to its cognitive task:

  MultilingualAgent  → AraBERT (aubmindlab/bert-base-arabertv2)
                       HuggingFace embedding — runs locally, GPU-accelerated.

  PolicyAgent        → Fireworks llama-v3p1-70b-instruct
                       Superior instruction-following and rule/citation tasks.

  ForensicsAgent     → Fireworks deepseek-r1
                       Chain-of-thought reasoning; MITRE ATT&CK mapping.

  RemediationAgent   → Fireworks llama-v3p1-8b-instruct
                       Fast structured-output generation; action list format.

Set SAFEO_ENABLE_AGENT_LLM=true to activate LLM augmentation inside the
investigation agents. When false (default) agents run their built-in rule
logic, ensuring zero-dependency cold-start.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

# Load repo-root .env for local dev (docker-compose uses env_file instead).
_repo_root = Path(__file__).resolve().parents[3]
load_dotenv(_repo_root / ".env", override=False)
load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _detect_amd_device() -> str:
    """Return ``cuda`` when ROCm/PyTorch sees a GPU, else ``cpu``."""
    forced = os.getenv("SAFEO_AMD_DEVICE", "").strip().lower()
    if forced in {"cuda", "cpu"}:
        return forced
    try:
        import torch

        if torch.cuda.is_available():
            return "cuda"
    except Exception:
        pass
    return "cpu"


# ── Tier pipeline models ─────────────────────────────────────────────────────

LLM_MODEL_NAME = os.getenv(
    "SAFEO_LLM_MODEL_NAME",
    "mistralai/Mistral-7B-Instruct-v0.2",
)
TIER2_MODEL_NAME = os.getenv(
    "SAFEO_TIER2_MODEL_NAME",
    "distilbert-base-uncased",
)
MULTILINGUAL_MODEL_NAME = os.getenv(
    "SAFEO_MULTILINGUAL_MODEL_NAME",
    "aubmindlab/bert-base-arabertv2",
)
LLM_SERVER_URL = os.getenv(
    "SAFEO_LLM_SERVER_URL",
    "http://localhost:8000/v1",
)

# ── Per-agent specialized models ─────────────────────────────────────────────
# Each model is chosen for the cognitive demands of that agent's task.
# Override via env var to point at local vLLM instances or alternative providers.

POLICY_AGENT_MODEL = os.getenv(
    "SAFEO_POLICY_AGENT_MODEL",
    "accounts/fireworks/models/llama-v3p1-70b-instruct",
)
FORENSICS_AGENT_MODEL = os.getenv(
    "SAFEO_FORENSICS_AGENT_MODEL",
    "accounts/fireworks/models/deepseek-r1",
)
REMEDIATION_AGENT_MODEL = os.getenv(
    "SAFEO_REMEDIATION_AGENT_MODEL",
    "accounts/fireworks/models/llama-v3p1-8b-instruct",
)
VERIFIER_AGENT_MODEL = os.getenv(
    "SAFEO_VERIFIER_AGENT_MODEL",
    "accounts/fireworks/models/llama-v3p1-8b-instruct",
)

# Set to "true" to activate LLM augmentation inside investigation agents.
# Agents fall back gracefully to deterministic rule logic when disabled.
ENABLE_AGENT_LLM: bool = _env_bool("SAFEO_ENABLE_AGENT_LLM", False)

# ── Bayesian threshold engine (Fireworks optional reasoning) ─────────────────
# Primary threshold math is deterministic Python. When enabled, Fireworks
# llama-v3p1-8b-instruct (temperature=0) generates the one-sentence reasoning.

FIREWORKS_API_KEY = os.getenv("FIREWORKS_API_KEY", "")
FIREWORKS_BASE_URL = os.getenv(
    "FIREWORKS_BASE_URL",
    "https://api.fireworks.ai/inference/v1",
)
AGENT_LLM_SERVER_URL = os.getenv("SAFEO_AGENT_LLM_SERVER_URL", FIREWORKS_BASE_URL)
AGENT_LLM_API_KEY = os.getenv("SAFEO_AGENT_LLM_API_KEY", FIREWORKS_API_KEY or "EMPTY")
BAYESIAN_LLM_MODEL = os.getenv(
    "SAFEO_BAYESIAN_LLM_MODEL",
    "accounts/fireworks/models/llama-v3p1-8b-instruct",
)
ENABLE_BAYESIAN_LLM: bool = _env_bool("SAFEO_ENABLE_BAYESIAN_LLM", False)

# ── Infrastructure ────────────────────────────────────────────────────────────

ENABLE_GPU_METRICS = _env_bool("SAFEO_ENABLE_GPU_METRICS", True)
AMD_DEVICE = _detect_amd_device()

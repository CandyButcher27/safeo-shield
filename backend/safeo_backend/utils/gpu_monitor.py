"""
GPU / ROCm telemetry for SafeO (optional AMD metrics).

Uses PyTorch CUDA/HIP memory APIs when available; rocm-smi for utilisation;
in-memory inference counters updated via record_gpu_inference().
"""
from __future__ import annotations

import logging
import subprocess
from typing import Any, Dict, List

from ..config import AMD_DEVICE, ENABLE_GPU_METRICS

logger = logging.getLogger("safeo.gpu")

_models_loaded: List[str] = []
_total_inferences = 0
_total_inference_ms = 0.0


def register_model(name: str) -> None:
    if name and name not in _models_loaded:
        _models_loaded.append(name)


def record_gpu_inference(inference_ms: float, model_name: str = "unknown") -> None:
    """Call after every GPU-backed inference to update rolling averages."""
    global _total_inferences, _total_inference_ms
    _total_inferences += 1
    _total_inference_ms += max(0.0, float(inference_ms))
    register_model(model_name)


def _rocm_smi_utilisation() -> float:
    """Query GPU utilisation via rocm-smi; return 0 if unavailable."""
    try:
        out = subprocess.run(
            ["rocm-smi", "--showuse"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if out.returncode != 0:
            return 0.0
        for line in out.stdout.splitlines():
            line = line.strip()
            if "GPU use" in line or "GPU Utilization" in line:
                parts = line.replace("%", "").split()
                for p in reversed(parts):
                    try:
                        return min(100.0, float(p))
                    except ValueError:
                        continue
        # Fallback: parse "XX %" patterns
        import re
        m = re.search(r"(\d+(?:\.\d+)?)\s*%", out.stdout)
        if m:
            return min(100.0, float(m.group(1)))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("rocm-smi unavailable: %s", exc)
    return 0.0


def _zero_stats(device_name: str = "cpu") -> Dict[str, Any]:
    avg_ms = (
        round(_total_inference_ms / _total_inferences, 2) if _total_inferences else 0.0
    )
    return {
        "rocm_available": False,
        "device_name": device_name,
        "memory_used_mb": 0.0,
        "memory_total_mb": 0.0,
        "memory_pct": 0.0,
        "gpu_utilisation_pct": 0.0,
        "models_loaded": list(_models_loaded),
        "total_inferences": _total_inferences,
        "avg_inference_ms": avg_ms,
    }


def get_gpu_stats() -> Dict[str, Any]:
    """
    Return AMD GPU snapshot for dashboard polling.

    Returns:
        rocm_available, device_name, memory_used_mb, memory_total_mb,
        memory_pct, gpu_utilisation_pct, models_loaded, total_inferences,
        avg_inference_ms
    """
    avg_ms = (
        round(_total_inference_ms / _total_inferences, 2) if _total_inferences else 0.0
    )
    base = {
        "models_loaded": list(_models_loaded),
        "total_inferences": _total_inferences,
        "avg_inference_ms": avg_ms,
    }

    if not ENABLE_GPU_METRICS:
        return {**_zero_stats(AMD_DEVICE), **base}

    try:
        import torch
    except ImportError:
        return {**_zero_stats(AMD_DEVICE), **base}

    rocm_available = bool(torch.cuda.is_available())
    if not rocm_available:
        return {**_zero_stats("cpu"), **base}

    try:
        idx = torch.cuda.current_device()
        device_name = torch.cuda.get_device_name(idx)
        props = torch.cuda.get_device_properties(idx)
        total_mb = float(props.total_memory) / (1024 * 1024)
        reserved_mb = float(torch.cuda.memory_reserved(idx)) / (1024 * 1024)
        memory_pct = round((reserved_mb / total_mb) * 100.0, 2) if total_mb > 0 else 0.0
        util = _rocm_smi_utilisation()
        if util <= 0.0:
            util = min(100.0, memory_pct)

        return {
            "rocm_available": True,
            "device_name": device_name,
            "memory_used_mb": round(reserved_mb, 2),
            "memory_total_mb": round(total_mb, 2),
            "memory_pct": memory_pct,
            "gpu_utilisation_pct": round(util, 2),
            "models_loaded": list(_models_loaded),
            "total_inferences": _total_inferences,
            "avg_inference_ms": avg_ms,
        }
    except Exception as exc:
        logger.warning("GPU stats error: %s", exc)
        return {**_zero_stats(AMD_DEVICE), **base}

#!/usr/bin/env python3
"""Print AMD GPU / ROCm visibility for SafeO (via PyTorch HIP/CUDA API)."""
from __future__ import annotations

import sys
from pathlib import Path

# Allow importing safeo_backend when run from repo
BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

try:
    import torch
except ImportError:
    print("PyTorch not installed. Run amd_setup/install_rocm.sh first.")
    sys.exit(1)

from safeo_backend.config import AMD_DEVICE  # noqa: E402
from safeo_backend.utils.gpu_monitor import get_gpu_stats  # noqa: E402


def main() -> None:
    print("SafeO AMD GPU check")
    print("-" * 40)
    print(f"SAFEO_AMD_DEVICE (config): {AMD_DEVICE}")
    print(f"torch.cuda.is_available(): {torch.cuda.is_available()}")

    if hasattr(torch.version, "hip") and torch.version.hip:
        print(f"ROCm (torch.version.hip): {torch.version.hip}")
    else:
        print("ROCm (torch.version.hip): not reported (CPU build or no HIP)")

    if torch.cuda.is_available():
        for i in range(torch.cuda.device_count()):
            print(f"GPU {i}: {torch.cuda.get_device_name(i)}")
    else:
        print("No GPU visible to PyTorch — SafeO will use CPU / remote vLLM.")

    stats = get_gpu_stats()
    print("-" * 40)
    print("get_gpu_stats():")
    for k, v in stats.items():
        print(f"  {k}: {v}")

    if stats.get("rocm_available"):
        print("\nOK: SafeO can see an AMD GPU via ROCm/HIP.")
    else:
        print("\nNote: GPU not available; heuristic scoring still works on CPU.")


if __name__ == "__main__":
    main()

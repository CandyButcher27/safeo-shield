#!/usr/bin/env bash
# SafeO — AMD ROCm 6.x + PyTorch (ROCm) + vLLM prerequisites
# Run on Ubuntu 22.04/24.04 with supported AMD GPUs. Review AMD docs for your distro.
set -euo pipefail

ROCM_VERSION="${ROCM_VERSION:-6.2}"
PYTORCH_INDEX="${PYTORCH_INDEX:-https://download.pytorch.org/whl/rocm6.2}"

echo "==> SafeO AMD setup (ROCm ${ROCM_VERSION})"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi

# --- ROCm stack (Ubuntu) — adjust for your OS per AMD install guide ---
if command -v apt-get >/dev/null 2>&1; then
  echo "==> Installing ROCm meta-package (requires sudo)..."
  sudo apt-get update
  sudo apt-get install -y "rocm-dev" "rocm-libs" "rocm-utils" || {
    echo "If apt install fails, follow: https://rocm.docs.amd.com/en/latest/deploy/linux/quick_start.html"
    exit 1
  }
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$(cd "${SCRIPT_DIR}/../backend" && pwd)"
VENV="${BACKEND_DIR}/.venv"

if [[ ! -d "${VENV}" ]]; then
  python3 -m venv "${VENV}"
fi
# shellcheck disable=SC1091
source "${VENV}/bin/activate"

echo "==> Upgrading pip..."
pip install --upgrade pip wheel setuptools

echo "==> Installing PyTorch with ROCm wheel index..."
pip install torch torchvision torchaudio --index-url "${PYTORCH_INDEX}"

echo "==> Installing SafeO ML dependencies..."
pip install transformers accelerate sentencepiece numpy scipy vllm

echo "==> Installing SafeO API dependencies..."
pip install -r "${BACKEND_DIR}/requirements.txt"

echo "==> Verifying GPU visibility..."
python3 "${SCRIPT_DIR}/check_gpu.py"

echo "Done. Activate venv: source ${VENV}/bin/activate"

#!/usr/bin/env bash
# Start local vLLM OpenAI-compatible server for SafeO tier-3 LLM (Mistral-7B).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$(cd "${SCRIPT_DIR}/../backend" && pwd)"
VENV="${BACKEND_DIR}/.venv"
MODEL="${SAFEO_LLM_MODEL_NAME:-mistralai/Mistral-7B-Instruct-v0.2}"
PORT="${SAFEO_VLLM_PORT:-8000}"

if [[ -d "${VENV}" ]]; then
  # shellcheck disable=SC1091
  source "${VENV}/bin/activate"
fi

echo "Starting vLLM on port ${PORT} (model=${MODEL})..."
exec python -m vllm.entrypoints.openai.api_server \
  --model "${MODEL}" \
  --device rocm \
  --port "${PORT}"

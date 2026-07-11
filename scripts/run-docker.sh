#!/usr/bin/env bash
# Run the full SafeO stack via Docker (stops conflicting local dev servers on 5174/8001).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "Stopping stale local dev servers on ports 5174 and 8001 (if any)..."
for port in 5174 8001; do
  while read -r pid comm; do
    case "$comm" in
      node|python*|Python*)
        echo "  Killing $comm (PID $pid) on :$port"
        kill "$pid" 2>/dev/null || true
        ;;
    esac
  done < <(lsof -ti ":$port" 2>/dev/null | xargs -I{} ps -p {} -o pid=,comm= 2>/dev/null || true)
done

echo "Building and starting Docker Compose..."
docker compose up --build -d

echo ""
echo "SafeO is running:"
echo "  Frontend:  http://localhost:5174/"
echo "  Logs:      http://localhost:5174/logs"
echo "  Backend:   http://localhost:8001/"
echo "  API docs:  http://localhost:8001/docs"
echo ""
echo "Hard-refresh the browser (Cmd+Shift+R) if UI looks stale."

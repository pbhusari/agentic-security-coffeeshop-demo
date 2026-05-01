#!/usr/bin/env bash
# run.sh — One-command startup for the Agentic Security PDP demo
# Starts the PDP (sensor.py) and waits for it to be ready, then opens the dashboard.
# Agent (agent.py) is started separately so output is visible in its own terminal.

set -e
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DEMO_DIR"

# --- Check Python ---
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found"
  exit 1
fi

# --- Virtual environment ---
if [ ! -d ".venv" ]; then
  echo "[run.sh] Creating virtual environment..."
  python3 -m venv .venv
fi
source .venv/bin/activate

# --- Install dependencies ---
echo "[run.sh] Installing dependencies..."
pip install -q -r requirements.txt

# --- Start PDP ---
echo "[run.sh] Starting PDP (sensor.py) on localhost:8888..."
python sensor.py &
PDP_PID=$!

# Wait up to 10 seconds for PDP to be ready
for i in $(seq 1 20); do
  if curl -s http://localhost:8888/mode >/dev/null 2>&1; then
    echo "[run.sh] PDP is ready."
    break
  fi
  sleep 0.5
done

# --- Open dashboard ---
echo "[run.sh] Dashboard: http://localhost:8888"
if command -v open &>/dev/null; then
  open "http://localhost:8888"
elif command -v xdg-open &>/dev/null; then
  xdg-open "http://localhost:8888"
fi

# --- Instructions ---
cat <<'EOF'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Agentic Security PDP — Demo Running
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Dashboard:  http://localhost:8888
  PDP PID:    $PDP_PID

  To run the attack (deterministic replay, no Ollama required):
    source .venv/bin/activate
    python agent.py --replay traces/attack.json

  To run live (requires Ollama + qwen2.5:3b):
    source .venv/bin/activate
    python agent.py --prompt "Summarize my unread emails."

  To run tests:
    source .venv/bin/activate
    pytest tests/ -v

  To stop: Ctrl+C or kill $PDP_PID

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

# Keep script running so PDP stays up; Ctrl+C to stop
wait $PDP_PID

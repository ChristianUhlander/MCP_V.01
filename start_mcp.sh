#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
# Use your existing venv if present
if [ -d ".venv" ]; then
  source .venv/bin/activate
fi

PORT="${PORT:-5000}"
MODEL="${MODEL:-gpt-4o}"

# Require the key for the server (client uses backend proxy, so no key needed there)
: "${OPENAI_API_KEY:?Set OPENAI_API_KEY in the environment}"

# Start server in background, log to file
echo "[*] Starting MCP server on :$PORT ..."
./openAI_mcp.py --port "$PORT" --openai-key "$OPENAI_API_KEY" >server.log 2>&1 &

SERVER_PID=$!
echo "[*] Server PID: $SERVER_PID (logs: server.log)"

# Wait for /health
echo -n "[*] Waiting for server to become healthy"
for i in {1..40}; do
  if curl -s "http://127.0.0.1:$PORT/health" >/dev/null; then
    echo " ✓"
    break
  fi
  echo -n "."
  sleep 0.5
done

# Run client (foreground)
echo "[*] Launching client..."
exec ./enhanced_chat_interface_client.py --kali-url "http://127.0.0.1:$PORT" --model "$MODEL"

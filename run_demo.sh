#!/bin/bash

echo "Starting AgentGuard-X Sandbox Service..."
cd ~/agentguardx/sandbox

# Start the sandbox API in background
python3 -m uvicorn sandbox_api:app --host 0.0.0.0 --port 8001 &
API_PID=$!

# Wait for it to be ready
echo "Waiting for service to be ready..."
for i in $(seq 1 15); do
    if curl -s http://localhost:8001/sandbox/health > /dev/null 2>&1; then
        echo "Service is up!"
        break
    fi
    sleep 1
done

# Run the demo
python3 ~/agentguardx/sandbox/agent_runtime.py

# Cleanup — kill the background service when demo finishes
kill $API_PID 2>/dev/null
echo "Service stopped."

"""
Phase 5 — Pool exhaustion test.
Floods the pool with more requests than pool_size.
Proves the system handles it gracefully instead of crashing.
"""
import requests
import threading
import time

API = "http://localhost:8001"
results = []

def send_request(i):
    payload = {
        "agent_id": f"flood-agent-{i:03d}",
        "agent_type": "ResearchAgent",
        "command": f"echo flood_test_{i} && sleep 0.5",
        "triage_risk_score": 0.40
    }
    t = time.time()
    try:
        r = requests.post(f"{API}/sandbox/evaluate", json=payload, timeout=30)
        elapsed = (time.time() - t) * 1000
        results.append({"id": i, "status": r.status_code,
                        "verdict": r.json().get("verdict"), "ms": round(elapsed)})
    except Exception as e:
        results.append({"id": i, "status": "error", "error": str(e)})

print("Flooding pool with 8 simultaneous requests (pool size = 3)...")
print("Expected: all complete, no crashes, some wait for replenishment\n")

threads = [threading.Thread(target=send_request, args=(i,)) for i in range(8)]
t_start = time.time()
for t in threads: t.start()
for t in threads: t.join()
total = (time.time() - t_start) * 1000

print(f"Results ({len(results)}/8 completed in {total:.0f}ms total):")
for r in sorted(results, key=lambda x: x["id"]):
    print(f"  Agent {r['id']:03d}: {r.get('verdict','ERROR'):6s}  {r.get('ms','?')}ms")

successes = sum(1 for r in results if r.get("status") == 200)
print(f"\n{'='*45}")
print(f"Success rate: {successes}/8")
print(f"System crashed: {'NO ✓' if successes > 0 else 'YES ✗'}")
print(f"Graceful degradation: {'✓ PASS' if successes >= 6 else '✗ FAIL'}")

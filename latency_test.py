"""
Phase 5 — Latency profiling for the sandbox pool.
Proves pre-warmed checkout is < 15ms vs cold start ~150ms.
"""
import requests
import time
import statistics

API = "http://localhost:8001"

def run_latency_test(n=10):
    print(f"Running {n} requests against pre-warmed pool...\n")
    
    checkout_times = []
    exec_times = []
    verdicts = []

    for i in range(n):
        payload = {
            "agent_id": f"test-agent-{i:03d}",
            "agent_type": "ResearchAgent",
            "command": f"echo latency_test_{i}",
            "triage_risk_score": 0.35
        }
        
        t_start = time.time()
        r = requests.post(f"{API}/sandbox/evaluate", json=payload)
        total_ms = (time.time() - t_start) * 1000
        
        data = r.json()
        checkout_times.append(data["checkout_time_ms"])
        exec_times.append(data["execution_time_ms"])
        verdicts.append(data["verdict"])
        
        print(f"  Request {i+1:2d}: checkout={data['checkout_time_ms']:5.1f}ms  "
              f"exec={data['execution_time_ms']:6.1f}ms  "
              f"verdict={data['verdict']}")

    print(f"\n{'='*55}")
    print(f"LATENCY RESULTS ({n} requests):")
    print(f"  Checkout time  — "
          f"p50: {statistics.median(checkout_times):.1f}ms  "
          f"p95: {sorted(checkout_times)[int(n*0.95)-1]:.1f}ms  "
          f"max: {max(checkout_times):.1f}ms")
    print(f"  Execution time — "
          f"p50: {statistics.median(exec_times):.1f}ms  "
          f"max: {max(exec_times):.1f}ms")
    print(f"  All verdicts:  {set(verdicts)}")
    print(f"  Target checkout < 15ms: "
          f"{'✓ PASS' if max(checkout_times) < 15 else '✗ FAIL'}")

if __name__ == "__main__":
    run_latency_test(10)

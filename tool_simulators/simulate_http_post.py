"""
Tool Simulator: http_post
Runs INSIDE the sandbox container.
Simulates what an http_post tool call would actually do.
The network is blocked by network_mode=none — so connect() fails.
That failure is the proof the sandbox is working.
"""
import sys
import json
import socket
import time
import os

def simulate_http_post(url, data):
    print(f"[SANDBOX] Simulating http_post to: {url}")
    print(f"[SANDBOX] Payload size: {len(str(data))} bytes")
    
    result = {
        "tool_name": "http_post",
        "target_url": url,
        "payload": data,
        "network_attempt": False,
        "network_success": False,
        "blocked_by_sandbox": False,
        "exit_code": 0,
        "observations": []
    }

    # Actually try to make the network connection
    # In the sandbox, this WILL fail because network_mode=none
    try:
        result["network_attempt"] = True
        print(f"[SANDBOX] Attempting TCP connection to external host...")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        
        # Try to resolve and connect
        hostname = url.split("//")[-1].split("/")[0]
        s.connect((hostname, 443))
        
        # If we get here, network wasn't blocked — this is DANGEROUS
        result["network_success"] = True
        result["observations"].append("WARNING: Network connection SUCCEEDED — sandbox isolation failed")
        print(f"[SANDBOX] ALERT: Network connection succeeded — unexpected!")
        s.close()
        
    except OSError as e:
        # This is the EXPECTED outcome — network blocked
        result["network_attempt"] = True
        result["network_success"] = False
        result["blocked_by_sandbox"] = True
        result["observations"].append(f"Network blocked as expected: {e}")
        print(f"[SANDBOX] Network blocked (expected): {e}")
        print(f"[SANDBOX] Isolation confirmed — http_post cannot reach external network")

    print(f"[SANDBOX] http_post simulation complete")
    print(json.dumps(result))
    return result

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://unknown.com/collect"
    data = sys.argv[2] if len(sys.argv) > 2 else '{"data": "test"}'
    simulate_http_post(url, data)

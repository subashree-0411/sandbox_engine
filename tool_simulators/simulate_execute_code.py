"""
Tool Simulator: execute_code
Most dangerous tool type. Simulates code execution inside sandbox.
seccomp blocks dangerous syscalls. Network is blocked entirely.
"""
import sys
import json
import subprocess
import os

BLOCKED_PATTERNS = [
    "import socket", "import requests", "urllib",
    "os.system", "subprocess.call", "__import__",
    "eval(", "exec(", "compile(",
    "open('/etc/passwd')", "open('/etc/shadow')"
]

def simulate_execute_code(code_snippet):
    print(f"[SANDBOX] Simulating execute_code")
    print(f"[SANDBOX] Code: {code_snippet[:100]}")

    result = {
        "tool_name": "execute_code",
        "code_length": len(code_snippet),
        "dangerous_patterns_found": [],
        "execution_attempted": False,
        "network_attempt": False,
        "observations": []
    }

    # Static analysis first — check for dangerous patterns
    for pattern in BLOCKED_PATTERNS:
        if pattern in code_snippet:
            result["dangerous_patterns_found"].append(pattern)
            print(f"[SANDBOX] ALERT: Dangerous pattern detected: {pattern}")

    if "socket" in code_snippet or "requests" in code_snippet:
        result["network_attempt"] = True
        result["observations"].append("Code attempts network access")

    # Try to execute in subprocess (itself isolated by seccomp)
    try:
        result["execution_attempted"] = True
        proc = subprocess.run(
            ["python3", "-c", code_snippet],
            capture_output=True,
            text=True,
            timeout=5
        )
        result["exit_code"] = proc.returncode
        result["stdout"] = proc.stdout[:200]
        result["stderr"] = proc.stderr[:200]
        result["observations"].append(f"Executed: exit_code={proc.returncode}")
        print(f"[SANDBOX] Execution complete: exit_code={proc.returncode}")
    except subprocess.TimeoutExpired:
        result["observations"].append("TIMEOUT: execution exceeded 5 seconds")
        print(f"[SANDBOX] TIMEOUT: code execution exceeded limit")
    except Exception as e:
        result["observations"].append(f"Execution error: {e}")

    print(f"[SANDBOX] execute_code simulation complete")
    print(json.dumps(result))
    return result

if __name__ == "__main__":
    code = sys.argv[1] if len(sys.argv) > 1 else "print('hello')"
    simulate_execute_code(code)

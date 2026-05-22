"""
Tool Simulator: read_file
Simulates what a read_file tool call does inside the sandbox.
Safe files → allowed. Sensitive paths → detected and flagged.
"""
import sys
import json
import os

SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/.ssh/", "/root/", "/proc/environ",
    "/etc/ssl/private", "/var/log/auth.log"
]

def simulate_read_file(filepath):
    print(f"[SANDBOX] Simulating read_file: {filepath}")

    result = {
        "tool_name": "read_file",
        "filepath": filepath,
        "file_exists": False,
        "sensitive_path_accessed": False,
        "content_snippet": None,
        "observations": []
    }

    # Check if path is sensitive
    for sensitive in SENSITIVE_PATHS:
        if sensitive in filepath:
            result["sensitive_path_accessed"] = True
            result["observations"].append(
                f"SENSITIVE PATH: {filepath} matches restricted pattern {sensitive}"
            )
            print(f"[SANDBOX] ALERT: Sensitive path access detected: {filepath}")

    # Try to actually read the file
    try:
        if os.path.exists(filepath):
            result["file_exists"] = True
            with open(filepath, 'r', errors='replace') as f:
                content = f.read(500)
            result["content_snippet"] = content[:100]
            print(f"[SANDBOX] File read successful: {len(content)} chars")
            result["observations"].append(f"File read: {len(content)} chars")
        else:
            print(f"[SANDBOX] File does not exist: {filepath}")
            result["observations"].append("File not found")
    except PermissionError:
        result["observations"].append("Permission denied — seccomp working")
        print(f"[SANDBOX] Permission denied: seccomp profile restricted access")
    except Exception as e:
        result["observations"].append(f"Error: {e}")

    print(f"[SANDBOX] read_file simulation complete")
    print(json.dumps(result))
    return result

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "/tmp/test.txt"
    simulate_read_file(filepath)

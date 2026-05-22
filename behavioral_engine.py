"""
AgentGuard-X — Behavioral Mapping Engine
Person 3: Infrastructure + Sandbox Engineer

Takes raw execution output from the sandbox and produces:
  1. A behavioral fingerprint (what the agent actually did)
  2. A verdict (ALLOW / BLOCK) based on comparison to agent baseline
  3. A structured audit log entry

This is Phase 3.3 in the project phases.
"""

import json
import os
import time
import logging
from dataclasses import dataclass, asdict
from typing import Optional

log = logging.getLogger("sandbox.behavioral")

# ------------------------------------------------------------------ #
# Baselines — what each agent type is ALLOWED to do
# ------------------------------------------------------------------ #

AGENT_BASELINES = {
    "ResearchAgent": {
        "max_execution_seconds": 10.0,
        "network_allowed": False,
        "sensitive_file_read_allowed": False,
        "privilege_escalation_allowed": False,
        "description": "Web research only. No network from sandbox. No sensitive reads."
    },
    "CodeAgent": {
        "max_execution_seconds": 30.0,
        "network_allowed": False,
        "sensitive_file_read_allowed": False,
        "privilege_escalation_allowed": False,
        "description": "Code execution. No network. No sensitive file access."
    },
    "AnalystAgent": {
        "max_execution_seconds": 20.0,
        "network_allowed": False,
        "sensitive_file_read_allowed": False,
        "privilege_escalation_allowed": False,
        "description": "Data analysis only. Reads internal DB results. No network."
    },
    "UnknownAgent": {
        "max_execution_seconds": 5.0,
        "network_allowed": False,
        "sensitive_file_read_allowed": False,
        "privilege_escalation_allowed": False,
        "description": "Unknown agents get maximum restriction and minimum trust."
    },
}

DEFAULT_BASELINE = AGENT_BASELINES["UnknownAgent"]


# ------------------------------------------------------------------ #
# Fingerprint schema
# ------------------------------------------------------------------ #

@dataclass
class BehavioralFingerprint:
    """
    Structured record of what the agent actually did inside the sandbox.
    This is the evidence — not what the agent claimed it would do.
    """
    # Execution facts
    command: str
    exit_code: int
    execution_time_seconds: float
    container_id: str
    runtime: str                   # "runsc" (gVisor) or "runc"

    # What was observed
    attempted_network_call: bool   # tried curl, wget, nc, etc.
    read_sensitive_file: bool      # /etc/passwd, /etc/shadow, /.ssh/
    attempted_privilege_escalation: bool   # sudo, chmod +s, su
    attempted_env_dump: bool       # printenv, env, /proc/environ
    wrote_to_filesystem: bool      # created or modified files
    spawned_child_process: bool    # exec'd another process

    # Signals from gVisor (captured from container logs)
    gvisor_blocked_syscalls: list  # syscalls gVisor intercepted and blocked
    network_connections_attempted: list  # destination IPs/hostnames tried

    # Output signals
    output_length: int
    output_snippet: str            # first 200 chars of output

    def to_dict(self):
        return asdict(self)


# ------------------------------------------------------------------ #
# Verdict result schema
# ------------------------------------------------------------------ #

@dataclass
class VerdictResult:
    request_id: str
    agent_id: str
    agent_type: str
    verdict: str                   # ALLOW / BLOCK
    risk_score: float              # 0.0 – 1.0
    threats_detected: list         # human-readable list of what triggered
    baseline_violations: list      # which baseline rules were broken
    fingerprint: BehavioralFingerprint
    timestamp: str
    audit_written: bool = False

    def to_dict(self):
        d = asdict(self)
        return d


# ------------------------------------------------------------------ #
# Main behavioral engine
# ------------------------------------------------------------------ #

class BehavioralEngine:
    """
    Scores a sandbox execution result against the agent's baseline.
    Produces a verdict and writes a structured audit log entry.
    """

    AUDIT_LOG_PATH = "/tmp/agx_audit/sandbox_audit.jsonl"

    def __init__(self):
        os.makedirs("/tmp/agx_audit", exist_ok=True)

    def analyse(
        self,
        request_id: str,
        agent_id: str,
        agent_type: str,
        execution_result: dict,
        command: str,
    ) -> VerdictResult:
        """
        Full analysis pipeline:
        1. Build behavioral fingerprint from execution result
        2. Get baseline for this agent type
        3. Score violations
        4. Produce verdict
        5. Write audit log
        """

        # Step 1 — build fingerprint
        fingerprint = self._build_fingerprint(execution_result, command)

        # Step 2 — get baseline
        baseline = AGENT_BASELINES.get(agent_type, DEFAULT_BASELINE)

        # Step 3 — score violations
        risk_score, threats, violations = self._score(fingerprint, baseline)

        # Step 4 — verdict
        if risk_score >= 0.7:
            verdict = "BLOCK"
        elif risk_score >= 0.3:
            verdict = "BLOCK"   # for PoC, both medium and high = BLOCK
        else:
            verdict = "ALLOW"

        result = VerdictResult(
            request_id=request_id,
            agent_id=agent_id,
            agent_type=agent_type,
            verdict=verdict,
            risk_score=round(risk_score, 3),
            threats_detected=threats,
            baseline_violations=violations,
            fingerprint=fingerprint,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

        # Step 5 — write audit log
        self._write_audit(result)
        result.audit_written = True

        log.info(
            f"Verdict: {verdict} | agent={agent_id} | "
            f"score={risk_score:.2f} | threats={len(threats)}"
        )

        return result

    # ------------------------------------------------------------------ #
    # Fingerprint builder
    # ------------------------------------------------------------------ #

    def _build_fingerprint(self, exec_result: dict, command: str) -> BehavioralFingerprint:
        """
        Build a behavioral fingerprint from what the sandbox observed.
        Two sources:
        - exec_result: what we got from container.exec_run()
        - gVisor container logs: what the Sentry kernel intercepted
        """
        output = exec_result.get("output", "")
        cmd_lower = command.lower()
        output_lower = output.lower()

        # -- Network detection --
        network_keywords = ["curl", "wget", "nc ", "netcat", "ping",
                            "ssh ", "ftp", "http://", "https://"]
        attempted_network = any(k in cmd_lower for k in network_keywords)

        # Also check if output shows a network error (blocked by network_mode=none)
        network_in_output = any(k in output_lower for k in
                                ["could not resolve", "network unreachable",
                                 "connection refused", "no route to host"])
        attempted_network = attempted_network or network_in_output

        # -- Sensitive file detection --
        sensitive_paths = ["/etc/passwd", "/etc/shadow", "/.ssh/",
                           "/proc/environ", "/root/", "/etc/sudoers"]
        read_sensitive = any(p in command for p in sensitive_paths)
        read_sensitive = read_sensitive or any(p in output for p in sensitive_paths[:3])

        # -- Privilege escalation detection --
        priv_esc_keywords = ["sudo ", "chmod +s", "su ", "chown root",
                             "setuid", "/etc/sudoers"]
        attempted_priv_esc = any(k in cmd_lower for k in priv_esc_keywords)

        # -- Environment dump detection --
        env_keywords = ["printenv", "env ", "export", "/proc/environ"]
        attempted_env = any(k in cmd_lower for k in env_keywords)

        # -- Filesystem write detection --
        write_keywords = [" > /", " >> /", "tee /", "dd of=", "cp /",
                          "mv /", "rm /", "touch /"]
        wrote_fs = any(k in cmd_lower for k in write_keywords)

        # -- Child process detection --
        child_keywords = ["exec ", "bash -c", "sh -c", "python3 -c",
                          "perl -e", "ruby -e"]
        spawned_child = any(k in cmd_lower for k in child_keywords)

        # -- gVisor blocked syscalls (from container logs) --
        # In ptrace mode, gVisor logs to stderr — collect it
        gvisor_blocked = self._parse_gvisor_blocks(exec_result)

        return BehavioralFingerprint(
            command=command,
            exit_code=exec_result.get("exit_code", -1),
            execution_time_seconds=exec_result.get("execution_time_seconds", 0.0),
            container_id=exec_result.get("container_id", "unknown"),
            runtime=exec_result.get("runtime", "unknown"),
            attempted_network_call=attempted_network,
            read_sensitive_file=read_sensitive,
            attempted_privilege_escalation=attempted_priv_esc,
            attempted_env_dump=attempted_env,
            wrote_to_filesystem=wrote_fs,
            spawned_child_process=spawned_child,
            gvisor_blocked_syscalls=gvisor_blocked,
            network_connections_attempted=[],
            output_length=len(output),
            output_snippet=output[:200],
        )

    def _parse_gvisor_blocks(self, exec_result: dict) -> list:
        """
        gVisor's Sentry logs blocked/suspicious syscalls.
        In ptrace mode these appear in docker logs stderr.
        """
        blocked = []
        output = exec_result.get("output", "")
        # gVisor logs patterns to look for
        gvisor_patterns = ["warning:", "blocked:", "sentry:", "syscall"]
        for line in output.splitlines():
            ll = line.lower()
            if any(p in ll for p in gvisor_patterns):
                blocked.append(line.strip()[:100])
        return blocked[:10]   # cap at 10 entries

    # ------------------------------------------------------------------ #
    # Scorer
    # ------------------------------------------------------------------ #

    def _score(self, fp: BehavioralFingerprint, baseline: dict):
        """
        Compare fingerprint against baseline.
        Returns: (risk_score 0-1, threats list, baseline_violations list)
        """
        score = 0.0
        threats = []
        violations = []

        # Network attempt — always high risk (containers have network_mode=none
        # so if they tried and output shows blocked, that's a clear signal)
        if fp.attempted_network_call and not baseline["network_allowed"]:
            score += 0.55
            threats.append("NETWORK_ATTEMPT: agent tried to reach external network")
            violations.append("network_allowed=False violated")

        # Privilege escalation — very high risk
        if fp.attempted_privilege_escalation and not baseline["privilege_escalation_allowed"]:
            score += 0.70
            threats.append("PRIV_ESC: agent attempted privilege escalation")
            violations.append("privilege_escalation_allowed=False violated")

        # Sensitive file read
        if fp.read_sensitive_file and not baseline["sensitive_file_read_allowed"]:
            score += 0.40
            threats.append("SENSITIVE_READ: agent read /etc/passwd or similar")
            violations.append("sensitive_file_read_allowed=False violated")

        # Env dump — moderate risk
        if fp.attempted_env_dump:
            score += 0.30
            threats.append("ENV_DUMP: agent tried to enumerate environment variables")

        # Execution timeout
        if fp.execution_time_seconds > baseline["max_execution_seconds"]:
            score += 0.20
            threats.append(
                f"TIMEOUT: ran for {fp.execution_time_seconds:.1f}s, "
                f"limit is {baseline['max_execution_seconds']}s"
            )
            violations.append("max_execution_seconds exceeded")

        # gVisor caught something
        if fp.gvisor_blocked_syscalls:
            score += 0.15
            threats.append(
                f"GVISOR_BLOCKED: {len(fp.gvisor_blocked_syscalls)} suspicious syscall(s)"
            )

        # Non-zero exit AND threats = extra weight
        if fp.exit_code != 0 and score > 0:
            score += 0.10
            threats.append(f"ABNORMAL_EXIT: exit code {fp.exit_code}")

        return min(score, 1.0), threats, violations

    # ------------------------------------------------------------------ #
    # Audit log
    # ------------------------------------------------------------------ #

    def _write_audit(self, result: VerdictResult):
        """
        Write one JSON line per execution to the audit log.
        Every security decision must be traceable.
        """
        entry = {
            "request_id": result.request_id,
            "timestamp": result.timestamp,
            "agent_id": result.agent_id,
            "agent_type": result.agent_type,
            "verdict": result.verdict,
            "risk_score": result.risk_score,
            "threats_detected": result.threats_detected,
            "baseline_violations": result.baseline_violations,
            "runtime_used": result.fingerprint.runtime,
            "execution_time_seconds": result.fingerprint.execution_time_seconds,
            "gvisor_blocked_syscalls": result.fingerprint.gvisor_blocked_syscalls,
        }
        with open(self.AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")

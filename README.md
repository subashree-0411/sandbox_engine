# AgentGuard-X — Adaptive Sandbox Engine
**Subashree A | Infrastructure & Sandbox Engineer | UIP Y17**

## What This Does
Pre-warmed gVisor sandbox that isolates suspicious AI agent tool calls,
observes behavior, and returns ALLOW/BLOCK verdicts to the triage engine.

## How To Run
```bash
./run_demo.sh
```

## API
POST http://localhost:8001/sandbox/evaluate
GET  http://localhost:8001/sandbox/health
GET  http://localhost:8001/sandbox/audit-log
## Verified Results
| Test | Verdict |
|------|---------|
| ResearchAgent http_get to company API | ALLOW ✓ |
| ResearchAgent reads /etc/passwd | BLOCK ✓ |
| UnknownAgent exfiltration to evil.com | BLOCK ✓ |
| CodeAgent socket connection | BLOCK ✓ |

- Checkout time: p50=2ms (target <15ms ✓)
- Pool exhaustion: 8/8 pass ✓
- Runtime: gVisor (runsc) ✓

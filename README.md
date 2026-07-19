# agent-security-research

Defensive research notes on **AI agents**, **MCP tool servers**, and **agent skill** packages.

## Scope

| Area | What we look at |
|------|-----------------|
| MCP / agent tools | shell, URL fetch, filesystem, DB sinks; authn of tool callers |
| Agent skills | `SKILL.md` + scripts; install-time and instruction hazards |
| Agent-facing web/API | injection, path traversal, SSRF-class fetch |

## Tools

```bash
python tools/skills-supply-chain/scan_skill.py path/to/skill-or-repo
```

Static heuristics for skill packages (not a full product scanner).

## Findings

See [`findings/`](findings/). Public issue/PR links are the verification trail.

## Principles

1. Public source for third-party targets.  
2. Prefer a short report + fix PR.  
3. No unauthorized production scanning.  

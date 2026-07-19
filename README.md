# Security research notes

Defensive code review: find issues, write maintainer-safe fixes, disclose cleanly.

## Tools

```bash
python tools/skills-supply-chain/scan_skill.py path/to/skill-or-repo
```

Static checks for Agent Skill packages (`SKILL.md` + scripts): shell hazards, secret-path hints, prompt-injection language. Dual-use content is labeled info, not a CVE claim.

## Findings index

See [`findings/`](findings/). Each note maps CWE → root cause → fix PR or external report when available.

## Principles

1. Public source for third-party targets.
2. Prefer a patch PR over a long write-up.
3. No production scanning without authorization.

# skills-supply-chain

Standalone static scanner for Agent Skill packages (`SKILL.md` + companion scripts).

Not derived from any third-party product scanner. Regex / heuristics only.

## Catches

- Pipe-to-shell and destructive shell patterns
- `shell=True` / `os.system` / `child_process.exec`
- Secret-path / env credential hints
- Prompt-injection style instruction overrides
- Dual-use labels (info only — not a CVE claim)

## Usage

```bash
python scan_skill.py path/to/skill-dir
python scan_skill.py --json path/to/SKILL.md
```

## Note

Runtime CVEs usually live in servers and apps, not markdown playbooks. Escalate only when scripts implement a real sink.

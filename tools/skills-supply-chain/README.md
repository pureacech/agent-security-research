# skills-supply-chain

Static scanner for **Agent Skills** packages (`SKILL.md` + scripts).

## What it catches

- Pipe-to-shell / destructive shell patterns
- `shell=True` / `os.system` / `child_process.exec`
- Secret path / env credential references
- Prompt-injection style instruction overrides
- Dual-use content labels (pentest/bypass/C2) as **info**, not CVE claims

## What it does **not** do

- Assign CVEs to “this skill teaches Android pentesting”
- Replace runtime audit of MCP servers / web apps (Track A)

## Usage

```bash
python scan_skill.py ../../vendor/DragonJAR-Android-Pentesting-Skill
python scan_skill.py --json ../../vendor/skills-cli
```

## CVE path reminder

Runtime CVEs usually live in **executable servers and apps**, not markdown playbooks. Use this tool to triage the skills ecosystem; escalate only when scripts implement a real vulnerable sink.

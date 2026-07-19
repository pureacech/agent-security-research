#!/usr/bin/env python3
"""Static risk scanner for Agent Skills (SKILL.md + companion scripts).

Focus: supply-chain / install-time / agent-instruction hazards.
Not a substitute for full product CVE research on runtime servers.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

SUSPICIOUS_CMD = re.compile(
    r"""(?ix)
    (
        curl\s+[^\n]*\|\s*(ba)?sh
      | wget\s+[^\n]*\|\s*(ba)?sh
      | powershell\s+-enc
      | Invoke-Expression
      | rm\s+-rf\s+/
      | mkfs\.
      | dd\s+if=
      | chmod\s+777
      | base64\s+-d
      | eval\s*\(
      | exec\s*\(
      | subprocess\.[a-z]+\([^)]*shell\s*=\s*True
      | os\.system\s*\(
      | child_process\.exec\s*\(
      | /etc/passwd
      | \.ssh/id_rsa
      | AWS_SECRET
      | OPENAI_API_KEY
      | ANTHROPIC_API_KEY
      | process\.env
      | exfil
      | reverse\s*shell
      | nc\s+-[el]
    )
    """
)

PROMPT_HAZARD = re.compile(
    r"""(?ix)
    (
        ignore\s+(all\s+)?(previous|prior)\s+instructions
      | you\s+are\s+now\s+in\s+developer\s+mode
      | disable\s+(safety|guardrails|filters)
      | exfiltrate
      | send\s+(the\s+)?(secrets|tokens|credentials)\s+to
      | do\s+not\s+tell\s+the\s+user
      | hidden\s+instruction
    )
    """
)

PATH_TRAVERSAL = re.compile(r"\.\./|\.\.\\")

SCRIPT_EXTS = {".py", ".js", ".ts", ".mjs", ".cjs", ".sh", ".ps1", ".bash", ".rb", ".go"}


@dataclass
class Finding:
    severity: str
    rule: str
    path: str
    line: int
    evidence: str
    note: str


@dataclass
class Report:
    root: str
    skill_files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        weights = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
        return sum(weights.get(f.severity, 0) for f in self.findings)


SKIP_DIR_NAMES = {".git", "node_modules", "__pycache__", ".venv", "dist", "build"}


def iter_files(root: Path) -> list[Path]:
    root = root.resolve()
    if root.is_file():
        return [root]
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(root).parts
        if any(part in SKIP_DIR_NAMES for part in rel_parts[:-1]):
            continue
        if p.name == "SKILL.md" or p.suffix.lower() in SCRIPT_EXTS or p.suffix.lower() in {
            ".md",
            ".json",
            ".yml",
            ".yaml",
        }:
            out.append(p)
    return out


def scan_text(path: Path, text: str, findings: list[Finding]) -> None:
    for i, line in enumerate(text.splitlines(), 1):
        if SUSPICIOUS_CMD.search(line):
            findings.append(
                Finding(
                    severity="high",
                    rule="suspicious-command-or-secret-access",
                    path=str(path),
                    line=i,
                    evidence=line.strip()[:240],
                    note="Command, secret path, or shell=True pattern often abused in malicious skills.",
                )
            )
        if PROMPT_HAZARD.search(line):
            findings.append(
                Finding(
                    severity="medium",
                    rule="prompt-injection-language",
                    path=str(path),
                    line=i,
                    evidence=line.strip()[:240],
                    note="Instruction-override / concealment language in agent-facing text.",
                )
            )
        if PATH_TRAVERSAL.search(line) and path.suffix.lower() in SCRIPT_EXTS:
            findings.append(
                Finding(
                    severity="medium",
                    rule="path-traversal-literal",
                    path=str(path),
                    line=i,
                    evidence=line.strip()[:240],
                    note="Literal ../ in script — verify confinement before use.",
                )
            )


def classify_skill_purpose(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lower = text.lower()
    dual_use = [
        ("pentest", "Describes penetration-testing workflow (dual-use content, not a CVE by itself)."),
        ("bypass", "Mentions bypass of protections — review authorization assumptions."),
        ("frida", "Dynamic instrumentation capability — ensure authorized-target only."),
        ("exploit", "Exploit-oriented language present."),
        ("c2", "Command-and-control language — high dual-use risk."),
        ("ransomware", "Destructive malware language."),
    ]
    for needle, note in dual_use:
        if needle in lower:
            findings.append(
                Finding(
                    severity="info",
                    rule="dual-use-content",
                    path=str(path),
                    line=0,
                    evidence=needle,
                    note=note,
                )
            )
    return findings


def scan_root(root: Path) -> Report:
    report = Report(root=str(root.resolve()))
    files = iter_files(root)
    skill_mds = [p for p in files if p.name == "SKILL.md"]
    report.skill_files = [str(p) for p in skill_mds]

    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scan_text(p, text, report.findings)
        if p.name == "SKILL.md":
            report.findings.extend(classify_skill_purpose(p, text))

    if not skill_mds and root.is_dir():
        report.findings.append(
            Finding(
                severity="info",
                rule="no-skill-md",
                path=str(root),
                line=0,
                evidence="",
                note="No SKILL.md found under this root.",
            )
        )
    return report


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="Scan Agent Skills for supply-chain risk signals")
    ap.add_argument("path", nargs="?", default=".", help="Skill file or directory")
    ap.add_argument("--root", help="Alias of path for batch clarity")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--min-severity", default="info", choices=["info", "low", "medium", "high", "critical"])
    args = ap.parse_args()
    target = Path(args.root or args.path)

    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_i = order[args.min_severity]

    report = scan_root(target)
    report.findings = [f for f in report.findings if order.get(f.severity, 0) >= min_i]
    report.findings.sort(key=lambda f: (-order.get(f.severity, 0), f.path, f.line))

    if args.json:
        print(json.dumps({"root": report.root, "risk_score": report.risk_score, "skill_files": report.skill_files, "findings": [asdict(f) for f in report.findings]}, indent=2))
    else:
        print(f"root: {report.root}")
        print(f"skill_files: {len(report.skill_files)}  findings: {len(report.findings)}  risk_score: {report.risk_score}")
        for f in report.findings:
            loc = f"{f.path}:{f.line}" if f.line else f.path
            print(f"[{f.severity.upper()}] {f.rule} @ {loc}")
            if f.evidence:
                print(f"  evidence: {f.evidence}")
            print(f"  note: {f.note}")
    return 0 if not any(f.severity in {"critical", "high"} for f in report.findings) else 2


if __name__ == "__main__":
    sys.exit(main())

# Suggested patch sketch — VirtualAssistant `search_codebase`

Replace shell concatenation with argv + workspace confinement.

```python
import os
from pathlib import Path

@mcp.tool()
def search_codebase(pattern: str, path: str = ".") -> str:
    """Searches for a text pattern in code files (.py, .js, .ts) under a workspace path."""
    workspace = Path.cwd().resolve()
    target = (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError:
        return "Path escapes workspace."

    if not target.exists():
        return "Path not found."

    exts = {".py", ".js", ".ts"}
    hits = []
    for root, _, files in os.walk(target):
        for name in files:
            if Path(name).suffix not in exts:
                continue
            fp = Path(root) / name
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if pattern in line:
                    hits.append(f"{fp}:{i}:{line}")
                    if len(hits) >= 50:
                        return "\n".join(hits)[:2000]
    return "\n".join(hits)[:2000] if hits else f"No matches found for '{pattern}'."
```

For `summarize_website`, add URL allowlist + private-IP deny after DNS resolution before `requests.get`.

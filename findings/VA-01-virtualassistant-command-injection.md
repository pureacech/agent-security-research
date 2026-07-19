# VA-01 — OS command injection in `search_codebase` (Axshatt/VirtualAssistant)

**Reporter:** pureace (@pureacech)  
**Target:** https://github.com/Axshatt/VirtualAssistant  
**Component:** `mcp_server.py` — tool `search_codebase`  
**CWE:** CWE-78 (OS Command Injection)  
**Attack surface:** MCP tool arguments controlled by the connected model / caller  
**Status:** Draft — coordinated disclosure (do not publish full PoC until maintainer notified)

## Summary

`search_codebase` builds a shell command with untrusted `pattern` and `path` via an f-string and runs it with `subprocess.run(..., shell=True)`. Metacharacters in either argument can execute arbitrary OS commands as the MCP server user.

## Root cause

```python
cmd = f"grep -r --include='*.py' --include='*.js' --include='*.ts' -n '{pattern}' {path}"
result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
```

## Impact

Any party that can invoke the MCP tool (compromised prompt, malicious skill, hostile local agent workflow) gains arbitrary command execution on the host running the VirtualAssistant MCP server.

## Reproduction boundary (lab only)

1. Run the MCP server in an isolated lab account.
2. Invoke `search_codebase` with a `pattern` containing shell metacharacters (details withheld in public notes until disclosure window).
3. Observe secondary command execution in process accounting / lab marker file.

## Fix intent

- Never use `shell=True`.
- Pass argv list to `grep` (or use pure-Python walk + search).
- Treat `pattern` as a fixed string (`-F`) and reject/escape path outside an allowlisted workspace root.
- Canonicalize `path` and require it stays under the workspace.

## Regression checks

- [ ] Metacharacters in `pattern` do not spawn extra processes
- [ ] `path` with `../` cannot escape workspace
- [ ] Legitimate literal search still returns matches

## Timeline

| Date | Event |
|------|--------|
| 2026-07-19 | Issue confirmed in public source @ main |
| | Maintainer notified |
| | Fix available |
| | Public advisory |

## References

- Source: `mcp_server.py` (`search_codebase`)
- Related: VA-02 SSRF in `summarize_website`

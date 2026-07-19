# Research focus — agents & MCP

## Why this surface

Agents and MCP servers turn natural language into **actions**. The high-risk boundary is wherever input is no longer treated as data:

| Capability class | Typical CWE |
|------------------|-------------|
| Shell / exec | CWE-78 |
| URL fetch | CWE-918 |
| Filesystem read/write | CWE-22 |
| SQL / query build | CWE-89 |
| Skill install + scripts | supply-chain / dual-use |

## How reports are structured

1. Name the tool or endpoint  
2. Show the sink (shell, join, fetch)  
3. State impact in one line  
4. Give maintainer-safe fix intent + regression checks  

## Related public trail

Indexed in [PUBLIC-SUMMARY.md](PUBLIC-SUMMARY.md).

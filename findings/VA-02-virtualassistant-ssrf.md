# VA-02 — Server-Side Request Forgery in `summarize_website`

**Reporter:** pureace (@pureacech)  
**Target:** https://github.com/Axshatt/VirtualAssistant  
**Component:** `mcp_server.py` — tool `summarize_website`  
**CWE:** CWE-918 (SSRF)  
**Status:** Draft — coordinated disclosure

## Summary

`summarize_website(url)` passes the caller-supplied URL directly to `requests.get` with no scheme/host allowlist and no block on link-local / cloud metadata ranges. A tool caller can force the host to fetch internal HTTP services and return body content (first 2000 chars) to the model.

## Root cause

```python
response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
...
return text[:2000]
```

## Impact

- Access to link-local metadata endpoints (cloud credential theft class)
- Reachability of internal admin HTTP services bound to localhost / RFC1918
- Content exfiltration into the agent transcript

## Fix intent

- Allowlist schemes (`https` only by default)
- Resolve DNS and block private, loopback, link-local, metadata CIDRs
- Optional host allowlist for user-approved domains
- Cap redirects; do not follow off-allowlist redirects
- Redact sensitive headers from any logged URL

## Regression checks

- [ ] `http://127.0.0.1/` denied
- [ ] `http://169.254.169.254/` denied
- [ ] Public documentation host still works if allowlisted

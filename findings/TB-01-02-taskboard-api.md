# TB-01 / TB-02 — Demo API endpoint hardening

**Reporter:** [@pureacech](https://github.com/pureacech)  
**Project:** [nlyrthiia/taskboard-api](https://github.com/nlyrthiia/taskboard-api)  
**Status:** Fixed — [PR #1](https://github.com/nlyrthiia/taskboard-api/pull/1)

| ID | Endpoint | CWE |
|----|----------|-----|
| TB-01 | note file read by name | 22 |
| TB-02 | host ping helper | 78 |

## Fix

- Contain note reads under the notes directory  
- Validate host / deny private ranges; `spawn` argv, no shell  

# Maintainer notification checklist

## Before public full advisory

1. [ ] Open GitHub **Private vulnerability report** if enabled  
   - VirtualAssistant: https://github.com/Axshatt/VirtualAssistant/security/advisories/new  
   - moviefiesta: https://github.com/AnaghaSPrasad/moviefiesta/security/advisories/new  
2. [ ] Else open a private channel / maintainer email from profile  
3. [ ] Else minimal public issue: “Security contact?” without PoC  
4. [ ] Wait reasonable window (e.g. 7–14 days small project; up to 90 for larger)  
5. [ ] Offer a patch PR  
6. [ ] Request CVE via GitHub GHSA CNA or MITRE after confirm  
7. [ ] Publish sanitized write-up under `pureacech/web-security-reviews`

## Suggested private message (short)

```
Hi — I responsibly reviewed <repo> and found <CWE-xx> in <file/function>.
Impact: <one line>. I can share a minimal lab PoC and a patch diff privately.
Reporter: pureace (@pureacech). Please reply with preferred coordinated disclosure channel.
```

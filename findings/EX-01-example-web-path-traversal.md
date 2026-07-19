# EX-01 — Path traversal in examples file APIs

**Reporter:** [@pureacech](https://github.com/pureacech)  
**Project:** [nlyrthiia/move-examples-gallery](https://github.com/nlyrthiia/move-examples-gallery)  
**CWE:** CWE-22  
**Status:** Fixed — [PR #1](https://github.com/nlyrthiia/move-examples-gallery/pull/1)

## Summary

Route params for example `directory` / `file` were joined into filesystem paths and read without ensuring the final path stayed under the examples root.

## Fix

Resolve-and-contain helper; reject `..` and absolute segments before `fs` reads.

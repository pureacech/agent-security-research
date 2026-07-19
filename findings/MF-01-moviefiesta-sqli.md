# MF-01 — SQL injection via `movie_id` / `date` (MovieFiesta)

**Reporter:** pureace (@pureacech)  
**Target:** https://github.com/AnaghaSPrasad/moviefiesta  
**Components:** `movie_details.php`, `booking.php` (and related query builders)  
**CWE:** CWE-89 (SQL Injection)  
**Status:** Draft — coordinated disclosure

## Summary

User-controlled `$_GET['movie_id']` and `$_GET['date']` are concatenated into SQL strings without parameterization. Unlike `login.php` (which correctly uses prepared statements), these pages trust raw query parameters.

## Root cause (representative)

```php
$movie_id = $_GET['movie_id'];
$movieQuery = "SELECT * FROM Movies WHERE Movie_ID = '$movie_id'";
$movieResult = $conn->query($movieQuery);
```

`booking.php` repeats the pattern for `movie_id` and `date`.

## Impact

Unauthenticated (or low-privilege) HTTP clients who can reach a deployed instance can manipulate SQL grammar: data disclosure, authentication bypass follow-on, or destructive queries depending on DB permissions.

## Note on `sqlinsertion.sql`

The repo ships `sqlinsertion.sql` with schema and sample user rows (bcrypt hashes). If the full tree is deployed under a web root, that file is also a CWE-200 exposure class risk. Prefer keeping dumps outside the document root.

## Fix intent

- Replace all dynamic SQL with prepared statements + bound parameters (as already done in `login.php`)
- Validate IDs as integers; validate dates against a strict format
- Deny web access to `*.sql`

## Regression checks

- [ ] Quote/comment characters in `movie_id` do not alter query shape
- [ ] Happy-path movie detail and booking still work
- [ ] `GET /sqlinsertion.sql` returns 403/404 on staging deploy

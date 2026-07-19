# Suggested patch sketch — MovieFiesta SQLi

Mirror the prepared-statement style already used in `login.php`.

```php
// movie_details.php
$movie_id = filter_input(INPUT_GET, 'movie_id', FILTER_VALIDATE_INT);
if (!$movie_id) {
    http_response_code(400);
    exit('Invalid movie id');
}
$stmt = $conn->prepare('SELECT * FROM Movies WHERE Movie_ID = ?');
$stmt->bind_param('i', $movie_id);
$stmt->execute();
$movieResult = $stmt->get_result();
$movie = $movieResult->fetch_assoc();
```

```php
// booking.php — movie_id + date
$movie_id = filter_input(INPUT_GET, 'movie_id', FILTER_VALIDATE_INT);
$selectedDate = $_GET['date'] ?? date('Y-m-d');
if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $selectedDate)) {
    http_response_code(400);
    exit('Invalid date');
}
$stmt = $conn->prepare(
  'SELECT * FROM Theaters INNER JOIN Shows ON Theaters.Theater_ID = Shows.Theater_ID
   WHERE Shows.Movie_ID = ? AND Shows.Date = ?'
);
$stmt->bind_param('is', $movie_id, $selectedDate);
$stmt->execute();
$theatersResult = $stmt->get_result();
```

Also add web-server deny for `*.sql` and keep `sqlinsertion.sql` out of deploy artifacts.

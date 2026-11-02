<?php
// VULNERABILITY: Raw SQL string concatenation (CVSS 8.5)
header('Content-Type: application/json');

$db = new SQLite3('/tmp/vulnerable.db');
$db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)");
$db->exec("INSERT OR IGNORE INTO users (id, username, password, role) VALUES (1, 'admin', 'SuperSecretAdminP@ss2026', 'administrator')");

$username = $_POST['username'] ?? $_GET['username'] ?? '';
$password = $_POST['password'] ?? $_GET['password'] ?? '';

if ($username != '') {
    // Intentionally vulnerable SQL query
    $query = "SELECT username, role FROM users WHERE username = '$username' AND password = '$password'";
    $result = @$db->query($query);

    if ($result && $row = $result->fetchArray(SQLITE3_ASSOC)) {
        echo json_encode([
            "status" => "AUTHENTICATED",
            "account" => $row['username'],
            "role" => $row['role'],
            "flag" => "FLAG{SQLI_AUTH_BYPASS_SUCCESSFUL}"
        ]);
        exit;
    }
}

echo json_encode(["status" => "FAILED", "error" => "Invalid credentials or SQL syntax error"]);
?>
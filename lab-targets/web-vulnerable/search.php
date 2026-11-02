<?php
// VULNERABILITY: Reflected Cross-Site Scripting (XSS - CVSS 7.2)
// Echoes raw user input directly into HTML without htmlspecialchars()
header('Content-Type: text/html');

$q = $_GET['q'] ?? '';
echo "<html><body>";
echo "<h1>Search Results for: " . $q . "</h1>";
if ($q != '') {
    echo "<p>No results found for your query.</p>";
}
echo "</body></html>";
?>
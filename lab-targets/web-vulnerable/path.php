<?php
// VULNERABILITY: Unrestricted file inclusion (CVSS 7.5)
header('Content-Type: text/plain');

$file = $_GET['file'] ?? '';
if ($file != '') {
    // Intentionally allows dot-dot-slash traversal
    if (file_exists($file)) {
        echo file_get_contents($file);
    } else {
        echo "File not found: " . htmlspecialchars($file);
    }
} else {
    echo "Usage: ?file=<path>";
}
?>
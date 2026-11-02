<?php
// VULNERABILITY: Server-Side Request Forgery (SSRF - CVSS 8.6)
// Fetches arbitrary URLs provided by the user without validation
header('Content-Type: text/plain');

if (isset($_GET['url'])) {
    $url = $_GET['url'];
    
    // Simulate fetching internal resource
    $ctx = stream_context_create(['http' => ['timeout' => 2]]);
    $content = @file_get_contents($url, false, $ctx);
    
    if ($content !== false) {
        echo "SSRF_FETCH_SUCCESS:\n";
        echo $content;
    } else {
        echo "SSRF_FETCH_ERROR: Could not connect to " . htmlspecialchars($url);
    }
} else {
    echo "Usage: ?url=http://target";
}
?>
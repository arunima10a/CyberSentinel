<?php
// VULNERABILITY: Insecure Direct Object Reference (IDOR - CVSS 8.1)
// Exposes user records directly based on user_id without authorization check
header('Content-Type: application/json');

$profiles = [
    1 => ["id" => 1, "username" => "admin", "role" => "Chief Security Officer", "salary" => "$185,000", "api_key" => "SEC_KEY_live_99482914a"],
    2 => ["id" => 2, "username" => "bob", "role" => "Junior Analyst", "salary" => "$65,000", "api_key" => "SEC_KEY_dev_10481239b"],
    3 => ["id" => 3, "username" => "alice", "role" => "Auditor", "salary" => "$95,000", "api_key" => "SEC_KEY_audit_5521948c"]
];

$userId = $_GET['user_id'] ?? 2;

if (isset($profiles[$userId])) {
    echo json_encode([
        "status" => "SUCCESS",
        "data" => $profiles[$userId],
        "flag" => $userId == 1 ? "FLAG{IDOR_ADMIN_DATA_LEAKED}" : "PUBLIC_RECORD"
    ]);
} else {
    echo json_encode(["status" => "NOT_FOUND"]);
}
?>
<?php
// auth_secure.php - Secure Staff Key Authentication System
require_once 'db_config_pdo.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $inputKey = $_POST['auth_key'] ?? '';

    // 1. Validate UTF-8 encoding
    if (!mb_check_encoding($username, 'UTF-8') || !mb_check_encoding($inputKey, 'UTF-8')) {
        http_response_code(400);
        exit("Invalid encoding.");
    }

    // 2. Character-aware and byte-aware boundary checking
    if (mb_strlen($inputKey, 'UTF-8') > 256 || strlen($inputKey) > 1024) {
        http_response_code(400);
        exit("Authentication key exceeds allowed boundary.");
    }

    // 3. Fetch staff credential hash using prepared statement
    $stmt = $pdo->prepare(
        "SELECT username, auth_key_hash, role 
         FROM staff_credentials 
         WHERE username = :username 
         LIMIT 1"
    );

    $stmt->execute([
        "username" => $username
    ]);

    $staff = $stmt->fetch();

    // 4. Verify using Argon2id-compatible password_verify()
    if ($staff && password_verify($inputKey, $staff['auth_key_hash'])) {
        echo "Access Granted. Role: " . htmlspecialchars($staff['role'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    } else {
        http_response_code(401);
        echo "Access Denied.";
    }
}
?>
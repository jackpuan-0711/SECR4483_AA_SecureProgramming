<?php
// auth_secure.php - Secure Staff Authentication using UTF-8 validation and Argon2id

require_once 'db_config_pdo.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $inputKey = $_POST['auth_key'] ?? '';

    if (!mb_check_encoding($username, 'UTF-8') || !mb_check_encoding($inputKey, 'UTF-8')) {
        http_response_code(400);
        exit("Invalid UTF-8 input.");
    }

    $username = trim($username);

    if ($username === '' || $inputKey === '') {
        http_response_code(400);
        exit("Username and authentication key are required.");
    }

    if (mb_strlen($username, 'UTF-8') > 100) {
        http_response_code(400);
        exit("Username is too long.");
    }

    if (mb_strlen($inputKey, 'UTF-8') > 256) {
        http_response_code(400);
        exit("Authentication key exceeds 256 characters.");
    }

    $stmt = $pdo->prepare(
        "SELECT username, auth_key_hash, role
         FROM staff_credentials
         WHERE username = :username
         LIMIT 1"
    );

    $stmt->execute([
        'username' => $username
    ]);

    $staff = $stmt->fetch();

    if (!$staff) {
        echo "Access Denied.";
        exit;
    }

    $storedHash = $staff['auth_key_hash'];

    if (password_verify($inputKey, $storedHash)) {
        $safeRole = htmlspecialchars($staff['role'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        echo "Access Granted. Role: " . $safeRole;
    } else {
        echo "Access Denied.";
    }
}
?>
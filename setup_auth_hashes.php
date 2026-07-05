<?php
require_once 'db_config_pdo.php';

$accounts = [
    'dr_faizal' => 'testkey123',
    'dr_sharifah' => 'doctorsecret'
];

foreach ($accounts as $username => $plainKey) {
    $argonHash = password_hash($plainKey, PASSWORD_ARGON2ID, [
        'memory_cost' => 1 << 16,
        'time_cost' => 3,
        'threads' => 1
    ]);

    $stmt = $pdo->prepare(
        "UPDATE staff_credentials 
         SET auth_key_hash = :hash 
         WHERE username = :username"
    );

    $stmt->execute([
        "hash" => $argonHash,
        "username" => $username
    ]);

    echo "Updated Argon2id hash for " . htmlspecialchars($username) . "<br>";
}

echo "Done. Delete this setup file after use.";
?>
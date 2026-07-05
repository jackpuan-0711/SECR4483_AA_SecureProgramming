<?php
// crypto_vault_secure.php - Secure Patient Medical Records Protection

function loadEnvKey(): string {
    $envPath = __DIR__ . '/.env';

    if (!file_exists($envPath)) {
        throw new RuntimeException(".env file is missing.");
    }

    $env = parse_ini_file($envPath);

    if (!isset($env['MEDVAULT_KEY_B64'])) {
        throw new RuntimeException("MEDVAULT_KEY_B64 is missing.");
    }

    $key = base64_decode($env['MEDVAULT_KEY_B64'], true);

    if ($key === false || strlen($key) !== 32) {
        throw new RuntimeException("Invalid AES-256 key. Key must be 32 bytes after Base64 decoding.");
    }

    return $key;
}

function encryptMedicalPayload(string $payload): string {
    $key = loadEnvKey();
    $iv = random_bytes(12);
    $tag = '';

    $ciphertext = openssl_encrypt(
        $payload,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        '',
        16
    );

    if ($ciphertext === false) {
        throw new RuntimeException("Encryption failed.");
    }

    // Serialization format: [12-byte IV][ciphertext][16-byte tag]
    return base64_encode($iv . $ciphertext . $tag);
}

function decryptMedicalPayload(string $package): string {
    $raw = base64_decode($package, true);

    if ($raw === false || strlen($raw) < 28) {
        throw new RuntimeException("Invalid encrypted package.");
    }

    $iv = substr($raw, 0, 12);
    $tag = substr($raw, -16);
    $ciphertext = substr($raw, 12, -16);

    $plaintext = openssl_decrypt(
        $ciphertext,
        'aes-256-gcm',
        loadEnvKey(),
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    if ($plaintext === false) {
        throw new RuntimeException("AEAD authentication failed: payload was tampered.");
    }

    return $plaintext;
}

try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $payload = $_POST['payload'] ?? '';

        if ($payload === '') {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Payload is required."]);
            exit;
        }

        $encrypted = encryptMedicalPayload($payload);
        $decrypted = decryptMedicalPayload($encrypted);

        echo json_encode([
            "status" => "vaulted",
            "algorithm" => "AES-256-GCM",
            "data" => $encrypted,
            "verification" => $decrypted
        ], JSON_PRETTY_PRINT);
    } else {
        echo "Secure crypto vault is running. Send POST payload to encrypt.";
    }
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        "status" => "error",
        "message" => $e->getMessage()
    ]);
}
?>
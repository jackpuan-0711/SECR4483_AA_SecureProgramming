<?php
// crypto_vault_secure.php - Secure AES-256-GCM Medical Payload Protection

function loadEnvKey(): string
{
    $envPath = __DIR__ . DIRECTORY_SEPARATOR . '.env';

    if (!file_exists($envPath)) {
        throw new RuntimeException(".env file is missing.");
    }

    $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    $base64Key = null;

    foreach ($lines as $line) {
        $line = trim($line);

        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }

        if (str_starts_with($line, 'MEDVAULT_KEY_B64=')) {
            $base64Key = substr($line, strlen('MEDVAULT_KEY_B64='));
            $base64Key = trim($base64Key);
            $base64Key = trim($base64Key, "\"'");
            break;
        }
    }

    if ($base64Key === null || $base64Key === '') {
        throw new RuntimeException("MEDVAULT_KEY_B64 is missing in .env.");
    }

    $key = base64_decode($base64Key, true);

    if ($key === false) {
        throw new RuntimeException("MEDVAULT_KEY_B64 is not valid Base64.");
    }

    if (strlen($key) !== 32) {
        throw new RuntimeException("AES-256-GCM key must be exactly 32 bytes.");
    }

    return $key;
}

function encryptMedicalPayload(string $payload): string
{
    $key = loadEnvKey();

    // GCM recommends a 12-byte nonce/IV.
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

    // Serialization format:
    // [12-byte IV][variable-length ciphertext][16-byte authentication tag]
    $package = $iv . $ciphertext . $tag;

    return base64_encode($package);
}

function decryptMedicalPayload(string $packageB64): string
{
    $key = loadEnvKey();

    $package = base64_decode($packageB64, true);

    if ($package === false) {
        throw new RuntimeException("Invalid Base64 encrypted package.");
    }

    if (strlen($package) <= 28) {
        throw new RuntimeException("Encrypted package is too short.");
    }

    $iv = substr($package, 0, 12);
    $tag = substr($package, -16);
    $ciphertext = substr($package, 12, -16);

    $plaintext = openssl_decrypt(
        $ciphertext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        ''
    );

    if ($plaintext === false) {
        throw new RuntimeException("AEAD authentication failed. Ciphertext or tag may be tampered.");
    }

    return $plaintext;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    try {
        $payload = $_POST['payload'] ?? '';

        if (!mb_check_encoding($payload, 'UTF-8')) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "Invalid UTF-8 input."
            ]);
            exit;
        }

        if ($payload === '') {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "Payload is required."
            ]);
            exit;
        }

        $encrypted = encryptMedicalPayload($payload);

        echo json_encode([
            "status" => "vaulted",
            "algorithm" => "AES-256-GCM",
            "data" => $encrypted
        ], JSON_PRETTY_PRINT);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode([
            "status" => "error",
            "message" => $e->getMessage()
        ], JSON_PRETTY_PRINT);
    }
}
?>
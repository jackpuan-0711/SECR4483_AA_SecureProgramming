<?php
use PHPUnit\Framework\TestCase;

final class SecurityTest extends TestCase
{
    protected function setUp(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';

        ob_start();
        require_once __DIR__ . '/../crypto_vault_secure.php';
        ob_end_clean();
    }

    public function testValidEncryptionDecryptionCycle(): void
    {
        $plaintext = 'DIAGNOSIS: Stage-2 Carcinoma. STATUS: Critical.';

        $package = encryptMedicalPayload($plaintext);
        $decrypted = decryptMedicalPayload($package);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testTamperedCiphertextThrowsAeadException(): void
    {
        $plaintext = 'DIAGNOSIS: Acute Type-2 Diabetes. STATUS: Managed.';

        $package = encryptMedicalPayload($plaintext);
        $raw = base64_decode($package, true);

        $this->assertNotFalse($raw);
        $this->assertGreaterThan(28, strlen($raw));

        // Flip one byte inside the ciphertext area.
        $raw[12] = chr(ord($raw[12]) ^ 1);

        $tamperedPackage = base64_encode($raw);

        $this->expectException(RuntimeException::class);
        decryptMedicalPayload($tamperedPackage);
    }

    public function testArgon2idCredentialVerification(): void
    {
        $hash = password_hash('testkey123', PASSWORD_ARGON2ID);

        $this->assertTrue(password_verify('testkey123', $hash));
        $this->assertFalse(password_verify('wrongkey', $hash));
    }
}
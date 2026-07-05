# SECR4483 Secure Programming Alternative Assessment

This repository contains the vulnerable and secure refactored PHP source code for the SECR4483/SCSR4483 Secure Programming Alternative Assessment.

## Modules
- search.php: vulnerable patient search
- search_secure.php: PDO and output encoding refactor
- auth.php: vulnerable authentication
- auth_secure.php: UTF-8 validation and Argon2id refactor
- crypto_vault.php: vulnerable AES-ECB encryption
- crypto_vault_secure.php: AES-256-GCM refactor
- schema.sql: database initialization script

## Security Improvements
- SQL Injection mitigation using PDO prepared statements
- Reflected XSS mitigation using htmlspecialchars()
- UTF-8 boundary validation using mb_strlen()
- MD5 replacement using Argon2id
- AES-ECB replacement using AES-256-GCM
- Secret separation using .env and .gitignore
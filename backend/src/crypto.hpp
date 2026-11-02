// Cryptography helpers (OpenSSL): password hashing, token hashing, and encryption at rest.
#pragma once

#include <string>

namespace scamshield::crypto {

// Cryptographically secure random bytes as lowercase hex (2 characters per byte).
std::string randomHex(std::size_t bytes);

// Random string from `alphabet`, without modulo bias. Used for invite codes.
std::string randomCode(std::size_t length, const std::string& alphabet);

std::string sha256Hex(const std::string& data);

// Password hashing with scrypt (memory-hard) and a random 16-byte salt. The result is a
// self-describing string: "scrypt$logN$r$p$saltHex$hashHex".
std::string hashPassword(const std::string& password);
bool verifyPassword(const std::string& password, const std::string& encoded);

// 32-byte key for encrypting stored messages. Taken from SCAMSHIELD_DATA_KEY (64 hex characters)
// if set, otherwise read from (or created in) "<dbPath>.key" with owner-only permissions.
std::string loadOrCreateDataKey(const std::string& dbPath);

// AES-256-GCM. Output is hex of nonce(12) + ciphertext + tag(16). Decrypt fails (returns false)
// if the data was changed or the key is wrong.
std::string encrypt(const std::string& key32, const std::string& plaintext);
bool decrypt(const std::string& key32, const std::string& hexBlob, std::string* plaintext);

}  // namespace scamshield::crypto

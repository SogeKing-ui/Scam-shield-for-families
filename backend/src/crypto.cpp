#include "crypto.hpp"

#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace scamshield::crypto {
namespace {

constexpr int kLogN = 15;  // scrypt N = 32768
constexpr int kR = 8;
constexpr int kP = 1;
constexpr std::size_t kSaltLen = 16;
constexpr std::size_t kHashLen = 32;
constexpr std::size_t kMaxMem = 128u * 1024u * 1024u;
constexpr std::size_t kNonceLen = 12;
constexpr std::size_t kTagLen = 16;

std::string toHex(const unsigned char* data, std::size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 15]);
    }
    return out;
}

int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool fromHex(const std::string& hex, std::string* out) {
    if (hex.size() % 2 != 0) return false;
    out->clear();
    out->reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = hexVal(hex[i]), lo = hexVal(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out->push_back(static_cast<char>((hi << 4) | lo));
    }
    return true;
}

std::vector<std::string> splitDollar(const std::string& s) {
    std::vector<std::string> parts;
    std::string cur;
    for (char c : s) {
        if (c == '$') {
            parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    parts.push_back(cur);
    return parts;
}

bool scrypt(const std::string& password, const std::string& salt, int logN, int r, int p, unsigned char* out) {
    return EVP_PBE_scrypt(password.data(), password.size(), reinterpret_cast<const unsigned char*>(salt.data()),
                          salt.size(), 1ULL << logN, static_cast<uint64_t>(r), static_cast<uint64_t>(p), kMaxMem,
                          out, kHashLen) == 1;
}

}  // namespace

std::string randomHex(std::size_t bytes) {
    std::vector<unsigned char> buf(bytes);
    if (RAND_bytes(buf.data(), static_cast<int>(bytes)) != 1) throw std::runtime_error("random failed");
    return toHex(buf.data(), bytes);
}

std::string randomCode(std::size_t length, const std::string& alphabet) {
    const unsigned limit = 256u - (256u % static_cast<unsigned>(alphabet.size()));  // reject to avoid bias
    std::string out;
    while (out.size() < length) {
        unsigned char b;
        if (RAND_bytes(&b, 1) != 1) throw std::runtime_error("random failed");
        if (b < limit) out.push_back(alphabet[b % alphabet.size()]);
    }
    return out;
}

std::string sha256Hex(const std::string& data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), md, &len, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("sha256 failed");
    }
    return toHex(md, len);
}

std::string hashPassword(const std::string& password) {
    unsigned char salt[kSaltLen];
    if (RAND_bytes(salt, static_cast<int>(kSaltLen)) != 1) throw std::runtime_error("random failed");
    std::string saltStr(reinterpret_cast<char*>(salt), kSaltLen);
    unsigned char out[kHashLen];
    if (!scrypt(password, saltStr, kLogN, kR, kP, out)) throw std::runtime_error("scrypt failed");
    return "scrypt$" + std::to_string(kLogN) + "$" + std::to_string(kR) + "$" + std::to_string(kP) + "$" +
           toHex(salt, kSaltLen) + "$" + toHex(out, kHashLen);
}

bool verifyPassword(const std::string& password, const std::string& encoded) {
    std::vector<std::string> parts = splitDollar(encoded);
    if (parts.size() != 6 || parts[0] != "scrypt") return false;
    int logN = std::atoi(parts[1].c_str());
    int r = std::atoi(parts[2].c_str());
    int p = std::atoi(parts[3].c_str());
    if (logN < 10 || logN > 20 || r < 1 || r > 16 || p < 1 || p > 4) return false;
    std::string salt, expected;
    if (!fromHex(parts[4], &salt) || !fromHex(parts[5], &expected) || expected.size() != kHashLen) return false;
    unsigned char out[kHashLen];
    if (!scrypt(password, salt, logN, r, p, out)) return false;
    return CRYPTO_memcmp(out, expected.data(), kHashLen) == 0;
}

std::string loadOrCreateDataKey(const std::string& dbPath) {
    std::string hex;
    if (const char* env = std::getenv("SCAMSHIELD_DATA_KEY"); env && *env) {
        hex = env;
    } else {
        const std::string path = dbPath + ".key";
        std::ifstream in(path);
        if (in) {
            std::getline(in, hex);
        } else {
            hex = randomHex(32);
            int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (fd < 0) throw std::runtime_error("cannot create key file " + path);
            std::string line = hex + "\n";
            if (::write(fd, line.data(), line.size()) != static_cast<ssize_t>(line.size())) {
                ::close(fd);
                throw std::runtime_error("cannot write key file");
            }
            ::close(fd);
        }
    }
    std::string key;
    if (hex.size() != 64 || !fromHex(hex, &key)) {
        throw std::runtime_error("data key must be 64 hex characters (32 bytes)");
    }
    return key;
}

std::string encrypt(const std::string& key32, const std::string& plaintext) {
    if (key32.size() != 32) throw std::runtime_error("bad key size");
    unsigned char nonce[kNonceLen];
    if (RAND_bytes(nonce, static_cast<int>(kNonceLen)) != 1) throw std::runtime_error("random failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ct(plaintext.size() + 16);
    unsigned char tag[kTagLen];
    int len = 0, total = 0;
    bool ok = ctx && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceLen), nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key32.data()), nonce) == 1 &&
              EVP_EncryptUpdate(ctx, ct.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()),
                                static_cast<int>(plaintext.size())) == 1;
    if (ok) {
        total = len;
        ok = EVP_EncryptFinal_ex(ctx, ct.data() + total, &len) == 1;
        total += len;
    }
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagLen), tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw std::runtime_error("encrypt failed");
    return toHex(nonce, kNonceLen) + toHex(ct.data(), static_cast<std::size_t>(total)) + toHex(tag, kTagLen);
}

bool decrypt(const std::string& key32, const std::string& hexBlob, std::string* plaintext) {
    if (key32.size() != 32) return false;
    std::string blob;
    if (!fromHex(hexBlob, &blob) || blob.size() < kNonceLen + kTagLen) return false;
    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(blob.data());
    const std::size_t ctLen = blob.size() - kNonceLen - kTagLen;
    const unsigned char* ct = nonce + kNonceLen;
    unsigned char tag[kTagLen];
    std::copy(ct + ctLen, ct + ctLen + kTagLen, tag);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> pt(ctLen + 16);
    int len = 0, total = 0;
    bool ok = ctx && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceLen), nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key32.data()), nonce) == 1 &&
              EVP_DecryptUpdate(ctx, pt.data(), &len, ct, static_cast<int>(ctLen)) == 1;
    if (ok) {
        total = len;
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagLen), tag) == 1 &&
             EVP_DecryptFinal_ex(ctx, pt.data() + total, &len) == 1;  // fails if tampered
        total += len;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;
    plaintext->assign(reinterpret_cast<char*>(pt.data()), static_cast<std::size_t>(total));
    return true;
}

}  // namespace scamshield::crypto

// Accounts, sessions, family links, and shared messages, stored in SQLite.
//
// - Passwords: scrypt hashes only, never the password.
// - Session tokens, invite codes, and password-reset tokens: only their SHA-256 is stored.
// - Shared messages: encrypted with AES-256-GCM before they are written.
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "analyzer.hpp"
#include "db.hpp"

namespace scamshield {

struct User {
    std::int64_t id = 0;
    std::string email;
    std::string displayName;
    std::string role;  // "protected" (person being protected) or "helper" (trusted family member)
};

struct LinkedPerson {
    std::int64_t id;
    std::string displayName;
    std::int64_t since;
};

struct SharedItem {
    std::int64_t id;
    std::int64_t fromId;
    std::string fromName;
    int score;
    std::string level;
    std::int64_t createdAt;
    bool read;
    std::string payloadJson;  // decrypted: {"text":..., "signals":[...], "urls":[...], "phones":[...]}
};

enum class AiQuota { Ok, UserLimit, GlobalLimit };

constexpr int kResetMinutes = 30;  // how long a password-reset link works

struct PasswordReset {
    User user;
    std::string token;  // raw token for the emailed link; only its SHA-256 is stored
};

class Store {
public:
    // dataKey: 32 raw bytes used to encrypt shared messages.
    Store(const std::string& dbPath, const std::string& dataKey);

    // Users
    std::optional<User> createUser(const std::string& email, const std::string& displayName,
                                   const std::string& role, const std::string& password);
    std::optional<User> authenticate(const std::string& email, const std::string& password);
    bool deleteAccount(std::int64_t userId);

    // Password reset. createPasswordReset returns nothing for an unknown email (callers must not tell
    // the requester which case happened). A new request replaces any earlier link for that account.
    // resetPassword uses the token once, sets the new password, and signs the account out everywhere.
    std::optional<PasswordReset> createPasswordReset(const std::string& email);
    std::optional<User> resetPassword(const std::string& token, const std::string& newPassword);

    // Sessions (token is the raw cookie value; only its hash is stored)
    std::string createSession(std::int64_t userId);
    std::optional<User> userForSession(const std::string& token);
    void deleteSession(const std::string& token);

    // Family links
    std::string createInvite(std::int64_t protectedId);  // returns display code like "ABCD-EFGH"
    std::optional<User> acceptInvite(std::int64_t helperId, const std::string& code);
    std::vector<LinkedPerson> linksFor(const User& user);
    bool areLinked(std::int64_t protectedId, std::int64_t helperId);
    bool unlink(const User& user, std::int64_t otherId);

    // Daily AI usage limits (UTC days). useAi() consumes one unit when it returns Ok.
    AiQuota useAi(std::int64_t userId, int perUserCap, int globalCap);
    void refundAi(std::int64_t userId);
    int aiRemaining(std::int64_t userId, int perUserCap);

    // Shared messages
    std::optional<std::int64_t> shareMessage(std::int64_t protectedId, std::int64_t helperId,
                                             const std::string& text, const Result& result);
    std::vector<SharedItem> inbox(std::int64_t helperId, int limit);
    int unreadCount(std::int64_t helperId);
    bool markRead(std::int64_t helperId, std::int64_t itemId);
    bool deleteShared(const User& user, std::int64_t itemId);

private:
    std::optional<User> userById(std::int64_t id);

    Db db_;
    std::string key_;
    std::string dummyHash_;  // used to keep login timing similar for unknown emails
    std::mutex mu_;
};

}  // namespace scamshield

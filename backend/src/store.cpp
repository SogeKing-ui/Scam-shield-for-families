#include "store.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>

#include "crypto.hpp"
#include "json.hpp"

using json = nlohmann::json;

namespace scamshield {
namespace {

constexpr long long kSessionSeconds = 7 * 24 * 3600;
constexpr long long kInviteSeconds = 24 * 3600;
constexpr long long kResetSeconds = kResetMinutes * 60;
constexpr std::size_t kMaxSharedPerPair = 200;
const char* kCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";  // no 0/O/1/I/L

long long now() { return static_cast<long long>(std::time(nullptr)); }

std::string utcDay(long long offsetDays = 0) {
    std::time_t t = static_cast<std::time_t>(now() + offsetDays * 86400);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[16];
    std::strftime(buf, sizeof buf, "%Y-%m-%d", &tm);
    return buf;
}

bool validToken(const std::string& t) {
    if (t.size() != 64) return false;
    return std::all_of(t.begin(), t.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

std::string normalizeCode(const std::string& in) {
    std::string out;
    for (unsigned char c : in) {
        if (c == '-' || c == ' ') continue;
        out.push_back(static_cast<char>(std::toupper(c)));
    }
    return out;
}

bool validCode(const std::string& c) {
    if (c.size() != 8) return false;
    const std::string alpha = kCodeAlphabet;
    return std::all_of(c.begin(), c.end(), [&](char ch) { return alpha.find(ch) != std::string::npos; });
}

// BEGIN IMMEDIATE ... COMMIT, rolled back automatically on error.
class Tx {
public:
    explicit Tx(Db& db) : db_(db) { db_.exec("BEGIN IMMEDIATE"); }
    ~Tx() {
        if (!done_) {
            try {
                db_.exec("ROLLBACK");
            } catch (...) {
            }
        }
    }
    void commit() {
        db_.exec("COMMIT");
        done_ = true;
    }

private:
    Db& db_;
    bool done_ = false;
};

}  // namespace

Store::Store(const std::string& dbPath, const std::string& dataKey) : db_(dbPath), key_(dataKey) {
    db_.exec("PRAGMA foreign_keys = ON");
    db_.exec("PRAGMA journal_mode = WAL");
    db_.exec(
        "CREATE TABLE IF NOT EXISTS users ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " email TEXT NOT NULL UNIQUE,"
        " display_name TEXT NOT NULL,"
        " role TEXT NOT NULL CHECK (role IN ('protected','helper')),"
        " pw_hash TEXT NOT NULL,"
        " created_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS sessions ("
        " token_hash TEXT PRIMARY KEY,"
        " user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        " expires_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS invites ("
        " code_hash TEXT PRIMARY KEY,"
        " protected_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        " expires_at INTEGER NOT NULL,"
        " used INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS links ("
        " protected_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        " helper_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        " created_at INTEGER NOT NULL,"
        " PRIMARY KEY (protected_id, helper_id));"
        "CREATE TABLE IF NOT EXISTS shared_messages ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " protected_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        " helper_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        " payload_enc TEXT NOT NULL,"
        " score INTEGER NOT NULL,"
        " level TEXT NOT NULL,"
        " created_at INTEGER NOT NULL,"
        " read_at INTEGER);"
        "CREATE INDEX IF NOT EXISTS idx_shared_helper ON shared_messages(helper_id, created_at);"
        "CREATE TABLE IF NOT EXISTS ai_usage ("
        " day TEXT NOT NULL,"
        " scope TEXT NOT NULL,"
        " count INTEGER NOT NULL,"
        " PRIMARY KEY (day, scope));"
        "CREATE TABLE IF NOT EXISTS password_resets ("
        " token_hash TEXT PRIMARY KEY,"
        " user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        " expires_at INTEGER NOT NULL);");
    dummyHash_ = crypto::hashPassword("not-a-real-password");
}

std::optional<User> Store::userById(std::int64_t id) {
    Stmt st(db_, "SELECT id, email, display_name, role FROM users WHERE id = ?");
    st.integer(1, id);
    if (!st.step()) return std::nullopt;
    return User{st.colInt(0), st.colText(1), st.colText(2), st.colText(3)};
}

std::optional<User> Store::createUser(const std::string& email, const std::string& displayName,
                                      const std::string& role, const std::string& password) {
    const std::string hash = crypto::hashPassword(password);  // slow on purpose; done outside the lock
    std::lock_guard<std::mutex> lock(mu_);
    try {
        Stmt st(db_, "INSERT INTO users (email, display_name, role, pw_hash, created_at) VALUES (?,?,?,?,?)");
        st.text(1, email).text(2, displayName).text(3, role).text(4, hash).integer(5, now());
        st.run();
    } catch (const DbError& e) {
        if (e.isConstraint()) return std::nullopt;  // email already registered
        throw;
    }
    Stmt id(db_, "SELECT last_insert_rowid()");
    id.step();
    return userById(id.colInt(0));
}

std::optional<User> Store::authenticate(const std::string& email, const std::string& password) {
    std::string hash;
    User user;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        Stmt st(db_, "SELECT id, email, display_name, role, pw_hash FROM users WHERE email = ?");
        st.text(1, email);
        if (st.step()) {
            user = User{st.colInt(0), st.colText(1), st.colText(2), st.colText(3)};
            hash = st.colText(4);
            found = true;
        }
    }
    // Always do one slow hash check, even for unknown emails, so timing does not reveal who is registered.
    const bool ok = crypto::verifyPassword(password, found ? hash : dummyHash_);
    if (!found || !ok) return std::nullopt;
    return user;
}

bool Store::deleteAccount(std::int64_t userId) {
    std::lock_guard<std::mutex> lock(mu_);
    Stmt st(db_, "DELETE FROM users WHERE id = ?");
    st.integer(1, userId).run();
    return st.changes() > 0;
}

std::optional<PasswordReset> Store::createPasswordReset(const std::string& email) {
    std::lock_guard<std::mutex> lock(mu_);
    Stmt find(db_, "SELECT id FROM users WHERE email = ?");
    find.text(1, email);
    if (!find.step()) return std::nullopt;
    const std::int64_t userId = find.colInt(0);
    auto user = userById(userId);
    if (!user) return std::nullopt;
    const std::string token = crypto::randomHex(32);
    Tx tx(db_);
    Stmt clear(db_, "DELETE FROM password_resets WHERE user_id = ? OR expires_at < ?");  // one active link
    clear.integer(1, userId).integer(2, now()).run();
    Stmt st(db_, "INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?,?,?)");
    st.text(1, crypto::sha256Hex(token)).integer(2, userId).integer(3, now() + kResetSeconds).run();
    tx.commit();
    return PasswordReset{*user, token};
}

std::optional<User> Store::resetPassword(const std::string& token, const std::string& newPassword) {
    if (!validToken(token)) return std::nullopt;
    const std::string tokenHash = crypto::sha256Hex(token);
    std::int64_t userId = 0;
    {  // Quick look first, so a bad or expired link does not cost a slow password hash.
        std::lock_guard<std::mutex> lock(mu_);
        Stmt find(db_, "SELECT user_id FROM password_resets WHERE token_hash = ? AND expires_at > ?");
        find.text(1, tokenHash).integer(2, now());
        if (!find.step()) return std::nullopt;
        userId = find.colInt(0);
    }
    const std::string hash = crypto::hashPassword(newPassword);  // slow on purpose; done outside the lock
    std::lock_guard<std::mutex> lock(mu_);
    Tx tx(db_);
    // Deleting the row is what makes the link single-use, even if two requests race.
    Stmt use(db_, "DELETE FROM password_resets WHERE token_hash = ? AND expires_at > ?");
    use.text(1, tokenHash).integer(2, now()).run();
    if (use.changes() == 0) return std::nullopt;
    Stmt upd(db_, "UPDATE users SET pw_hash = ? WHERE id = ?");
    upd.text(1, hash).integer(2, userId).run();
    Stmt sessions(db_, "DELETE FROM sessions WHERE user_id = ?");  // sign out everywhere
    sessions.integer(1, userId).run();
    Stmt others(db_, "DELETE FROM password_resets WHERE user_id = ?");
    others.integer(1, userId).run();
    tx.commit();
    return userById(userId);
}

std::string Store::createSession(std::int64_t userId) {
    const std::string token = crypto::randomHex(32);
    std::lock_guard<std::mutex> lock(mu_);
    Stmt cleanup(db_, "DELETE FROM sessions WHERE expires_at < ?");
    cleanup.integer(1, now()).run();
    Stmt st(db_, "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)");
    st.text(1, crypto::sha256Hex(token)).integer(2, userId).integer(3, now() + kSessionSeconds).run();
    return token;
}

std::optional<User> Store::userForSession(const std::string& token) {
    if (!validToken(token)) return std::nullopt;
    std::lock_guard<std::mutex> lock(mu_);
    Stmt st(db_,
            "SELECT u.id, u.email, u.display_name, u.role FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = ? AND s.expires_at > ?");
    st.text(1, crypto::sha256Hex(token)).integer(2, now());
    if (!st.step()) return std::nullopt;
    return User{st.colInt(0), st.colText(1), st.colText(2), st.colText(3)};
}

void Store::deleteSession(const std::string& token) {
    if (!validToken(token)) return;
    std::lock_guard<std::mutex> lock(mu_);
    Stmt st(db_, "DELETE FROM sessions WHERE token_hash = ?");
    st.text(1, crypto::sha256Hex(token)).run();
}

std::string Store::createInvite(std::int64_t protectedId) {
    const std::string code = crypto::randomCode(8, kCodeAlphabet);
    std::lock_guard<std::mutex> lock(mu_);
    Tx tx(db_);
    Stmt clear(db_, "DELETE FROM invites WHERE protected_id = ? OR expires_at < ?");  // one active invite
    clear.integer(1, protectedId).integer(2, now()).run();
    Stmt st(db_, "INSERT INTO invites (code_hash, protected_id, expires_at) VALUES (?,?,?)");
    st.text(1, crypto::sha256Hex(code)).integer(2, protectedId).integer(3, now() + kInviteSeconds).run();
    tx.commit();
    return code.substr(0, 4) + "-" + code.substr(4);
}

std::optional<User> Store::acceptInvite(std::int64_t helperId, const std::string& rawCode) {
    const std::string code = normalizeCode(rawCode);
    if (!validCode(code)) return std::nullopt;
    const std::string hash = crypto::sha256Hex(code);
    std::lock_guard<std::mutex> lock(mu_);
    Tx tx(db_);
    Stmt find(db_, "SELECT protected_id FROM invites WHERE code_hash = ? AND used = 0 AND expires_at > ?");
    find.text(1, hash).integer(2, now());
    if (!find.step()) return std::nullopt;
    const std::int64_t protectedId = find.colInt(0);
    if (protectedId == helperId) return std::nullopt;
    Stmt link(db_, "INSERT OR IGNORE INTO links (protected_id, helper_id, created_at) VALUES (?,?,?)");
    link.integer(1, protectedId).integer(2, helperId).integer(3, now()).run();
    Stmt used(db_, "UPDATE invites SET used = 1 WHERE code_hash = ?");
    used.text(1, hash).run();
    tx.commit();
    return userById(protectedId);
}

std::vector<LinkedPerson> Store::linksFor(const User& user) {
    std::lock_guard<std::mutex> lock(mu_);
    const bool isProtected = user.role == "protected";
    Stmt st(db_, isProtected ? "SELECT u.id, u.display_name, l.created_at FROM links l JOIN users u ON u.id = l.helper_id "
                               "WHERE l.protected_id = ? ORDER BY l.created_at"
                             : "SELECT u.id, u.display_name, l.created_at FROM links l JOIN users u ON u.id = l.protected_id "
                               "WHERE l.helper_id = ? ORDER BY l.created_at");
    st.integer(1, user.id);
    std::vector<LinkedPerson> out;
    while (st.step()) out.push_back({st.colInt(0), st.colText(1), st.colInt(2)});
    return out;
}

bool Store::areLinked(std::int64_t protectedId, std::int64_t helperId) {
    std::lock_guard<std::mutex> lock(mu_);
    Stmt st(db_, "SELECT 1 FROM links WHERE protected_id = ? AND helper_id = ?");
    st.integer(1, protectedId).integer(2, helperId);
    return st.step();
}

bool Store::unlink(const User& user, std::int64_t otherId) {
    const bool isProtected = user.role == "protected";
    const std::int64_t protectedId = isProtected ? user.id : otherId;
    const std::int64_t helperId = isProtected ? otherId : user.id;
    std::lock_guard<std::mutex> lock(mu_);
    Tx tx(db_);
    Stmt del(db_, "DELETE FROM links WHERE protected_id = ? AND helper_id = ?");
    del.integer(1, protectedId).integer(2, helperId).run();
    const bool removed = del.changes() > 0;
    if (removed) {  // the helper loses access to everything that was shared with them
        Stmt msgs(db_, "DELETE FROM shared_messages WHERE protected_id = ? AND helper_id = ?");
        msgs.integer(1, protectedId).integer(2, helperId).run();
    }
    tx.commit();
    return removed;
}

AiQuota Store::useAi(std::int64_t userId, int perUserCap, int globalCap) {
    const std::string day = utcDay();
    const std::string userScope = "user:" + std::to_string(userId);
    std::lock_guard<std::mutex> lock(mu_);
    Tx tx(db_);
    auto countOf = [&](const std::string& scope) {
        Stmt st(db_, "SELECT count FROM ai_usage WHERE day = ? AND scope = ?");
        st.text(1, day).text(2, scope);
        return st.step() ? static_cast<int>(st.colInt(0)) : 0;
    };
    if (countOf(userScope) >= perUserCap) return AiQuota::UserLimit;
    if (countOf("global") >= globalCap) return AiQuota::GlobalLimit;
    for (const std::string& scope : {userScope, std::string("global")}) {
        Stmt up(db_, "INSERT INTO ai_usage (day, scope, count) VALUES (?, ?, 1) "
                     "ON CONFLICT(day, scope) DO UPDATE SET count = count + 1");
        up.text(1, day).text(2, scope).run();
    }
    Stmt old(db_, "DELETE FROM ai_usage WHERE day < ?");  // keep only recent days
    old.text(1, utcDay(-7)).run();
    tx.commit();
    return AiQuota::Ok;
}

void Store::refundAi(std::int64_t userId) {
    const std::string day = utcDay();
    std::lock_guard<std::mutex> lock(mu_);
    for (const std::string& scope : {"user:" + std::to_string(userId), std::string("global")}) {
        Stmt st(db_, "UPDATE ai_usage SET count = MAX(count - 1, 0) WHERE day = ? AND scope = ?");
        st.text(1, day).text(2, scope).run();
    }
}

int Store::aiRemaining(std::int64_t userId, int perUserCap) {
    std::lock_guard<std::mutex> lock(mu_);
    Stmt st(db_, "SELECT count FROM ai_usage WHERE day = ? AND scope = ?");
    st.text(1, utcDay()).text(2, "user:" + std::to_string(userId));
    const int used = st.step() ? static_cast<int>(st.colInt(0)) : 0;
    return std::max(perUserCap - used, 0);
}

std::optional<std::int64_t> Store::shareMessage(std::int64_t protectedId, std::int64_t helperId,
                                                const std::string& text, const Result& result) {
    json signals = json::array();
    for (const Signal& s : result.signals) {
        signals.push_back({{"id", s.id}, {"title", s.title}, {"explanation", s.explanation}, {"weight", s.weight}});
    }
    json urls = json::array();
    for (const UrlInfo& u : result.urls) urls.push_back({{"url", u.url}, {"host", u.host}, {"flags", u.flags}});
    json payload = {{"text", text}, {"signals", signals}, {"urls", urls}, {"phones", result.phones}};
    const std::string enc = crypto::encrypt(key_, payload.dump());

    std::lock_guard<std::mutex> lock(mu_);
    Tx tx(db_);
    Stmt linked(db_, "SELECT 1 FROM links WHERE protected_id = ? AND helper_id = ?");
    linked.integer(1, protectedId).integer(2, helperId);
    if (!linked.step()) return std::nullopt;
    Stmt ins(db_,
             "INSERT INTO shared_messages (protected_id, helper_id, payload_enc, score, level, created_at) "
             "VALUES (?,?,?,?,?,?)");
    ins.integer(1, protectedId).integer(2, helperId).text(3, enc).integer(4, result.score)
        .text(5, levelToString(result.level)).integer(6, now()).run();
    Stmt idq(db_, "SELECT last_insert_rowid()");
    idq.step();
    const std::int64_t id = idq.colInt(0);
    Stmt trim(db_,
              "DELETE FROM shared_messages WHERE protected_id = ? AND helper_id = ? AND id NOT IN "
              "(SELECT id FROM shared_messages WHERE protected_id = ? AND helper_id = ? ORDER BY id DESC LIMIT ?)");
    trim.integer(1, protectedId).integer(2, helperId).integer(3, protectedId).integer(4, helperId)
        .integer(5, static_cast<long long>(kMaxSharedPerPair)).run();
    tx.commit();
    return id;
}

std::vector<SharedItem> Store::inbox(std::int64_t helperId, int limit) {
    std::lock_guard<std::mutex> lock(mu_);
    Stmt st(db_,
            "SELECT m.id, m.protected_id, u.display_name, m.payload_enc, m.score, m.level, m.created_at, m.read_at "
            "FROM shared_messages m JOIN users u ON u.id = m.protected_id WHERE m.helper_id = ? "
            "ORDER BY m.created_at DESC, m.id DESC LIMIT ?");
    st.integer(1, helperId).integer(2, limit);
    std::vector<SharedItem> out;
    while (st.step()) {
        std::string payload;
        if (!crypto::decrypt(key_, st.colText(3), &payload)) continue;  // skip anything that fails to decrypt
        out.push_back({st.colInt(0), st.colInt(1), st.colText(2), static_cast<int>(st.colInt(4)), st.colText(5),
                       st.colInt(6), !st.colIsNull(7), payload});
    }
    return out;
}

int Store::unreadCount(std::int64_t helperId) {
    std::lock_guard<std::mutex> lock(mu_);
    Stmt st(db_, "SELECT COUNT(*) FROM shared_messages WHERE helper_id = ? AND read_at IS NULL");
    st.integer(1, helperId);
    st.step();
    return static_cast<int>(st.colInt(0));
}

bool Store::markRead(std::int64_t helperId, std::int64_t itemId) {
    std::lock_guard<std::mutex> lock(mu_);
    Stmt st(db_, "UPDATE shared_messages SET read_at = COALESCE(read_at, ?) WHERE id = ? AND helper_id = ?");
    st.integer(1, now()).integer(2, itemId).integer(3, helperId).run();
    return st.changes() > 0;
}

bool Store::deleteShared(const User& user, std::int64_t itemId) {
    std::lock_guard<std::mutex> lock(mu_);
    Stmt st(db_, "DELETE FROM shared_messages WHERE id = ? AND (protected_id = ? OR helper_id = ?)");
    st.integer(1, itemId).integer(2, user.id).integer(3, user.id).run();
    return st.changes() > 0;
}

}  // namespace scamshield

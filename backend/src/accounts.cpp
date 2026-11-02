#include "accounts.hpp"

#include <cctype>
#include <ctime>
#include <memory>

#include "analyzer.hpp"

using json = nlohmann::json;
using httplib::Request;
using httplib::Response;

namespace scamshield {
namespace {

constexpr int kMaxFailures = 5;
constexpr long long kLockSeconds = 15 * 60;
const char* kCookie = "ss_session";

long long nowSec() { return static_cast<long long>(std::time(nullptr)); }

struct State {
    Store& store;
    AccountsConfig cfg;
    http::RateLimiter authLimiter{10.0};  // sign up / log in: 10 per minute per address
    http::RateLimiter codeLimiter{8.0};   // trying invite codes: 8 per minute per address
    http::RateLimiter apiLimiter{120.0};  // everything else
    http::RateLimiter resetLimiter{5.0};  // asking for reset emails: 5 per minute per address
    struct Hourly {
        int count = 0;
        long long first = 0;
    };
    std::mutex hourlyMu;
    std::unordered_map<std::string, Hourly> hourly;
    struct Fail {
        int count = 0;
        long long first = 0;
    };
    std::mutex failMu;
    std::unordered_map<std::string, Fail> fails;

    State(Store& s, AccountsConfig c) : store(s), cfg(std::move(c)) {}

    bool locked(const std::string& key) {
        std::lock_guard<std::mutex> lock(failMu);
        auto it = fails.find(key);
        if (it == fails.end()) return false;
        if (nowSec() - it->second.first > kLockSeconds) {
            fails.erase(it);
            return false;
        }
        return it->second.count >= kMaxFailures;
    }
    void fail(const std::string& key) {
        std::lock_guard<std::mutex> lock(failMu);
        if (fails.size() > 10000) fails.clear();
        Fail& f = fails[key];
        if (f.count == 0 || nowSec() - f.first > kLockSeconds) f = Fail{0, nowSec()};
        ++f.count;
    }
    void clear(const std::string& key) {
        std::lock_guard<std::mutex> lock(failMu);
        fails.erase(key);
    }
    // At most `max` per hour per key (used so nobody can flood one person's inbox with reset emails).
    bool allowHourly(const std::string& key, int max) {
        std::lock_guard<std::mutex> lock(hourlyMu);
        if (hourly.size() > 10000) hourly.clear();
        Hourly& h = hourly[key];
        if (h.count == 0 || nowSec() - h.first > 3600) h = Hourly{0, nowSec()};
        if (h.count >= max) return false;
        ++h.count;
        return true;
    }
};

// Common checks. Returns false (and fills in the response) if the request should stop.
bool prelude(State& st, const Request& req, Response& res, http::RateLimiter& limiter, bool changesData) {
    http::applyCors(req, res, st.cfg.origins);
    if (changesData) {
        const std::string origin = req.get_header_value("Origin");
        if (!origin.empty() && !st.cfg.origins.allows(origin)) {
            http::sendError(res, 403, "Request not allowed.");
            return false;
        }
    }
    if (!limiter.allow(req.remote_addr)) {
        res.set_header("Retry-After", "30");
        http::sendError(res, 429, "Too many requests. Please wait a moment and try again.");
        return false;
    }
    return true;
}

bool readJson(const Request& req, Response& res, json* out) {
    if (req.get_header_value("Content-Type").rfind("application/json", 0) != 0) {
        http::sendError(res, 415, "Send JSON.");
        return false;
    }
    json j = json::parse(req.body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        http::sendError(res, 400, "That request was not understood.");
        return false;
    }
    *out = std::move(j);
    return true;
}

std::string str(const json& j, const char* key) {
    return (j.contains(key) && j[key].is_string()) ? j[key].get<std::string>() : std::string();
}

std::string trim(const std::string& s) {
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool validEmail(const std::string& e) {
    if (e.size() < 5 || e.size() > 254) return false;
    const std::size_t at = e.find('@');
    if (at == std::string::npos || at == 0 || at != e.rfind('@')) return false;
    for (unsigned char c : e) {
        if (c <= 0x20 || c >= 0x7f) return false;  // ASCII only, no spaces or control characters
    }
    const std::string domain = e.substr(at + 1);
    return domain.find('.') != std::string::npos && domain.front() != '.' && domain.back() != '.';
}

bool validName(const std::string& n) {
    if (n.empty() || n.size() > 60) return false;
    for (unsigned char c : n) {
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

// Empty string if the password is acceptable, otherwise a message to show.
std::string passwordProblem(const std::string& email, const std::string& password) {
    if (password.size() < 10 || password.size() > 128) return "Use a password with 10 to 128 characters.";
    if (lower(password) == email) return "The password cannot be your email.";
    return "";
}

json userJson(const User& u) {
    return {{"id", u.id}, {"email", u.email}, {"displayName", u.displayName}, {"role", u.role}, {"verified", u.verified}};
}

std::string sessionToken(const Request& req) {
    const std::string c = req.get_header_value("Cookie");
    const std::string name = std::string(kCookie) + "=";
    std::size_t p = c.find(name);
    while (p != std::string::npos) {
        if (p == 0 || c[p - 1] == ' ' || c[p - 1] == ';') {
            const std::size_t s = p + name.size();
            const std::size_t e = c.find(';', s);
            return c.substr(s, e == std::string::npos ? std::string::npos : e - s);
        }
        p = c.find(name, p + 1);
    }
    return "";
}

void setSessionCookie(State& st, Response& res, const std::string& token) {
    res.set_header("Set-Cookie", std::string(kCookie) + "=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800" +
                                     (st.cfg.secureCookie ? "; Secure" : ""));
}

void clearSessionCookie(State& st, Response& res) {
    res.set_header("Set-Cookie", std::string(kCookie) + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" +
                                     (st.cfg.secureCookie ? "; Secure" : ""));
}

std::optional<User> requireUser(State& st, const Request& req, Response& res, const char* role = nullptr) {
    auto user = st.store.userForSession(sessionToken(req));
    if (!user) {
        http::sendError(res, 401, "Please sign in.");
        return std::nullopt;
    }
    if (role && user->role != role) {
        http::sendError(res, 403, role == std::string("protected") ? "Only the person being protected can do this."
                                                                   : "Only a family helper can do this.");
        return std::nullopt;
    }
    return user;
}

// Linking and AI use need a confirmed email address, so one person cannot spread fake accounts around.
bool requireVerified(const User& user, Response& res) {
    if (user.verified) return true;
    http::sendError(res, 403, "Please confirm your email first. We sent you a link when you signed up.");
    return false;
}

bool parseId(const std::string& s, std::int64_t* out) {
    if (s.empty() || s.size() > 15) return false;
    *out = std::stoll(s);
    return true;
}

}  // namespace

std::optional<User> currentUser(Store& store, const Request& req) {
    return store.userForSession(sessionToken(req));
}

void registerAccountRoutes(httplib::Server& svr, Store& store, const AccountsConfig& config) {
    auto st = std::make_shared<State>(store, config);

    svr.Post("/api/auth/signup", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->authLimiter, true)) return;
        json body;
        if (!readJson(req, res, &body)) return;
        const std::string email = lower(trim(str(body, "email")));
        const std::string name = trim(str(body, "displayName"));
        const std::string role = str(body, "role");
        const std::string password = str(body, "password");
        if (!validEmail(email)) return http::sendError(res, 400, "Please enter a valid email address.");
        if (!validName(name)) return http::sendError(res, 400, "Please enter a name (1 to 60 characters).");
        if (role != "protected" && role != "helper") return http::sendError(res, 400, "Please choose a role.");
        if (const std::string problem = passwordProblem(email, password); !problem.empty()) {
            return http::sendError(res, 400, problem);
        }
        auto user = st->store.createUser(email, name, role, password);
        if (!user) return http::sendError(res, 400, "Could not create that account. Try a different email, or sign in.");
        deliverEmailVerification(st->cfg.mail, *user, st->store.createEmailVerification(user->id), str(body, "lang"));
        setSessionCookie(*st, res, st->store.createSession(user->id));
        res.status = 201;
        res.set_content(json{{"user", userJson(*user)}}.dump(), "application/json");
    });

    svr.Post("/api/auth/login", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->authLimiter, true)) return;
        json body;
        if (!readJson(req, res, &body)) return;
        const std::string email = lower(trim(str(body, "email")));
        const std::string password = str(body, "password");
        const std::string key = "login:" + email;
        if (st->locked(key)) {
            return http::sendError(res, 429, "Too many failed attempts. Please try again in 15 minutes.");
        }
        if (password.empty() || password.size() > 128) return http::sendError(res, 400, "Email or password is incorrect.");
        auto user = st->store.authenticate(email, password);
        if (!user) {
            st->fail(key);
            return http::sendError(res, 401, "Email or password is incorrect.");
        }
        st->clear(key);
        setSessionCookie(*st, res, st->store.createSession(user->id));
        res.set_content(json{{"user", userJson(*user)}}.dump(), "application/json");
    });

    // Step 1 of a password reset. The answer is always the same, so this cannot be used to find out who has an account.
    svr.Post("/api/auth/forgot", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->resetLimiter, true)) return;
        json body;
        if (!readJson(req, res, &body)) return;
        const std::string email = lower(trim(str(body, "email")));
        if (!validEmail(email)) return http::sendError(res, 400, "Please enter a valid email address.");
        if (st->allowHourly("reset:" + email, 3)) {
            if (auto reset = st->store.createPasswordReset(email)) {
                deliverPasswordReset(st->cfg.mail, reset->user, reset->token, str(body, "lang"));
            }
        }
        res.set_content(
            json{{"ok", true},
                 {"message", "If that email has an account, we sent a link to choose a new password. It works for " +
                                 std::to_string(kResetMinutes) + " minutes."}}
                .dump(),
            "application/json");
    });

    // Step 2: the emailed link carries a one-time token. It is only used up when the new password is accepted.
    svr.Post("/api/auth/reset", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->authLimiter, true)) return;
        json body;
        if (!readJson(req, res, &body)) return;
        const std::string password = str(body, "password");
        if (const std::string problem = passwordProblem("", password); !problem.empty()) {
            return http::sendError(res, 400, problem);
        }
        auto user = st->store.resetPassword(str(body, "token"), password);
        if (!user) {
            return http::sendError(res, 400, "This link has expired or was already used. Please ask for a new one.");
        }
        if (lower(password) == user->email) {  // rare; the token is already used, so ask again
            return http::sendError(res, 400, "The password cannot be your email. Please ask for a new link.");
        }
        st->clear("login:" + user->email);  // a locked-out person can get back in by resetting
        clearSessionCookie(*st, res);
        res.set_content(R"({"ok":true})", "application/json");
    });

    // Opening the emailed link confirms the address. It works without being signed in (the email may be opened on a phone).
    svr.Post("/api/auth/verify", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->apiLimiter, true)) return;  // the token is 256 random bits, so guessing is hopeless
        json body;
        if (!readJson(req, res, &body)) return;
        if (!st->store.verifyEmail(str(body, "token"))) {
            return http::sendError(res, 400, "This link has expired or was already used. Sign in and ask for a new one.");
        }
        res.set_content(R"({"ok":true})", "application/json");
    });

    svr.Post("/api/auth/resend-verification", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->apiLimiter, true)) return;  // plus 3 emails per hour per account below
        auto user = requireUser(*st, req, res);
        if (!user) return;
        json body;
        if (!readJson(req, res, &body)) return;
        if (!user->verified && st->allowHourly("verify:" + std::to_string(user->id), 3)) {
            deliverEmailVerification(st->cfg.mail, *user, st->store.createEmailVerification(user->id), str(body, "lang"));
        }
        res.set_content(R"({"ok":true})", "application/json");
    });

    svr.Post("/api/auth/logout", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->apiLimiter, true)) return;
        st->store.deleteSession(sessionToken(req));
        clearSessionCookie(*st, res);
        res.set_content(R"({"ok":true})", "application/json");
    });

    svr.Get("/api/auth/me", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->apiLimiter, false)) return;
        auto user = requireUser(*st, req, res);
        if (!user) return;
        json out = {{"user", userJson(*user)}};
        if (user->role == "helper") out["unread"] = st->store.unreadCount(user->id);
        res.set_content(out.dump(), "application/json");
    });

    svr.Post("/api/account/delete", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->authLimiter, true)) return;
        auto user = requireUser(*st, req, res);
        if (!user) return;
        json body;
        if (!readJson(req, res, &body)) return;
        const std::string key = "delete:" + std::to_string(user->id);
        if (st->locked(key)) return http::sendError(res, 429, "Too many failed attempts. Please try again later.");
        if (!st->store.authenticate(user->email, str(body, "password"))) {
            st->fail(key);
            return http::sendError(res, 401, "Password is incorrect.");
        }
        st->clear(key);
        st->store.deleteAccount(user->id);
        clearSessionCookie(*st, res);
        res.set_content(R"({"ok":true})", "application/json");
    });

    svr.Post("/api/links/invite", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->apiLimiter, true)) return;
        auto user = requireUser(*st, req, res, "protected");
        if (!user || !requireVerified(*user, res)) return;
        res.set_content(json{{"code", st->store.createInvite(user->id)}, {"expiresInHours", 24}}.dump(),
                        "application/json");
    });

    svr.Post("/api/links/accept", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->codeLimiter, true)) return;
        auto user = requireUser(*st, req, res, "helper");
        if (!user || !requireVerified(*user, res)) return;
        json body;
        if (!readJson(req, res, &body)) return;
        const std::string key = "invite:" + std::to_string(user->id);
        if (st->locked(key)) return http::sendError(res, 429, "Too many wrong codes. Please try again in 15 minutes.");
        auto person = st->store.acceptInvite(user->id, str(body, "code"));
        if (!person) {
            st->fail(key);
            return http::sendError(res, 400, "That code is not valid. It may have expired or been used already.");
        }
        st->clear(key);
        res.set_content(json{{"linked", {{"id", person->id}, {"displayName", person->displayName}}}}.dump(),
                        "application/json");
    });

    svr.Get("/api/links", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->apiLimiter, false)) return;
        auto user = requireUser(*st, req, res);
        if (!user) return;
        json list = json::array();
        for (const LinkedPerson& p : st->store.linksFor(*user)) {
            list.push_back({{"id", p.id}, {"displayName", p.displayName}, {"since", p.since}});
        }
        res.set_content(json{{"role", user->role}, {"links", list}}.dump(), "application/json");
    });

    svr.Delete(R"(/api/links/(\d+))", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->apiLimiter, true)) return;
        auto user = requireUser(*st, req, res);
        if (!user) return;
        std::int64_t other;
        if (!parseId(req.matches[1].str(), &other)) return http::sendError(res, 404, "Not found.");
        if (!st->store.unlink(*user, other)) return http::sendError(res, 404, "Not found.");
        res.set_content(R"({"ok":true})", "application/json");
    });

    svr.Post("/api/share", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->apiLimiter, true)) return;
        auto user = requireUser(*st, req, res, "protected");
        if (!user) return;
        json body;
        if (!readJson(req, res, &body)) return;
        const std::string text = str(body, "text");
        if (text.empty()) return http::sendError(res, 400, "The message is empty.");
        if (text.size() > kMaxChars) return http::sendError(res, 413, "That message is too long.");

        const std::vector<LinkedPerson> helpers = st->store.linksFor(*user);
        if (helpers.empty()) return http::sendError(res, 400, "You are not linked to a helper yet.");
        std::int64_t helperId = helpers[0].id;
        if (body.contains("helperId") && body["helperId"].is_number_integer()) {
            helperId = body["helperId"].get<std::int64_t>();
        } else if (helpers.size() > 1) {
            return http::sendError(res, 400, "Please choose which helper to send this to.");
        }
        // The score is always recomputed here; a client cannot make a message look worse or better.
        auto id = st->store.shareMessage(user->id, helperId, text, analyze(text));
        if (!id) return http::sendError(res, 400, "You are not linked to that helper.");
        res.status = 201;
        res.set_content(json{{"shared", true}}.dump(), "application/json");
    });

    svr.Get("/api/inbox", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->apiLimiter, false)) return;
        auto user = requireUser(*st, req, res, "helper");
        if (!user) return;
        json items = json::array();
        for (const SharedItem& it : st->store.inbox(user->id, 50)) {
            items.push_back({{"id", it.id},
                             {"from", {{"id", it.fromId}, {"displayName", it.fromName}}},
                             {"score", it.score},
                             {"level", it.level},
                             {"createdAt", it.createdAt},
                             {"read", it.read},
                             {"message", json::parse(it.payloadJson, nullptr, false)}});
        }
        res.set_content(json{{"items", items}, {"unread", st->store.unreadCount(user->id)}}.dump(), "application/json");
    });

    svr.Post(R"(/api/inbox/(\d+)/read)", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->apiLimiter, true)) return;
        auto user = requireUser(*st, req, res, "helper");
        if (!user) return;
        std::int64_t id;
        if (!parseId(req.matches[1].str(), &id) || !st->store.markRead(user->id, id)) {
            return http::sendError(res, 404, "Not found.");
        }
        res.set_content(R"({"ok":true})", "application/json");
    });

    svr.Delete(R"(/api/inbox/(\d+))", [st](const Request& req, Response& res) {
        if (!prelude(*st, req, res, st->apiLimiter, true)) return;
        auto user = requireUser(*st, req, res);
        if (!user) return;
        std::int64_t id;
        if (!parseId(req.matches[1].str(), &id) || !st->store.deleteShared(*user, id)) {
            return http::sendError(res, 404, "Not found.");
        }
        res.set_content(R"({"ok":true})", "application/json");
    });
}

}  // namespace scamshield

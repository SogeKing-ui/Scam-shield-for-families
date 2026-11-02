// Scam Shield API server.
//
// Anyone (no account needed):
//   POST /api/analyze   {"text": "..."}                                   -> analysis JSON
//   POST /api/explain   {"text": "...", "language": "en|es|ht", "consent": true}  -> explanation JSON
//   GET  /api/health
// Accounts (see accounts.cpp): sign up / log in, link a person to a family helper with an invite
// code, share a checked message with a helper, helper inbox, delete account.
//
// Security choices (see docs/SECURITY.md):
//  - binds to 127.0.0.1 only by default
//  - checked message text is never written to disk or logs (only messages a person chooses to
//    share with their helper are stored, and those are encrypted)
//  - passwords are stored as scrypt hashes; session tokens and invite codes only as SHA-256
//  - the AI explanation only runs with explicit consent, on a redacted copy, for signed-in accounts,
//    within daily limits (per account and overall), with a cache for repeated messages
//  - request size, input length, and request rates are limited; strict response headers; CSRF checks
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

#include "accounts.hpp"
#include "analyzer.hpp"
#include "crypto.hpp"
#include "explainer.hpp"
#include "http_util.hpp"
#include "httplib.h"
#include "mailer.hpp"
#include "json.hpp"
#include "store.hpp"

using json = nlohmann::json;
using scamshield::http::envOr;
using scamshield::http::sendError;

namespace {

json toJson(const scamshield::Result& r) {
    json signals = json::array();
    for (const auto& s : r.signals) {
        signals.push_back({{"id", s.id}, {"title", s.title}, {"explanation", s.explanation}, {"weight", s.weight}});
    }
    json urls = json::array();
    for (const auto& u : r.urls) {
        urls.push_back({{"url", u.url}, {"host", u.host}, {"flags", u.flags}});
    }
    return {{"score", r.score},
            {"level", scamshield::levelToString(r.level)},
            {"signals", signals},
            {"urls", urls},
            {"phones", r.phones}};
}

}  // namespace

int main() {
    const std::string host = envOr("SCAMSHIELD_HOST", "127.0.0.1");
    const int port = std::atoi(envOr("SCAMSHIELD_PORT", "8080").c_str());
    const std::string dbPath = envOr("SCAMSHIELD_DB", "scamshield.db");

    scamshield::AccountsConfig accounts;
    if (const char* o = std::getenv("SCAMSHIELD_ORIGIN"); o && *o) {
        accounts.origins.allowed = {o};
    } else {
        accounts.origins.allowed = {"http://localhost:5173", "http://127.0.0.1:5173"};
    }
    accounts.secureCookie = envOr("SCAMSHIELD_COOKIE_SECURE", "0") == "1";
    accounts.mail = scamshield::mailConfigFromEnv();

    std::unique_ptr<scamshield::Store> store;
    try {
        store = std::make_unique<scamshield::Store>(dbPath, scamshield::crypto::loadOrCreateDataKey(dbPath));
    } catch (const std::exception& e) {
        std::cerr << "Could not open the account database (" << dbPath << "): " << e.what() << std::endl;
        return 1;
    }

    const int userDailyCap = std::max(0, std::atoi(envOr("SCAMSHIELD_AI_USER_CAP", "5").c_str()));
    const int globalDailyCap = std::max(0, std::atoi(envOr("SCAMSHIELD_AI_DAILY_CAP", "200").c_str()));
    scamshield::http::RateLimiter limiter(30.0);         // 30 analyses per minute per client
    scamshield::http::RateLimiter explainLimiter(10.0);  // AI calls cost money: 10 per minute per client
    const scamshield::ExplainerConfig explainer = scamshield::configFromEnv();
    httplib::Server svr;

    svr.set_payload_max_length(16 * 1024);
    svr.set_read_timeout(5, 0);
    svr.set_write_timeout(5, 0);
    svr.set_default_headers({
        {"X-Content-Type-Options", "nosniff"},
        {"Cache-Control", "no-store"},
        {"Referrer-Policy", "no-referrer"},
        {"Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"},
    });

    svr.Options(R"(/api/.*)", [&](const httplib::Request& req, httplib::Response& res) {
        scamshield::http::applyCors(req, res, accounts.origins);
        res.set_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        res.status = 204;
    });

    svr.Get("/api/health", [&](const httplib::Request& req, httplib::Response& res) {
        scamshield::http::applyCors(req, res, accounts.origins);
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    svr.Post("/api/analyze", [&](const httplib::Request& req, httplib::Response& res) {
        scamshield::http::applyCors(req, res, accounts.origins);
        if (!limiter.allow(req.remote_addr)) {
            res.set_header("Retry-After", "30");
            return sendError(res, 429, "Too many requests. Please wait a moment and try again.");
        }
        json body = json::parse(req.body, nullptr, /*allow_exceptions=*/false);
        if (body.is_discarded() || !body.is_object() || !body.contains("text") || !body["text"].is_string()) {
            return sendError(res, 400, "Send JSON like {\"text\": \"the message\"}.");
        }
        const std::string text = body["text"].get<std::string>();
        if (text.empty()) return sendError(res, 400, "The message is empty.");
        if (text.size() > scamshield::kMaxChars) {
            return sendError(res, 413, "That message is too long. Please paste up to 5000 characters.");
        }
        res.set_content(toJson(scamshield::analyze(text)).dump(), "application/json");
    });

    svr.Post("/api/explain", [&](const httplib::Request& req, httplib::Response& res) {
        scamshield::http::applyCors(req, res, accounts.origins);
        if (!explainLimiter.allow(req.remote_addr)) {
            res.set_header("Retry-After", "30");
            return sendError(res, 429, "Too many requests. Please wait a moment and try again.");
        }
        json body = json::parse(req.body, nullptr, /*allow_exceptions=*/false);
        if (body.is_discarded() || !body.is_object() || !body.contains("text") || !body["text"].is_string()) {
            return sendError(res, 400, "Send JSON like {\"text\": \"the message\", \"consent\": true}.");
        }
        if (!body.contains("consent") || body["consent"] != true) {
            return sendError(res, 400, "Consent is required before a message is sent to an AI service.");
        }
        const std::string lang = body.contains("language") && body["language"].is_string()
                                     ? body["language"].get<std::string>()
                                     : "en";
        if (!scamshield::isSupportedLanguage(lang)) return sendError(res, 400, "Unsupported language.");
        const std::string text = body["text"].get<std::string>();
        if (text.empty()) return sendError(res, 400, "The message is empty.");
        if (text.size() > scamshield::kMaxChars) {
            return sendError(res, 413, "That message is too long. Please paste up to 5000 characters.");
        }

        // Cost controls: AI answers need a signed-in account, each account and the whole app have a
        // daily limit, and repeated messages are answered from a cache at no cost.
        const auto user = scamshield::currentUser(*store, req);
        scamshield::Explanation ex;
        std::string blockNote;
        if (auto cached = scamshield::cachedExplanation(text, lang)) {
            ex = *cached;
        } else if (explainer.apiKey.empty()) {
            ex = scamshield::explain(explainer, text, lang);  // built-in, says why
        } else if (!user) {
            blockNote = "Sign in to use AI explanations. This is the built-in explanation.";
        } else {
            switch (store->useAi(user->id, userDailyCap, globalDailyCap)) {
                case scamshield::AiQuota::Ok:
                    ex = scamshield::explain(explainer, text, lang);
                    if (ex.source != "claude") store->refundAi(user->id);  // do not charge a failed attempt
                    break;
                case scamshield::AiQuota::UserLimit:
                    blockNote = "You have used today's " + std::to_string(userDailyCap) +
                                " AI explanations. They reset tomorrow. This is the built-in explanation.";
                    break;
                case scamshield::AiQuota::GlobalLimit:
                    blockNote = "AI explanations are paused for today to keep costs down. This is the built-in explanation.";
                    break;
            }
        }
        if (!blockNote.empty()) {
            scamshield::ExplainerConfig off = explainer;
            off.apiKey.clear();
            ex = scamshield::explain(off, text, lang);
            ex.note = blockNote + (lang != "en" ? " It is only available in English." : "");
        }
        json out = {{"text", ex.text}, {"source", ex.source}, {"model", ex.model}, {"note", ex.note}};
        if (user) out["remainingToday"] = store->aiRemaining(user->id, userDailyCap);
        res.set_content(out.dump(), "application/json");
    });

    scamshield::registerAccountRoutes(svr, *store, accounts);

    if (explainer.apiKey.empty()) {
        std::cout << "AI explanations: built-in only (set ANTHROPIC_API_KEY to use Claude)" << std::endl;
    } else if (!scamshield::sslAvailable() && explainer.baseUrl.rfind("https://", 0) == 0) {
        std::cout << "AI explanations: key found, but this build has no HTTPS support. "
                     "Install OpenSSL and rebuild (see README). Using built-in explanations."
                  << std::endl;
    } else {
        std::cout << "AI explanations: Claude (" << explainer.model << ")" << std::endl;
    }
    std::cout << "AI limits per day: " << userDailyCap << " per account, " << globalDailyCap << " in total" << std::endl;
    std::cout << (accounts.mail.enabled() ? "Password reset: emails are sent through the mail provider"
                                          : "Password reset: dev mode, reset links are printed here in the console")
              << std::endl;
    std::cout << "Accounts database: " << dbPath << std::endl;
    std::cout << "Scam Shield API listening on http://" << host << ":" << port << std::endl;
    if (!svr.listen(host, port)) {
        std::cerr << "Could not start server on " << host << ":" << port << std::endl;
        return 1;
    }
    return 0;
}

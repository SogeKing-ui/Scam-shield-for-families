// Scam Shield API server.
//   POST /api/analyze   {"text": "..."}  ->  analysis JSON
//   GET  /api/health
//
// Security choices (see docs/SECURITY.md):
//  - binds to 127.0.0.1 only by default
//  - message text is never written to disk or logs
//  - request size, input length, and per-client request rate are limited
//  - strict response headers; CORS only for the configured frontend origin
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>

#include "analyzer.hpp"
#include "httplib.h"
#include "json.hpp"

using json = nlohmann::json;
using Clock = std::chrono::steady_clock;

namespace {

std::string envOr(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : fallback;
}

// Simple token bucket per client address: `capacity` requests, refilled
// continuously over one minute.
class RateLimiter {
public:
    explicit RateLimiter(double perMinute) : capacity_(perMinute), ratePerSec_(perMinute / 60.0) {}

    bool allow(const std::string& client) {
        std::lock_guard<std::mutex> lock(mu_);
        const auto now = Clock::now();
        if (buckets_.size() > 10000) buckets_.clear();  // bound memory
        auto it = buckets_.find(client);
        if (it == buckets_.end()) {
            buckets_[client] = {capacity_ - 1.0, now};
            return true;
        }
        Bucket& b = it->second;
        double elapsed = std::chrono::duration<double>(now - b.last).count();
        b.tokens = std::min(capacity_, b.tokens + elapsed * ratePerSec_);
        b.last = now;
        if (b.tokens < 1.0) return false;
        b.tokens -= 1.0;
        return true;
    }

private:
    struct Bucket {
        double tokens;
        Clock::time_point last;
    };
    double capacity_;
    double ratePerSec_;
    std::mutex mu_;
    std::unordered_map<std::string, Bucket> buckets_;
};

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

void error(httplib::Response& res, int status, const std::string& message) {
    res.status = status;
    res.set_content(json{{"error", message}}.dump(), "application/json");
}

}  // namespace

int main() {
    const std::string host = envOr("SCAMSHIELD_HOST", "127.0.0.1");
    const int port = std::atoi(envOr("SCAMSHIELD_PORT", "8080").c_str());
    const std::string allowedOrigin = envOr("SCAMSHIELD_ORIGIN", "http://localhost:5173");

    RateLimiter limiter(30.0);  // 30 analyses per minute per client
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

    auto cors = [&](const httplib::Request& req, httplib::Response& res) {
        if (req.get_header_value("Origin") == allowedOrigin) {
            res.set_header("Access-Control-Allow-Origin", allowedOrigin);
            res.set_header("Vary", "Origin");
        }
    };

    svr.Options("/api/analyze", [&](const httplib::Request& req, httplib::Response& res) {
        cors(req, res);
        res.set_header("Access-Control-Allow-Methods", "POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        res.status = 204;
    });

    svr.Get("/api/health", [&](const httplib::Request& req, httplib::Response& res) {
        cors(req, res);
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    svr.Post("/api/analyze", [&](const httplib::Request& req, httplib::Response& res) {
        cors(req, res);
        if (!limiter.allow(req.remote_addr)) {
            res.set_header("Retry-After", "30");
            return error(res, 429, "Too many requests. Please wait a moment and try again.");
        }
        json body = json::parse(req.body, nullptr, /*allow_exceptions=*/false);
        if (body.is_discarded() || !body.is_object() || !body.contains("text") || !body["text"].is_string()) {
            return error(res, 400, "Send JSON like {\"text\": \"the message\"}.");
        }
        const std::string text = body["text"].get<std::string>();
        if (text.empty()) return error(res, 400, "The message is empty.");
        if (text.size() > scamshield::kMaxChars) {
            return error(res, 413, "That message is too long. Please paste up to 5000 characters.");
        }
        res.set_content(toJson(scamshield::analyze(text)).dump(), "application/json");
    });

    std::cout << "Scam Shield API listening on http://" << host << ":" << port << std::endl;
    if (!svr.listen(host, port)) {
        std::cerr << "Could not start server on " << host << ":" << port << std::endl;
        return 1;
    }
    return 0;
}

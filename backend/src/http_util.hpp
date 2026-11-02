// Small shared helpers for the HTTP layer.
#pragma once

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "httplib.h"
#include "json.hpp"

namespace scamshield::http {

inline std::string envOr(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : fallback;
}

inline void sendError(httplib::Response& res, int status, const std::string& message) {
    res.status = status;
    res.set_content(nlohmann::json{{"error", message}}.dump(), "application/json");
}

// Token bucket per key: `perMinute` requests, refilled continuously.
class RateLimiter {
public:
    explicit RateLimiter(double perMinute) : capacity_(perMinute), ratePerSec_(perMinute / 60.0) {}

    bool allow(const std::string& key) {
        using Clock = std::chrono::steady_clock;
        std::lock_guard<std::mutex> lock(mu_);
        const auto now = Clock::now();
        if (buckets_.size() > 10000) buckets_.clear();  // bound memory
        auto it = buckets_.find(key);
        if (it == buckets_.end()) {
            buckets_[key] = {capacity_ - 1.0, now};
            return true;
        }
        Bucket& b = it->second;
        const double elapsed = std::chrono::duration<double>(now - b.last).count();
        b.tokens = std::min(capacity_, b.tokens + elapsed * ratePerSec_);
        b.last = now;
        if (b.tokens < 1.0) return false;
        b.tokens -= 1.0;
        return true;
    }

private:
    struct Bucket {
        double tokens;
        std::chrono::steady_clock::time_point last;
    };
    double capacity_;
    double ratePerSec_;
    std::mutex mu_;
    std::unordered_map<std::string, Bucket> buckets_;
};

// Browser origins that may call the API (the web app). Requests with a different Origin are refused
// when they change data, which blocks cross-site request forgery.
struct Origins {
    std::vector<std::string> allowed;
    bool allows(const std::string& origin) const {
        return std::find(allowed.begin(), allowed.end(), origin) != allowed.end();
    }
};

inline void applyCors(const httplib::Request& req, httplib::Response& res, const Origins& origins) {
    const std::string origin = req.get_header_value("Origin");
    if (!origin.empty() && origins.allows(origin)) {
        res.set_header("Access-Control-Allow-Origin", origin);
        res.set_header("Access-Control-Allow-Credentials", "true");
        res.set_header("Vary", "Origin");
    }
}

}  // namespace scamshield::http

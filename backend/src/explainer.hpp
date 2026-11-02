// Plain-language explanations of a scam verdict.
//
// With ANTHROPIC_API_KEY set, a redacted copy of the message is sent to Claude.
// Without a key (or if the call fails) a built-in English explanation is used.
#pragma once

#include <optional>
#include <string>

#include "analyzer.hpp"

namespace scamshield {

struct ExplainerConfig {
    std::string apiKey;   // from ANTHROPIC_API_KEY; never logged
    std::string model;    // SCAMSHIELD_MODEL, default claude-haiku-5-5
    std::string baseUrl;  // ANTHROPIC_BASE_URL, default https://api.anthropic.com (override for tests)
};

struct Explanation {
    std::string text;
    std::string source;  // "claude" or "builtin"
    std::string model;   // empty for builtin
    std::string note;    // optional message for the UI
};

ExplainerConfig configFromEnv();
bool isSupportedLanguage(const std::string& code);  // "en", "es", "ht"
bool sslAvailable();                                // was the server built with HTTPS support?

// Exposed for tests.
std::string buildSystemPrompt();
std::string buildUserPrompt(const Result& result, const std::string& message, const std::string& lang);
std::string builtinExplanation(const Result& result);

Explanation explain(const ExplainerConfig& config, const std::string& message, const std::string& lang);

// Earlier AI answer for the same (redacted) message and language, if any. Free: no API call, no quota.
std::optional<Explanation> cachedExplanation(const std::string& message, const std::string& lang);

}  // namespace scamshield

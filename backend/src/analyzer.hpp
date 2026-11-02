// Scam Shield analyzer: scores a message for common scam warning signs.
// Pure standard C++17, no network access, no storage. Easy to unit test.
#pragma once

#include <string>
#include <vector>

namespace scamshield {

constexpr std::size_t kMaxChars = 5000;

enum class Level { Low, Medium, High };

struct Signal {
    std::string id;
    std::string title;
    std::string explanation;
    int weight;
};

struct UrlInfo {
    std::string url;                 // as written in the message
    std::string host;                // parsed host (lowercase)
    std::vector<std::string> flags;  // human-readable problems with this link
};

struct Result {
    int score = 0;  // 0..100
    Level level = Level::Low;
    std::vector<Signal> signals;  // sorted, strongest first
    std::vector<UrlInfo> urls;
    std::vector<std::string> phones;
};

Result analyze(const std::string& message);
std::string levelToString(Level level);

}  // namespace scamshield

// Evaluation helper: reads one escaped line of text per message from stdin and
// prints "score<TAB>signal ids" for each. Used by tools/evaluate.py.
#include <iostream>
#include <string>

#include "analyzer.hpp"

static std::string unescape(const std::string& s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char c = s[++i];
            out += (c == 'n') ? '\n' : (c == 't') ? '\t' : c;
        } else {
            out += s[i];
        }
    }
    return out;
}

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        auto r = scamshield::analyze(unescape(line));
        std::cout << r.score << '\t';
        for (std::size_t i = 0; i < r.signals.size(); ++i) std::cout << (i ? "," : "") << r.signals[i].id;
        std::cout << '\n';
    }
}

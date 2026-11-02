#include "redact.hpp"

#include <cctype>

namespace scamshield {
namespace {

bool isAlnum(char c) {
    unsigned char u = static_cast<unsigned char>(c);
    return u < 128 && std::isalnum(u) != 0;
}
bool isDigit(char c) { return c >= '0' && c <= '9'; }
bool isSpace(char c) { return std::isspace(static_cast<unsigned char>(c)) != 0; }
bool isLocalChar(char c) { return isAlnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-'; }
bool isDomainChar(char c) { return isAlnum(c) || c == '.' || c == '-'; }

bool startsAt(const std::string& s, std::size_t i, const char* prefix) {
    std::string p(prefix);
    return s.compare(i, p.size(), p) == 0;
}

std::string redactEmails(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '@') {
            std::size_t localLen = 0;
            while (localLen < out.size() && isLocalChar(out[out.size() - 1 - localLen])) ++localLen;
            std::size_t j = i + 1;
            while (j < in.size() && isDomainChar(in[j])) ++j;
            std::string domain = in.substr(i + 1, j - i - 1);
            // Do not swallow a sentence-ending period.
            while (!domain.empty() && domain.back() == '.') {
                domain.pop_back();
                --j;
            }
            if (localLen > 0 && domain.find('.') != std::string::npos) {
                out.erase(out.size() - localLen);
                out += "[EMAIL]";
                i = j - 1;
                continue;
            }
        }
        out.push_back(in[i]);
    }
    return out;
}

std::string redactNumbers(const std::string& in) {
    const std::string seps = " .-()+";
    std::string out;
    out.reserve(in.size());
    const std::size_t n = in.size();
    std::size_t i = 0;
    while (i < n) {
        bool tokenStart = (i == 0) || isSpace(in[i - 1]);
        // Copy links untouched (an IP address in a link is not a phone number).
        if (tokenStart && (startsAt(in, i, "http://") || startsAt(in, i, "https://") || startsAt(in, i, "www."))) {
            while (i < n && !isSpace(in[i])) out.push_back(in[i++]);
            continue;
        }
        char c = in[i];
        bool canStart = (isDigit(c) || c == '+' || c == '(') && (i == 0 || !isAlnum(in[i - 1]));
        if (!canStart) {
            out.push_back(c);
            ++i;
            continue;
        }
        std::size_t j = i, last = i;
        int digits = 0;
        while (j < n && (isDigit(in[j]) || seps.find(in[j]) != std::string::npos)) {
            if (isDigit(in[j])) {
                ++digits;
                last = j;
            }
            ++j;
        }
        if (digits >= 7) {
            out += (digits == 10 || digits == 11) ? "[PHONE]" : "[NUMBER]";
            i = last + 1;  // keep trailing separators as normal text
        } else {
            out.append(in, i, j - i);
            i = j;
        }
    }
    return out;
}

}  // namespace

std::string redact(const std::string& text) { return redactNumbers(redactEmails(text)); }

}  // namespace scamshield

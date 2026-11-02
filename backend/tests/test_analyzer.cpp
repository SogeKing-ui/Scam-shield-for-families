// Minimal dependency-free tests. Run with `make test`.
#include <iostream>
#include <string>

#include "analyzer.hpp"

using namespace scamshield;

static int failures = 0;
static int checks = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        ++checks;                                                                \
        if (!(cond)) {                                                           \
            ++failures;                                                          \
            std::cerr << "FAIL line " << __LINE__ << ": " #cond << std::endl;    \
        }                                                                        \
    } while (0)

static bool has(const Result& r, const std::string& id) {
    for (const auto& s : r.signals)
        if (s.id == id) return true;
    return false;
}

int main() {
    {  // Classic IRS gift card scam
        Result r = analyze("FINAL NOTICE: This is the IRS. There is a warrant for your arrest. "
                           "Pay immediately with gift cards and call 561-555-0142 now. Don't tell anyone.");
        CHECK(r.level == Level::High);
        CHECK(has(r, "payment"));
        CHECK(has(r, "threat"));
        CHECK(has(r, "secrecy"));
        CHECK(has(r, "combo-pay-pressure"));
        CHECK(has(r, "callback"));
        CHECK(r.phones.size() == 1);
        CHECK(r.score <= 100);
    }
    {  // Smart apostrophe from an iPhone still matches
        Result r = analyze("Please don\xE2\x80\x99t tell anyone about this.");
        CHECK(has(r, "secrecy"));
    }
    {  // Ordinary message stays low
        Result r = analyze("Hey, are we still on for dinner at 7? I made a reservation near the first parking garage.");
        CHECK(r.level == Level::Low);
        CHECK(r.signals.empty());
    }
    {  // "irs" must not match inside "first" or "shirt"
        Result r = analyze("My first shirt is blue");
        CHECK(!has(r, "impersonation"));
    }
    {  // Shortened link
        Result r = analyze("Your package is waiting, track it: bit.ly/3xYz12");
        CHECK(r.urls.size() == 1);
        CHECK(has(r, "url-shortener"));
    }
    {  // Look-alike brand domains (digit tricks and extra words)
        Result r = analyze("Verify your account at http://paypa1-secure-login.com/verify");
        CHECK(has(r, "url-lookalike"));
        CHECK(has(r, "url-not_https"));
        Result r2 = analyze("Sign in at https://www.paypal.com/signin");
        CHECK(!has(r2, "url-lookalike"));
        CHECK(r2.urls.size() == 1);
    }
    {  // Real domains that merely contain a short brand string are not flagged
        Result r = analyze("See https://purchase.com/offers and https://pineapple.com");
        CHECK(!has(r, "url-lookalike"));
    }
    {  // Raw IP and userinfo tricks
        Result r = analyze("Log in: http://192.168.4.20/bank and https://chase.com@evil.example.xyz/login");
        CHECK(has(r, "url-ip"));
        CHECK(has(r, "url-userinfo"));
        CHECK(has(r, "url-risky_tld"));
    }
    {  // Trailing punctuation does not break link detection
        Result r = analyze("Go to www.example.com.");
        CHECK(r.urls.size() == 1);
        CHECK(r.urls[0].host == "www.example.com");
    }
    {  // Spanish and Haitian Creole starter phrases
        Result r = analyze("Felicitaciones, has ganado un premio. No le digas a nadie.");
        CHECK(has(r, "prize"));
        CHECK(has(r, "secrecy"));
    }
    {  // Very long input is clipped, not crashed
        std::string big(200000, 'a');
        Result r = analyze(big);
        CHECK(r.level == Level::Low);
    }
    {  // Empty input
        Result r = analyze("");
        CHECK(r.score == 0);
    }

    std::cout << (checks - failures) << "/" << checks << " checks passed" << std::endl;
    return failures == 0 ? 0 : 1;
}

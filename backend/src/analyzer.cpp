#include "analyzer.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <utility>

namespace scamshield {
namespace {

// ---------- small text helpers ----------

bool isAlnumAscii(char ch) {
    unsigned char c = static_cast<unsigned char>(ch);
    return c < 128 && std::isalnum(c) != 0;
}

bool isDigit(char ch) { return ch >= '0' && ch <= '9'; }

bool startsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

bool endsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

// Lowercase ASCII and turn phone "smart quotes" into plain apostrophes so that
// "don’t" matches "don't".
std::string normalize(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(in[i]);
        if (c == 0xE2 && i + 2 < in.size() && static_cast<unsigned char>(in[i + 1]) == 0x80 &&
            (static_cast<unsigned char>(in[i + 2]) == 0x99 ||
             static_cast<unsigned char>(in[i + 2]) == 0x98)) {
            out.push_back('\'');
            i += 2;
        } else if (c < 128) {
            out.push_back(static_cast<char>(std::tolower(c)));
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

// Whole-word / whole-phrase match, so "irs" does not match "first".
bool containsWord(const std::string& hay, const std::string& needle) {
    std::size_t pos = 0;
    while ((pos = hay.find(needle, pos)) != std::string::npos) {
        bool left = pos == 0 || !isAlnumAscii(hay[pos - 1]);
        std::size_t end = pos + needle.size();
        bool right = end >= hay.size() || !isAlnumAscii(hay[end]);
        if (left && right) return true;
        ++pos;
    }
    return false;
}

std::vector<std::string> split(const std::string& s, const std::string& seps) {
    std::vector<std::string> parts;
    std::string cur;
    for (char c : s) {
        if (seps.find(c) != std::string::npos) {
            parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    parts.push_back(cur);
    return parts;
}

// ---------- keyword rules (English, Spanish, Haitian Creole starter set) ----------

struct TextRule {
    const char* id;
    const char* title;
    const char* explanation;
    int weight;
    std::vector<std::string> phrases;
};

const std::vector<TextRule>& textRules() {
    static const std::vector<TextRule> rules = {
        {"urgency", "Pressure to act fast",
         "Scammers rush you so you do not stop to think or ask anyone. Real companies give you time.",
         12,
         {"act now", "act immediately", "immediately", "urgent", "urgently", "right away",
          "within 24 hours", "within 48 hours", "final notice", "final warning", "last warning",
          "last chance", "expires today", "respond now", "ijan", "imedyatman", "urgente",
          "de inmediato", "ultimo aviso", "último aviso"}},
        {"threat", "Threats or scary consequences",
         "Threats of arrest, lawsuits, or a locked account are used to scare people into paying or sharing information.",
         20,
         {"arrest", "arrested", "warrant", "suspended", "locked", "legal action", "lawsuit",
          "deactivated", "will be closed", "jail", "deport", "deported", "deportation",
          "visa cancelled", "arete", "mandat", "arrestado", "suspendido", "suspendida", "bloqueado",
          "bloqueada"}},
        {"payment", "Asks for a hard-to-trace payment",
         "Gift cards, wire transfers, crypto, and payment apps are favorites of scammers because the money is almost impossible to get back. Real agencies and companies do not demand these.",
         30,
         {"gift card", "gift cards", "giftcard", "itunes card", "google play card", "steam card",
          "wire transfer", "wire the money", "western union", "moneygram", "bitcoin", "crypto",
          "cryptocurrency", "zelle", "cash app", "cashapp", "venmo", "prepaid card",
          "tarjeta de regalo", "kat kado"}},
        {"credentials", "Asks for private codes or account details",
         "Nobody legitimate will ask you to send a password, PIN, one-time code, or full Social Security number by text, email, or phone.",
         25,
         {"password", "passcode", "verification code", "security code", "one-time code",
          "one time code", "otp", "social security number", "ssn", "pin", "card number", "cvv",
          "routing number", "account number", "modpas", "mòdpas", "kod verifikasyon",
          "kòd verifikasyon", "contrasena", "contraseña", "codigo de verificacion",
          "código de verificación", "numero de seguro social", "número de seguro social"}},
        {"link-action", "Pushes you to click or 'verify'",
         "Messages that tell you to click a link to verify or update an account are a common way to steal logins.",
         10,
         {"click the link", "click here", "tap the link", "tap here", "follow the link",
          "open the link", "verify your account", "confirm your account", "update your account",
          "update your payment", "verify your identity"}},
        {"impersonation", "Claims to be a well-known organization",
         "Scammers pretend to be banks, delivery companies, utilities, and government agencies. Do not trust the sender's name; contact the real organization yourself.",
         12,
         {"irs", "internal revenue service", "social security administration", "medicare",
          "medicaid", "amazon", "paypal", "your bank", "fedex", "usps", "netflix", "microsoft",
          "apple support", "wells fargo", "chase", "bank of america", "fpl", "duke energy",
          "sheriff", "fbi", "uscis", "customs", "utility company"}},
        {"prize", "Promises a prize or money",
         "If you did not enter a contest, you did not win one. 'Winnings' that cost you a fee are a scam.",
         20,
         {"you won", "you have won", "you've won", "winner", "congratulations", "lottery",
          "sweepstakes", "claim your prize", "inheritance", "unclaimed funds", "gagnan",
          "ou genyen", "felicitaciones", "has ganado"}},
        {"secrecy", "Tells you to keep it secret",
         "Scammers isolate people so family or the bank cannot warn them. A real emergency never requires secrecy.",
         25,
         {"don't tell", "do not tell", "dont tell", "keep this secret", "keep it secret",
          "between us", "pa di pesonn", "pa di pèsonn", "no le digas", "no se lo digas"}},
        {"family", "Sounds like a 'family emergency' scam",
         "Messages like 'Hi Mom, this is my new number' or 'I need bail money' are common impersonation scams. Call the person on the number you already have.",
         25,
         {"hi mom", "hi dad", "hey mom", "hey dad", "grandma", "grandpa", "grandson",
          "granddaughter", "bail", "new number", "new phone", "lost my phone",
          "in the hospital"}},
        {"remote-access", "Asks to control your device",
         "Remote-access apps let a scammer see and control your phone or computer. Never install one for someone who contacted you first.",
         25,
         {"teamviewer", "anydesk", "remote access", "remote desktop", "screen share",
          "ultraviewer"}},
        {"refund", "Mentions a refund or unclaimed money",
         "Surprise refunds and 'overpayments' are used to trick people into sharing bank details or sending money back.",
         12,
         {"refund", "overpaid", "overpayment", "you are owed", "reimbursement", "unclaimed"}},
    };
    return rules;
}

const std::vector<std::string> kCallbackPhrases = {"call", "llame", "llamar", "rele"};

// ---------- phone numbers ----------

std::vector<std::string> extractPhones(const std::string& text) {
    std::vector<std::string> phones;
    std::set<std::string> seen;
    const std::string seps = " .-()+";
    const std::size_t n = text.size();
    for (std::size_t i = 0; i < n; ++i) {
        char c = text[i];
        if (!(isDigit(c) || c == '+' || c == '(')) continue;
        if (i > 0 && isAlnumAscii(text[i - 1])) continue;
        std::size_t j = i, last = i;
        int digits = 0;
        while (j < n && (isDigit(text[j]) || seps.find(text[j]) != std::string::npos)) {
            if (isDigit(text[j])) {
                ++digits;
                last = j;
                if (digits > 11) break;
            }
            ++j;
        }
        if (digits == 10 || digits == 11) {
            std::string cand = text.substr(i, last - i + 1);
            if (seen.insert(cand).second) phones.push_back(cand);
        }
        i = (j > i) ? j - 1 : i;
    }
    return phones;
}

// ---------- links ----------

const std::set<std::string> kShorteners = {"bit.ly",  "tinyurl.com", "t.co",   "goo.gl",
                                           "is.gd",   "cutt.ly",     "rb.gy",  "ow.ly",
                                           "shorturl.at", "tiny.cc", "t.ly"};

const std::set<std::string> kRiskyTlds = {"xyz", "top", "click", "icu", "buzz", "live",
                                          "link", "info", "shop", "online", "site", "cc",
                                          "support", "monster", "rest"};

const std::set<std::string> kCommonTlds = {"com", "net", "org", "us", "co", "io", "me", "app"};

struct Brand {
    const char* name;
    bool substring;  // true: match anywhere in a host part; false: whole part only
    std::vector<std::string> official;
};

const std::vector<Brand>& brands() {
    static const std::vector<Brand> b = {
        {"paypal", true, {"paypal.com"}},
        {"amazon", true, {"amazon.com", "amazon.co.uk"}},
        {"netflix", true, {"netflix.com"}},
        {"microsoft", true, {"microsoft.com"}},
        {"wellsfargo", true, {"wellsfargo.com"}},
        {"bankofamerica", true, {"bankofamerica.com"}},
        {"fedex", true, {"fedex.com"}},
        {"medicare", true, {"medicare.gov"}},
        {"socialsecurity", true, {"ssa.gov", "socialsecurity.gov"}},
        {"chase", false, {"chase.com"}},
        {"apple", false, {"apple.com", "icloud.com"}},
        {"irs", false, {"irs.gov"}},
        {"usps", false, {"usps.com"}},
        {"fpl", false, {"fpl.com"}},
    };
    return b;
}

std::string stripEdges(const std::string& tok) {
    std::size_t b = 0, e = tok.size();
    while (b < e && std::string("(<[\"'").find(tok[b]) != std::string::npos) ++b;
    while (e > b && std::string(".,;:!?)>]\"'").find(tok[e - 1]) != std::string::npos) --e;
    return tok.substr(b, e - b);
}

bool looksLikeHost(const std::string& host) {
    if (host.find('.') == std::string::npos) return false;
    for (char c : host) {
        if (!(isAlnumAscii(c) || c == '-' || c == '.')) return false;
    }
    return true;
}

std::string hostOf(std::string rest, bool* hasUserInfo) {
    std::size_t end = rest.find_first_of("/?#");
    std::string authority = rest.substr(0, end);
    *hasUserInfo = false;
    std::size_t at = authority.rfind('@');
    if (at != std::string::npos) {
        *hasUserInfo = true;
        authority = authority.substr(at + 1);
    }
    std::size_t colon = authority.find(':');
    if (colon != std::string::npos) authority = authority.substr(0, colon);
    return authority;
}

bool isIpv4(const std::string& host) {
    int dots = 0;
    for (char c : host) {
        if (c == '.') ++dots;
        else if (!isDigit(c)) return false;
    }
    return dots == 3;
}

std::string registrable(const std::vector<std::string>& labels) {
    if (labels.size() < 2) return labels.empty() ? "" : labels[0];
    return labels[labels.size() - 2] + "." + labels.back();
}

std::string undoLookalikes(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        if (c == '0') c = 'o';
        else if (c == '1') c = 'l';
        else if (c == '3') c = 'e';
        else if (c == '5') c = 's';
    }
    return out;
}

// Returns the UrlInfo for a token if it looks like a link, else an empty url.
UrlInfo inspectToken(const std::string& original) {
    UrlInfo info;
    std::string token = stripEdges(original);
    if (token.empty()) return info;
    std::string lo = normalize(token);

    bool http = false;
    std::string rest;
    if (startsWith(lo, "https://")) rest = lo.substr(8);
    else if (startsWith(lo, "http://")) { rest = lo.substr(7); http = true; }
    else if (startsWith(lo, "www.")) rest = lo;
    else {
        std::string h = lo.substr(0, lo.find_first_of("/?#"));
        if (!looksLikeHost(h)) return info;
        std::string tld = h.substr(h.rfind('.') + 1);
        if (!(kShorteners.count(h) || kRiskyTlds.count(tld) || kCommonTlds.count(tld))) return info;
        rest = lo;
    }

    bool userInfo = false;
    std::string host = hostOf(rest, &userInfo);
    if (host.empty() || !looksLikeHost(host)) return info;

    info.url = token;
    info.host = host;

    std::vector<std::string> labels = split(host, ".");
    std::string reg = registrable(labels);
    std::string tld = labels.back();

    if (http) info.flags.push_back("not_https");
    if (userInfo) info.flags.push_back("userinfo");
    if (isIpv4(host)) info.flags.push_back("ip");
    if (host.find("xn--") != std::string::npos) info.flags.push_back("punycode");
    if (kShorteners.count(host)) info.flags.push_back("shortener");
    if (kRiskyTlds.count(tld)) info.flags.push_back("risky_tld");
    if (labels.size() >= 5) info.flags.push_back("deep_subdomains");
    if (std::count(host.begin(), host.end(), '-') >= 3) info.flags.push_back("many_hyphens");

    std::vector<std::string> parts = split(undoLookalikes(host), ".-");
    for (const Brand& brand : brands()) {
        bool mentions = false;
        for (const std::string& part : parts) {
            if (part == brand.name || (brand.substring && part.find(brand.name) != std::string::npos)) {
                mentions = true;
                break;
            }
        }
        if (!mentions) continue;
        bool official = false;
        for (const std::string& dom : brand.official) {
            if (reg == dom || endsWith(host, "." + dom)) official = true;
        }
        if (!official) {
            info.flags.push_back(std::string("lookalike:") + brand.name);
            break;
        }
    }
    return info;
}

std::vector<UrlInfo> extractUrls(const std::string& text) {
    std::vector<UrlInfo> urls;
    std::set<std::string> seen;
    std::string tok;
    auto flush = [&]() {
        if (tok.empty()) return;
        UrlInfo u = inspectToken(tok);
        if (!u.url.empty() && seen.insert(u.url).second) urls.push_back(std::move(u));
        tok.clear();
    };
    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c))) flush();
        else tok.push_back(c);
    }
    flush();
    return urls;
}

struct FlagInfo {
    const char* id;
    const char* title;
    const char* explanation;
    int weight;
};

const std::vector<FlagInfo>& flagInfos() {
    static const std::vector<FlagInfo> f = {
        {"ip", "Link goes to a raw number address",
         "Real companies use their own names in links, not a string of numbers.", 25},
        {"userinfo", "Link hides its real destination",
         "A '@' in a link can make it look like one website while sending you to another.", 25},
        {"punycode", "Link uses look-alike characters",
         "The address uses special characters that can imitate a real website's name.", 25},
        {"shortener", "Shortened link hides where it goes",
         "Short links (like bit.ly) hide the real destination. Scammers use them a lot.", 15},
        {"risky_tld", "Link ends in an unusual domain",
         "Endings like .xyz, .top, and .click are cheap and heavily used for scam sites.", 15},
        {"not_https", "Link is not secure",
         "The link starts with http:// instead of https://, so it is not using a secure connection.", 8},
        {"deep_subdomains", "Link has a very long address",
         "Long, stacked addresses are used to bury the real website name.", 8},
        {"many_hyphens", "Link has many dashes",
         "Addresses like 'secure-login-update-account.com' are typical of fake sites.", 10},
    };
    return f;
}

}  // namespace

std::string levelToString(Level level) {
    switch (level) {
        case Level::Low: return "low";
        case Level::Medium: return "medium";
        case Level::High: return "high";
    }
    return "low";
}

Result analyze(const std::string& message) {
    const std::string clipped = message.substr(0, kMaxChars);
    const std::string lo = normalize(clipped);

    Result r;
    std::set<std::string> seen;
    auto add = [&](const std::string& id, const std::string& title, const std::string& why, int weight) {
        if (seen.insert(id).second) r.signals.push_back({id, title, why, weight});
    };

    for (const TextRule& rule : textRules()) {
        for (const std::string& phrase : rule.phrases) {
            if (containsWord(lo, phrase)) {
                add(rule.id, rule.title, rule.explanation, rule.weight);
                break;
            }
        }
    }

    r.phones = extractPhones(clipped);
    if (!r.phones.empty()) {
        for (const std::string& phrase : kCallbackPhrases) {
            if (containsWord(lo, phrase)) {
                add("callback", "Asks you to call a number in the message",
                    "Scammers put their own phone number in the message so you reach them instead of the real company. Look up the official number yourself.",
                    15);
                break;
            }
        }
    }

    r.urls = extractUrls(clipped);
    for (const UrlInfo& u : r.urls) {
        for (const std::string& flag : u.flags) {
            if (startsWith(flag, "lookalike:")) {
                std::string brand = flag.substr(10);
                add("url-lookalike", "Link imitates " + brand,
                    "The link's address uses the name '" + brand + "' but does not belong to the real " + brand +
                        " website. This is a classic fake-login trick.",
                    30);
                continue;
            }
            for (const FlagInfo& info : flagInfos()) {
                if (flag == info.id) add(std::string("url-") + info.id, info.title, info.explanation, info.weight);
            }
        }
    }

    // Combinations are much more suspicious than any single sign.
    const bool pressure = seen.count("urgency") || seen.count("threat") || seen.count("secrecy");
    if (seen.count("payment") && pressure) {
        add("combo-pay-pressure", "Pressure plus a hard-to-trace payment",
            "Being rushed or threatened while being asked to pay by gift card, crypto, or transfer is the most common scam pattern.",
            15);
    }
    if (seen.count("credentials") && (seen.count("link-action") || !r.urls.empty())) {
        add("combo-login-link", "Link plus a request for private details",
            "A link combined with a request for codes or passwords is how many accounts get taken over.", 10);
    }

    std::stable_sort(r.signals.begin(), r.signals.end(),
                     [](const Signal& a, const Signal& b) { return a.weight > b.weight; });

    int score = 0;
    for (const Signal& s : r.signals) score += s.weight;
    r.score = std::min(score, 100);
    r.level = r.score >= 55 ? Level::High : (r.score >= 25 ? Level::Medium : Level::Low);
    return r;
}

}  // namespace scamshield

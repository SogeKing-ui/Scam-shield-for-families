#include "mailer.hpp"

#include <cstdlib>
#include <iostream>
#include <thread>

#include "explainer.hpp"
#include "httplib.h"
#include "json.hpp"

using json = nlohmann::json;

namespace scamshield {
namespace {

std::string envOr(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : fallback;
}

// Runs on a background thread. Never logs the key, the address, or the link.
void sendEmail(const MailConfig& cfg, const std::string& to, const std::string& subject, const std::string& text) {
    if (!sslAvailable() && cfg.baseUrl.rfind("https://", 0) == 0) {
        std::cerr << "mail: this build has no HTTPS support, so the reset email was not sent" << std::endl;
        return;
    }
    json body = {{"from", cfg.from}, {"to", json::array({to})}, {"subject", subject}, {"text", text}};
    httplib::Client cli(cfg.baseUrl);
    cli.set_connection_timeout(5, 0);
    cli.set_write_timeout(10, 0);
    cli.set_read_timeout(15, 0);
    httplib::Headers headers = {{"Authorization", "Bearer " + cfg.apiKey}};
    auto res = cli.Post("/emails", headers, body.dump(), "application/json");
    if (!res) {
        std::cerr << "mail: request failed (" << httplib::to_string(res.error()) << ")" << std::endl;
    } else if (res->status < 200 || res->status >= 300) {
        std::cerr << "mail: provider returned HTTP " << res->status << std::endl;
    }
}

}  // namespace

MailConfig mailConfigFromEnv() {
    MailConfig c;
    c.apiKey = envOr("SCAMSHIELD_MAIL_API_KEY", "");
    c.from = envOr("SCAMSHIELD_MAIL_FROM", "");
    c.baseUrl = envOr("SCAMSHIELD_MAIL_BASE_URL", "https://api.resend.com");
    c.appUrl = envOr("SCAMSHIELD_APP_URL", "http://localhost:5173");
    while (c.appUrl.size() > 1 && c.appUrl.back() == '/') c.appUrl.pop_back();
    return c;
}

// The token goes after "#", which browsers never send to a server, so it stays out of server logs and
// Referer headers. The web app reads it and removes it from the address bar.
std::string resetLink(const MailConfig& cfg, const std::string& token) { return cfg.appUrl + "/#reset=" + token; }

std::string resetEmailBody(const std::string& displayName, const std::string& link, int minutes) {
    return "Hello " + displayName +
           ",\n\nSomeone asked to reset the password for your Scam Shield account. "
           "To choose a new password, open this link:\n\n" +
           link + "\n\nThe link works once and expires in " + std::to_string(minutes) +
           " minutes.\n\nIf you did not ask for this, you can ignore this email. Your password will not change.\n"
           "Scam Shield will never ask you for your password by phone or text.\n";
}

void deliverPasswordReset(const MailConfig& cfg, const User& user, const std::string& token) {
    const std::string link = resetLink(cfg, token);
    if (!cfg.enabled()) {
        std::cout << "[dev mode] Password reset link for " << user.email << " (no email provider is set up):\n  " << link
                  << std::endl;
        return;
    }
    const std::string to = user.email;
    const std::string body = resetEmailBody(user.displayName, link, kResetMinutes);
    MailConfig copy = cfg;
    std::thread([copy, to, body]() { sendEmail(copy, to, "Reset your Scam Shield password", body); }).detach();
}

}  // namespace scamshield

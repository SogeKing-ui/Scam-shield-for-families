// Sending password-reset emails.
//
// With SCAMSHIELD_MAIL_API_KEY and SCAMSHIELD_MAIL_FROM set, mail goes out through the Resend HTTP API
// (https://resend.com). Without them the server runs in "dev mode": the reset link is printed in the
// server console instead, so you can test the whole flow without an email account.
#pragma once

#include <string>

#include "store.hpp"

namespace scamshield {

struct MailConfig {
    std::string apiKey;   // SCAMSHIELD_MAIL_API_KEY; never logged
    std::string from;     // SCAMSHIELD_MAIL_FROM, e.g. "Scam Shield <no-reply@yourdomain.com>"
    std::string baseUrl;  // SCAMSHIELD_MAIL_BASE_URL, default https://api.resend.com (override for tests)
    std::string appUrl;   // SCAMSHIELD_APP_URL, where the web app lives, default http://localhost:5173
    bool enabled() const { return !apiKey.empty() && !from.empty(); }
};

MailConfig mailConfigFromEnv();

// Exposed for tests.
std::string resetLink(const MailConfig& cfg, const std::string& token);
std::string resetEmailBody(const std::string& displayName, const std::string& link, int minutes);

// Sends the reset email in the background (so the response time does not reveal whether the address
// has an account). In dev mode, prints the link to the console instead.
void deliverPasswordReset(const MailConfig& cfg, const User& user, const std::string& token);

}  // namespace scamshield

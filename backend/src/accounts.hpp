// HTTP routes for accounts, family links, sharing, and the helper inbox.
#pragma once

#include "http_util.hpp"
#include "mailer.hpp"
#include "store.hpp"

namespace scamshield {

struct AccountsConfig {
    http::Origins origins;
    bool secureCookie = false;  // set true when served over HTTPS
    MailConfig mail;            // how password-reset emails are sent
};

// The signed-in user for this request (from the session cookie), if any.
std::optional<User> currentUser(Store& store, const httplib::Request& req);

void registerAccountRoutes(httplib::Server& svr, Store& store, const AccountsConfig& config);

}  // namespace scamshield

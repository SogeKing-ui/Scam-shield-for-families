// Removes private details before text is sent to any outside service.
#pragma once

#include <string>

namespace scamshield {

// Replaces email addresses with [EMAIL], phone numbers with [PHONE], and other
// long digit sequences (account, card, SSN) with [NUMBER]. Links are left alone
// because they are needed to explain a scam.
//
// Limit: names and addresses cannot be removed reliably. The UI tells people
// not to include them.
std::string redact(const std::string& text);

}  // namespace scamshield

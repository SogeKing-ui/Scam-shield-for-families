// Tests for password hashing, encryption, sessions, family links, and sharing.
#include <iostream>
#include <string>

#include "analyzer.hpp"
#include "crypto.hpp"
#include "json.hpp"
#include "store.hpp"

using namespace scamshield;
using json = nlohmann::json;

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

int main() {
    {  // Password hashing
        std::string h1 = crypto::hashPassword("correct horse battery");
        std::string h2 = crypto::hashPassword("correct horse battery");
        CHECK(h1 != h2);  // random salt
        CHECK(h1.rfind("scrypt$", 0) == 0);
        CHECK(h1.find("correct") == std::string::npos);
        CHECK(crypto::verifyPassword("correct horse battery", h1));
        CHECK(!crypto::verifyPassword("correct horse batterY", h1));
        CHECK(!crypto::verifyPassword("anything", "garbage"));
        CHECK(!crypto::verifyPassword("anything", "scrypt$99$8$1$00$00"));
    }
    std::string key(32, 'k');
    {  // Encryption
        std::string blob = crypto::encrypt(key, "hello private message");
        CHECK(blob.find("hello") == std::string::npos);
        std::string out;
        CHECK(crypto::decrypt(key, blob, &out) && out == "hello private message");
        CHECK(crypto::encrypt(key, "x") != crypto::encrypt(key, "x"));  // fresh nonce each time
        std::string tampered = blob;
        tampered[tampered.size() / 2] = tampered[tampered.size() / 2] == 'a' ? 'b' : 'a';
        CHECK(!crypto::decrypt(key, tampered, &out));
        CHECK(!crypto::decrypt(std::string(32, 'z'), blob, &out));
        CHECK(!crypto::decrypt(key, "zz", &out));
    }
    {  // Codes avoid ambiguous characters
        std::string code = crypto::randomCode(200, "ABC");
        CHECK(code.size() == 200 && code.find_first_not_of("ABC") == std::string::npos);
        CHECK(crypto::randomHex(32).size() == 64);
    }

    Store store(":memory:", key);
    auto mom = store.createUser("mom@example.com", "Mom", "protected", "a long password 1");
    auto kid = store.createUser("kid@example.com", "Jehu", "helper", "another long password");
    auto other = store.createUser("other@example.com", "Stranger", "helper", "yet another password");
    CHECK(mom && kid && other);

    {  // Accounts
        CHECK(!store.createUser("mom@example.com", "Dup", "helper", "a long password 1"));
        CHECK(store.authenticate("mom@example.com", "a long password 1").has_value());
        CHECK(!store.authenticate("mom@example.com", "wrong password"));
        CHECK(!store.authenticate("nobody@example.com", "a long password 1"));
        CHECK(!store.createUser("x@example.com", "X", "admin", "a long password 1"));  // bad role rejected by DB
    }
    {  // Sessions
        std::string tok = store.createSession(mom->id);
        CHECK(tok.size() == 64);
        auto u = store.userForSession(tok);
        CHECK(u && u->id == mom->id && u->role == "protected");
        CHECK(!store.userForSession(std::string(64, 'a')));
        CHECK(!store.userForSession("short"));
        store.deleteSession(tok);
        CHECK(!store.userForSession(tok));
    }
    {  // Linking with an invite code
        std::string code = store.createInvite(mom->id);
        CHECK(code.size() == 9 && code[4] == '-');
        CHECK(!store.acceptInvite(kid->id, "AAAA-AAAA"));
        CHECK(!store.acceptInvite(mom->id, code));  // cannot link to yourself
        auto p = store.acceptInvite(kid->id, "  " + code.substr(0, 4) + code.substr(5) + " ");  // sloppy typing still works
        CHECK(p && p->id == mom->id);
        CHECK(!store.acceptInvite(other->id, code));  // single use
        CHECK(store.areLinked(mom->id, kid->id));
        CHECK(!store.areLinked(mom->id, other->id));
        auto helpers = store.linksFor(*mom);
        CHECK(helpers.size() == 1 && helpers[0].id == kid->id);
        auto people = store.linksFor(*kid);
        CHECK(people.size() == 1 && people[0].id == mom->id);
    }
    {  // Sharing and the inbox
        Result r = analyze("IRS: pay with gift cards now or be arrested. Call 561-555-0142");
        CHECK(!store.shareMessage(mom->id, other->id, "x", r));  // not linked
        auto id = store.shareMessage(mom->id, kid->id, "IRS: pay with gift cards now", r);
        CHECK(id.has_value());
        CHECK(store.unreadCount(kid->id) == 1);
        auto items = store.inbox(kid->id, 50);
        CHECK(items.size() == 1 && items[0].fromName == "Mom" && !items[0].read);
        json payload = json::parse(items[0].payloadJson);
        CHECK(payload["text"] == "IRS: pay with gift cards now");
        CHECK(payload["signals"].size() > 0);
        CHECK(store.inbox(other->id, 50).empty());          // other helpers see nothing
        CHECK(!store.markRead(other->id, *id));             // and cannot touch it
        CHECK(store.markRead(kid->id, *id));
        CHECK(store.unreadCount(kid->id) == 0);
        CHECK(!store.deleteShared(*other, *id));
        CHECK(store.inbox(kid->id, 50).size() == 1);
    }
    {  // Unlinking removes the helper's access to what was shared
        CHECK(store.unlink(*mom, kid->id));
        CHECK(!store.areLinked(mom->id, kid->id));
        CHECK(store.inbox(kid->id, 50).empty());
        CHECK(!store.unlink(*mom, kid->id));
    }
    {  // Deleting an account removes its data
        std::string code = store.createInvite(mom->id);
        store.acceptInvite(kid->id, code);
        auto id = store.shareMessage(mom->id, kid->id, "hello", analyze("hello"));
        CHECK(id.has_value());
        std::string tok = store.createSession(mom->id);
        CHECK(store.deleteAccount(mom->id));
        CHECK(!store.userForSession(tok));
        CHECK(store.inbox(kid->id, 50).empty());
        CHECK(store.linksFor(*kid).empty());
        CHECK(!store.authenticate("mom@example.com", "a long password 1"));
    }

    {  // Password reset: single use, replaces earlier links, signs out everywhere
        Store s3(":memory:", key);
        auto u = s3.createUser("reset@example.com", "Reset Me", "protected", "old password 123");
        CHECK(u.has_value());
        CHECK(!s3.createPasswordReset("nobody@example.com"));  // unknown email: nothing created
        auto r1 = s3.createPasswordReset("reset@example.com");
        CHECK(r1 && r1->token.size() == 64 && r1->user.id == u->id);
        auto r2 = s3.createPasswordReset("reset@example.com");  // a newer request replaces the older link
        CHECK(r2 && r2->token != r1->token);
        CHECK(!s3.resetPassword(r1->token, "brand new password"));
        CHECK(!s3.resetPassword("short", "brand new password"));
        CHECK(!s3.resetPassword(std::string(64, 'a'), "brand new password"));
        std::string session = s3.createSession(u->id);
        CHECK(s3.userForSession(session).has_value());
        auto done = s3.resetPassword(r2->token, "brand new password");
        CHECK(done && done->id == u->id);
        CHECK(!s3.resetPassword(r2->token, "another new password"));  // single use
        CHECK(!s3.userForSession(session));                           // signed out everywhere
        CHECK(s3.authenticate("reset@example.com", "brand new password").has_value());
        CHECK(!s3.authenticate("reset@example.com", "old password 123"));
        auto r3 = s3.createPasswordReset("reset@example.com");
        CHECK(r3 && s3.deleteAccount(u->id));
        CHECK(!s3.resetPassword(r3->token, "brand new password"));  // deleted account's links die with it
    }

    {  // Daily AI limits: per account and overall; failed attempts can be refunded
        Store s2(":memory:", key);
        auto a = s2.createUser("a@example.com", "A", "helper", "a long password 1");
        auto b = s2.createUser("b@example.com", "B", "helper", "a long password 2");
        CHECK(a && b);
        CHECK(s2.aiRemaining(a->id, 2) == 2);
        CHECK(s2.useAi(a->id, 2, 3) == AiQuota::Ok);
        CHECK(s2.useAi(a->id, 2, 3) == AiQuota::Ok);
        CHECK(s2.useAi(a->id, 2, 3) == AiQuota::UserLimit);
        CHECK(s2.aiRemaining(a->id, 2) == 0);
        CHECK(s2.useAi(b->id, 2, 3) == AiQuota::Ok);           // overall total is now 3
        CHECK(s2.useAi(b->id, 2, 3) == AiQuota::GlobalLimit);  // app-wide cap reached
        s2.refundAi(b->id);
        CHECK(s2.useAi(b->id, 2, 3) == AiQuota::Ok);
        CHECK(s2.aiRemaining(b->id, 2) == 1);
        CHECK(s2.useAi(a->id, 0, 3) == AiQuota::UserLimit);    // a cap of 0 switches AI off
    }

    std::cout << (checks - failures) << "/" << checks << " checks passed" << std::endl;
    return failures == 0 ? 0 : 1;
}

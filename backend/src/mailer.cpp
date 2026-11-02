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
std::string verifyLink(const MailConfig& cfg, const std::string& token) { return cfg.appUrl + "/#verify=" + token; }

std::string mailLang(const std::string& requested) { return isSupportedLanguage(requested) ? requested : "en"; }

// The Spanish and Haitian Creole texts should be reviewed by native speakers before real users see them.
std::string resetEmailSubject(const std::string& lang) {
    if (lang == "es") return "Restablece tu contraseña de Scam Shield";
    if (lang == "ht") return "Chanje modpas Scam Shield ou";
    return "Reset your Scam Shield password";
}

std::string resetEmailBody(const std::string& lang, const std::string& name, const std::string& link, int minutes) {
    const std::string n = std::to_string(minutes);
    if (lang == "es") {
        return "Hola " + name +
               ",\n\nAlguien pidió restablecer la contraseña de tu cuenta de Scam Shield. "
               "Para elegir una contraseña nueva, abre este enlace:\n\n" +
               link + "\n\nEl enlace funciona una sola vez y caduca en " + n +
               " minutos.\n\nSi tú no lo pediste, puedes ignorar este correo. Tu contraseña no cambiará.\n"
               "Scam Shield nunca te pedirá tu contraseña por teléfono ni por mensaje de texto.\n";
    }
    if (lang == "ht") {
        return "Bonjou " + name +
               ",\n\nYon moun mande pou chanje modpas kont Scam Shield ou an. "
               "Pou chwazi yon nouvo modpas, louvri lyen sa a:\n\n" +
               link + "\n\nLyen an mache yon sèl fwa, epi li ekspire apre " + n +
               " minit.\n\nSi se pa ou ki mande sa, ou ka inyore imèl sa a. Modpas ou p ap chanje.\n"
               "Scam Shield pa janm ap mande w modpas ou nan telefòn oswa nan mesaj tèks.\n";
    }
    return "Hello " + name +
           ",\n\nSomeone asked to reset the password for your Scam Shield account. "
           "To choose a new password, open this link:\n\n" +
           link + "\n\nThe link works once and expires in " + n +
           " minutes.\n\nIf you did not ask for this, you can ignore this email. Your password will not change.\n"
           "Scam Shield will never ask you for your password by phone or text.\n";
}

std::string verifyEmailSubject(const std::string& lang) {
    if (lang == "es") return "Confirma tu correo para Scam Shield";
    if (lang == "ht") return "Konfime imèl ou pou Scam Shield";
    return "Confirm your email for Scam Shield";
}

std::string verifyEmailBody(const std::string& lang, const std::string& name, const std::string& link, int hours) {
    const std::string h = std::to_string(hours);
    if (lang == "es") {
        return "Hola " + name +
               ",\n\nBienvenido a Scam Shield. Por favor confirma que este es tu correo abriendo este enlace:\n\n" +
               link + "\n\nEl enlace caduca en " + h +
               " horas. Si no creaste una cuenta, puedes ignorar este correo.\n";
    }
    if (lang == "ht") {
        return "Bonjou " + name +
               ",\n\nByenveni nan Scam Shield. Tanpri konfime se imèl ou sa a lè w louvri lyen sa a:\n\n" + link +
               "\n\nLyen an ekspire apre " + h + " è. Si se pa ou ki te kreye yon kont, ou ka inyore imèl sa a.\n";
    }
    return "Hello " + name +
           ",\n\nWelcome to Scam Shield. Please confirm this is your email address by opening this link:\n\n" + link +
           "\n\nThe link expires in " + h + " hours. If you did not create an account, you can ignore this email.\n";
}

namespace {
void deliver(const MailConfig& cfg, const User& user, const std::string& what, const std::string& link,
             const std::string& subject, const std::string& body) {
    if (!cfg.enabled()) {
        std::cout << "[dev mode] " << what << " link for " << user.email << " (no email provider is set up):\n  " << link
                  << std::endl;
        return;
    }
    const std::string to = user.email;
    MailConfig copy = cfg;
    std::thread([copy, to, subject, body]() { sendEmail(copy, to, subject, body); }).detach();
}
}  // namespace

void deliverPasswordReset(const MailConfig& cfg, const User& user, const std::string& token, const std::string& lang) {
    const std::string l = mailLang(lang);
    const std::string link = resetLink(cfg, token);
    deliver(cfg, user, "Password reset", link, resetEmailSubject(l),
            resetEmailBody(l, user.displayName, link, kResetMinutes));
}

void deliverEmailVerification(const MailConfig& cfg, const User& user, const std::string& token, const std::string& lang) {
    const std::string l = mailLang(lang);
    const std::string link = verifyLink(cfg, token);
    deliver(cfg, user, "Email confirmation", link, verifyEmailSubject(l),
            verifyEmailBody(l, user.displayName, link, kVerifyHours));
}

}  // namespace scamshield

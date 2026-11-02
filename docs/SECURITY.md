# Security notes

Scam Shield handles messages that may contain names, account numbers, and other private details, so security is part of the design, not an add-on.

## What is protected

- The text of messages people paste in.
- Later: accounts, message history, and the link between a person and their family helper.

## Who we worry about

- A scammer trying to abuse the tool (probing it to learn which wording evades detection, or flooding it).
- Someone on the same network reading traffic.
- Someone who gets hold of the server or a backup.
- Mistakes of our own, like logging a private message or sending too much to a third-party AI service.

## Done in this prototype

- Server binds to `127.0.0.1` only (override with `SCAMSHIELD_HOST` on purpose).
- Message text is not written to disk or logs.
- Request body capped at 16 KB; messages capped at 5000 characters; read/write timeouts set.
- Per-client rate limit (30 requests per minute).
- Strict JSON validation; bad input returns a clear 400/413 and never crashes the server (a 200,000-character input is covered by a test).
- No regular expressions on user input (avoids ReDoS and stack-overflow issues); matching is simple scanning.
- Response headers: `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, restrictive `Content-Security-Policy`.
- CORS allows only the configured frontend origin (`SCAMSHIELD_ORIGIN`).
- React escapes all output; links found in messages are shown as text, never as clickable links.

## To do before real users

- [ ] HTTPS everywhere (reverse proxy such as Caddy or nginx in front of the server).
- [ ] Accounts: password hashing with Argon2id (libsodium), sessions or short-lived JWTs, role checks on every route.
- [ ] Encrypt stored messages at rest; per-user keys; delete-my-data endpoint.
- [ ] Redact names, phone numbers, and account numbers before any text goes to an AI API; get consent first; check the provider's retention policy.
- [ ] Treat the AI explanation as untrusted text: message content can try to "prompt inject" the model. Never let model output trigger actions.
- [ ] Keep API keys in environment variables, never in the repo (`.env` is gitignored).
- [ ] Rate limiting by account as well as address; do not trust `X-Forwarded-For` unless behind your own proxy.
- [ ] Dependency checks (`npm audit`, update the vendored headers) and a fuzz test for the analyzer.
- [ ] Short write-up of known limits so people do not over-trust a "low" result.

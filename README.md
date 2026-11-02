# Scam Shield for Families

Seniors and immigrant communities lose a lot of money to phishing texts, fake bank calls, and payment scams. Scam Shield lets someone paste a suspicious message and get a plain-language answer: is this likely a scam, and why?

**Status:** working prototype. Detection, AI explanations, and the family-helper flow (accounts, linking, sharing, helper inbox) work end to end.

## How it works

| Layer | Tech | Job |
|-------|------|-----|
| Analyzer + API | C++17 | Parses messages, extracts links and phone numbers, scores scam signals, serves a small JSON API |
| Frontend | React + Vite | Large-text "paste it here" screen with clear reasons and next steps |
| AI | Claude API (called from the C++ server) | Plain-language explanations in English, Spanish, and Haitian Creole |
| Accounts | SQLite + OpenSSL, in the C++ server | Sign-in, family links, shared messages stored encrypted |

The analyzer looks for things like pressure to act fast, threats, requests for gift cards or crypto, requests for codes or passwords, secrecy, look-alike links (`paypa1-secure-login.com`), shortened links, and "family emergency" scripts. It includes starter phrases in English, Spanish, and Haitian Creole.

## Run it

You need a C++17 compiler (Xcode command line tools on a Mac) and Node 18+.

```bash
# 1. Backend (terminal 1)
brew install openssl@3                # Mac, one time: needed for HTTPS, password hashing, and encryption
export ANTHROPIC_API_KEY="your-key"   # optional: without it you get built-in explanations
cd backend
make test     # run the unit tests
make api-test # end-to-end test of accounts, sharing, and security checks
make run      # starts the API on http://127.0.0.1:8080

# 2. Frontend (terminal 2)
cd frontend
npm install
npm run dev   # opens on http://localhost:5173
```

API example:

```bash
curl -X POST http://127.0.0.1:8080/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"Your account is suspended. Click http://bit.ly/abc and send a gift card."}'
```

## Family helpers

Checking a message never needs an account. Accounts add a safe way for a person and someone they trust to work together:

1. The person being protected and the helper each create an account (choosing their role).
2. The person taps **Invite a helper** and gives the one-time code (valid 24 hours) to the helper, who enters it under **Family**.
3. After checking a message, the person can tap **Send to (helper name)**. Nothing is shared unless they press that button.
4. The helper sees it under **Family** with the verdict, the reasons, and the links and numbers to avoid.

Either side can remove the link at any time, which deletes what was shared. Anyone can delete their account and all of its data.

### Forgot password

On the sign-in page, **Forgot your password?** asks for an email and always shows the same message, whether or not an account exists. If it does, a link is sent that works once for 30 minutes; choosing a new password signs the account out on every device. Asking again replaces the older link, and each address can request at most 3 per hour.

- **Trying it locally (no email account needed):** with nothing configured, the link is printed in the terminal where `make run` is running (look for `[dev mode]`). Copy it into your browser.
- **Sending real email:** create a [Resend](https://resend.com) account, verify a sending domain, and set `SCAMSHIELD_MAIL_API_KEY`, `SCAMSHIELD_MAIL_FROM` (for example `Scam Shield <no-reply@yourdomain.com>`), and `SCAMSHIELD_APP_URL` (the public address of the web app, used in the link). Keep the key in an environment variable, never in the repo.

Settings (environment variables): `SCAMSHIELD_DB` (database path, default `backend/scamshield.db`), `SCAMSHIELD_DATA_KEY` (64 hex characters; otherwise a key file is created next to the database), `SCAMSHIELD_ORIGIN`, `SCAMSHIELD_COOKIE_SECURE=1` (when served over HTTPS).

## AI explanations

Click **Explain with AI** under a result. The server removes phone numbers, emails, and long numbers, then asks Claude for a short explanation in the chosen language. The message is only sent after that click (the request must include `"consent": true`).

- **Cost controls:** AI explanations need a signed-in account (anonymous visitors get the free built-in explanation). Each account gets 5 per day and the whole app gets 200 per day (UTC days, saved in the database so a restart does not reset them). Change them with `SCAMSHIELD_AI_USER_CAP` and `SCAMSHIELD_AI_DAILY_CAP`; a cap of 0 turns AI off. A repeated message (same text, language) is answered from a cache at no cost, and a failed API call is not counted.
- Also keep a low prepaid balance and no auto-reload on your Anthropic account, and use a separate key for this project. That is the real backstop.
- No `ANTHROPIC_API_KEY`, no OpenSSL, or the API is unreachable: the built-in English explanation is used and the UI says so.
- `SCAMSHIELD_MODEL` changes the model (default `claude-haiku-5-5`).
- The key is read from the environment only. Never put it in a file in this repo.
- `make run` prints whether Claude is enabled at startup.

## How well does it work?

Measured with `tools/evaluate.py` on two public datasets (kept in `data/`, which is not committed):

| Dataset | Result (current rules) | Before the dataset-driven update |
|---------|------------------------|----------------------------------|
| Smishtank, 1,062 real US phishing texts | 45% flagged medium or higher, 17% high | 27% / 5% |
| SpaPhish, 731 phishing + 664 legitimate Spanish emails | catches 51% of phishing, wrongly flags 9% of legitimate | 19% / 8% |

How to read this: these are honest first numbers, not a finished detector.
- The rules were improved by studying these same datasets, so the numbers are optimistic. The next step is testing on new, unseen messages.
- Smishtank has only scam messages, so it cannot measure false alarms on English texts. SpaPhish is email, not SMS.
- Nothing public was found for Haitian Creole. Creole rules are a small starter set and need review by a native speaker.

```bash
cd backend && make scorer && cd ..
python3 tools/evaluate.py
```

Data sources (see `data/README.md`):
- Smishtank dataset (Timko and Rahman, [arXiv:2402.18430](https://arxiv.org/abs/2402.18430), [smishtank.com](https://smishtank.com)).
- SpaPhish: Spanish phishing and legitimate email dataset, CC BY 4.0 ([Mendeley Data](https://data.mendeley.com/datasets/hz2d6gz7pc)).

## Project layout

```
backend/
  src/analyzer.*      scoring engine (standard library only)
  src/redact.*        removes private details before text leaves the server
  src/explainer.*     Claude call + built-in fallback
  src/store.*         accounts, sessions, links, shared messages (SQLite)
  src/crypto.*        scrypt password hashing, AES-256-GCM encryption
  src/accounts.*      account and family API routes
  src/mailer.*        password-reset email (Resend API, or console in dev mode)
  src/main.cpp        HTTP server, security headers, analyze/explain routes
  tests/              unit tests (make test)
  third_party/        cpp-httplib and nlohmann/json (single headers, MIT)
frontend/             React app (Vite)
tools/                evaluation script and helper (tools/evaluate.py)
data/                 public datasets for evaluation (not committed)
docs/SECURITY.md      threat model and security checklist
```

## Roadmap

1. Collect real examples from family and friends (with permission, names removed) and test on messages the rules have never seen.
2. Native-speaker review and more Haitian Creole and Spanish phrases, plus a language toggle in the UI.
3. Have Haitian Creole and Spanish speakers review the AI explanations; add a Creole/Spanish interface.
4. Email or text alerts to the helper when something is shared, a helper-to-person reply, and email verification at sign-up.
5. HTTPS deployment, then the remaining items in `docs/SECURITY.md`.
6. Screenshot input (OCR).

## Limits

Scam Shield looks for known warning signs and can be wrong in both directions. A "low" result means no strong signs were found, not that a message is safe.

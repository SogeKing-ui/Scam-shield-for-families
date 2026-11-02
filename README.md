# Scam Shield for Families

Seniors and immigrant communities lose a lot of money to phishing texts, fake bank calls, and payment scams. Scam Shield lets someone paste a suspicious message and get a plain-language answer: is this likely a scam, and why?

**Status:** early prototype. Detection, the paste-and-check screen, and AI explanations work end to end.

## How it works

| Layer | Tech | Job |
|-------|------|-----|
| Analyzer + API | C++17 | Parses messages, extracts links and phone numbers, scores scam signals, serves a small JSON API |
| Frontend | React + Vite | Large-text "paste it here" screen with clear reasons and next steps |
| AI | Claude API (called from the C++ server) | Plain-language explanations in English, Spanish, and Haitian Creole |

The analyzer looks for things like pressure to act fast, threats, requests for gift cards or crypto, requests for codes or passwords, secrecy, look-alike links (`paypa1-secure-login.com`), shortened links, and "family emergency" scripts. It includes starter phrases in English, Spanish, and Haitian Creole.

## Run it

You need a C++17 compiler (Xcode command line tools on a Mac) and Node 18+.

```bash
# 1. Backend (terminal 1)
brew install openssl                  # Mac, one time: needed to call the Claude API
export ANTHROPIC_API_KEY="your-key"   # optional: without it you get built-in explanations
cd backend
make test     # run the unit tests
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

## AI explanations

Click **Explain with AI** under a result. The server removes phone numbers, emails, and long numbers, then asks Claude for a short explanation in the chosen language. The message is only sent after that click (the request must include `"consent": true`).

- No `ANTHROPIC_API_KEY`, no OpenSSL, or the API is unreachable: the built-in English explanation is used and the UI says so.
- `SCAMSHIELD_MODEL` changes the model (default `claude-haiku-5-5`).
- The key is read from the environment only. Never put it in a file in this repo.
- `make run` prints whether Claude is enabled at startup.

## Project layout

```
backend/
  src/analyzer.*      scoring engine (standard library only)
  src/redact.*        removes private details before text leaves the server
  src/explainer.*     Claude call + built-in fallback
  src/main.cpp        HTTP server, rate limiting, security headers
  tests/              unit tests (make test)
  third_party/        cpp-httplib and nlohmann/json (single headers, MIT)
frontend/             React app (Vite)
docs/SECURITY.md      threat model and security checklist
```

## Roadmap

1. Collect real examples from family and friends (with permission, names removed) and turn them into test cases.
2. Add more Haitian Creole and Spanish phrases and a language toggle in the UI.
3. Have Haitian Creole and Spanish speakers review the AI explanations; add a Creole/Spanish interface.
4. Accounts with two roles: the person being protected and a trusted family helper who sees flagged messages.
5. Encrypted storage for history, plus consent controls and delete-my-data.
6. Screenshot input (OCR).

## Limits

Scam Shield looks for known warning signs and can be wrong in both directions. A "low" result means no strong signs were found, not that a message is safe.

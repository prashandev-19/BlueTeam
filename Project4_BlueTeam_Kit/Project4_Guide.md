# Project 4 - Blue Team: Guardrails, Hardening and Detection

This kit defends the Project 3 app. Same model, same 5 attacks, so the before/after numbers are a fair comparison.

| File | What it does |
|---|---|
| `guardrails.py`, `rails/` | NeMo Guardrails: 1 input rail + 2 output rails (JWT regex, internal-ID redaction). Checks are plain regex in Python. |
| `crypto_identity.py`, `gen_keys.py`, `tamper_test.py` | Ed25519 key pair, sign / verify, tampered-message test |
| `detect.py` | Anomaly detection: volume spike, scope change, expired-token reuse |
| `defended.py` | The hardened app: rails + signed messages + signed knowledge base + MCP argument policy + monitor |
| `run_defended.py` | Re-runs all Project 3 attacks on the hardened app and prints the before/after table |
| `guard_demo.py`, `jwt_redact_demo.py`, `fp_test.py` | Screenshot demos (no model calls needed) |
| `auth0/` | Refresh-token rotation test + risk-based login Action (for your Auth0 tenant / Project 2 folder) |

## 1. Setup (in a Python venv, as the brief says)
Windows PowerShell:
```
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```
Codespaces / Linux: `python -m venv venv && source venv/bin/activate && pip install -r requirements.txt && cp .env.example .env`
- Edit `.env`: same `LLM_API_KEY` and `LLM_MODEL` as Project 3. Save it as **UTF-8**.
- Copy **`results.json` from your Project 3 folder** into this folder. It holds the "before" numbers.
- The NeMo install downloads many packages (a few minutes). If it fails on your laptop, do this part in Codespaces.

## 2. The 8 screenshots
| # | Brief asks for | Do this |
|---|---|---|
| 1 | Guardrail blocking 3+ attack payloads, status and reason | `python guard_demo.py` |
| 2 | JWT regex output guardrail, credential replaced by [REDACTED] | `python jwt_redact_demo.py` |
| 3 | Ed25519 key pair, both key files | `python gen_keys.py` |
| 4 | Tampered message rejected, clear error log | `python tamper_test.py` |
| 5 | Auth0 dashboard: TTL 300 s + refresh token rotation ON | Section 3 (a, b). Two dashboard shots, paste both on one page. |
| 6 | Old refresh token replay returns an error | Section 3 (c, d): `python refresh_rotation_test.py` |
| 7 | Anomaly alert firing | `python detect.py replay` |
| 8 | Before/after table for all 5 attacks | `python run_defended.py` (bottom of the output) |

Also needed by the brief (add as extra pages in your Word file): `python fp_test.py` (false positive test on 10 legitimate inputs) and a screenshot of a blocked risky login (section 3 e).
Optional proof that the output rail works on a real model leak: `python run_defended.py --output-rail-only` (input rail switched off).
Logs for your ZIP: `defended_log.txt`, `alerts.log`, `security.log`.

## 3. Auth0 hardening (about 15 minutes)
**a) Token TTL 300 s.** Dashboard > Applications > APIs > SecureNova API > Settings. Set **Token Expiration (Seconds)** = 300 and **Implicit/Hybrid Flow Token Expiration** = 300. Turn **Allow Offline Access** ON. Save. (Your Project 2 `rotation_test.py` waits 65 s, so it only matches a 60 s TTL. You do not need to rerun it.)

**b) Refresh token rotation.** Dashboard > Applications > your Regular Web App > Settings > **Refresh Token Rotation**: Rotation ON, Reuse Interval Leeway 0. Save. Also check Advanced Settings > Grant Types has **Refresh Token** ticked.

**c) Get a refresh token.** In your Project 2 `pkce_login.py`, change only the scope line to:
```
"scope": "openid profile email offline_access read:ai-data",
```
Log in again (`python pkce_login.py`). `tokens.json` now has a `refresh_token`.

**d) Test rotation.** Copy `auth0/refresh_rotation_test.py` into the Project 2 folder and run `python refresh_rotation_test.py`. It uses the refresh token once (new tokens issued), then replays the old one (error `invalid_grant`). Screenshot 6. Run `pkce_login.py` again before repeating the test.

**e) Risk-based login block (Auth0 Action).** Dashboard > Actions > Library > Build Custom > name `Risk Login Block`, trigger **Login / Post Login**, paste `auth0/risk_action.js`, Deploy. Then Actions > Triggers > post-login flow: drag the Action between Start and Complete, Apply.
Test: User Management > Users > Create User `fraud.test@mailinator.com` with any password, then run `pkce_login.py` and log in as that user. The login is refused (`access_denied`, "Login blocked by risk policy ... disposable e-mail domain"). Your normal test user still works.

## 4. How it works (viva)
- **NeMo Guardrails** runs "rails" around the model: an *input rail* before the prompt reaches the model and *output rails* before the reply reaches the user. Rails are written in `rails/rails.co` and call Python functions in `guardrails.py`. No extra model calls are used, so they are fast and free.
- **Input rail** = regex rules (override phrases, fake `SYSTEM:` text, credential-request wording, prompt-extraction wording, role play, role elevation, tool-call text). It scans the user text AND the retrieved documents.
- **JWT output rail** = regex for JWT-shaped strings (`eyJ...`) and their base64 form (`ZXlK...`). The match is replaced by `[REDACTED]`. A second output rail hides internal ids.
- **Ed25519 identity binding:** the orchestrator signs `{from, text}` with its private key. Agent B checks the signature with the public key BEFORE the model sees the message. Forged `FROM` lines and tampered text fail. Zero trust: "do not trust a claimed identity, verify it".
- **Signed knowledge base:** only chunks signed by the orchestrator are accepted, so a poisoned chunk never reaches retrieval. This also defeats poison that looks like normal text (the false-policy chunk), which no text rule can detect.
- **MCP argument policy:** second layer. Even if a bad tool call reaches the server, refunds above 50 or to a stranger are denied.
- **Monitoring:** `detect.py` raises 3 alerts (volume > 20 requests in 60 s, scope change between consecutive requests, expired token reuse), each with timestamp, identity and event type. `replay` feeds it events that represent the Project 3 attacks. `defended.py` also records every real model call.
- **Auth0:** 300 s access token; rotating refresh token (reusing an old one fails, and Auth0 then revokes the new one too); an Action denies risky logins.

## 5. Be honest about limits (examiners like this)
- Regex rules are **tuned to the Project 3 payloads**. A rephrased attack can get past them, so the input rail is one layer, not the fix. The false positive rate of 0% is measured on 10 simple inputs only. A real customer who writes "I never got my reset token, please send it again" would be blocked.
- Signatures prove WHO sent a message, not that the content is wise. They do not stop a replay of an old valid message (add a timestamp and a one-time number as a next step). Keys are stored in files here; production would use a key vault.
- The model is random, so rates come from only a few trials. The result, not the exact percentage, is what matters.
- If a number in your table is not 0% after, say why (for example "the output rail redacted it").

# buns

AI-assisted security assessment platform for web applications. buns runs OWASP ZAP and a set of controlled cURL probes against an authorised target, has a language model (DeepSeek) explain and rate each result, and requires a human assessor to confirm or reject every finding against the raw HTTP evidence before it can appear in the PDF report.

Built for CS24-4755 by Agsoy, Alves and Morales. The assessed application is [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) running in a local container.

```
React + Vite  ──>  FastAPI ──> scope check ──> OWASP ZAP (spider, passive, active)
  dashboard          │                    └──> cURL probes (WSTG test cases)
  review screen      │
  reports            ├──> SQLite (targets, scans, endpoints, findings, decisions)
                     ├──> sanitiser ──> DeepSeek API (analysis, remediation)
                     └──> ReportLab PDF (confirmed findings only)
```

## Run it

You need Docker Desktop (or Docker Engine with Compose v2).

```bash
cp .env.example .env          # optional: add DEEPSEEK_API_KEY
docker compose up -d --build
```

Then open <http://localhost:8000>.

The first start pulls Juice Shop and ZAP and takes a few minutes. ZAP needs about 30 seconds after its container starts before it accepts API calls; the left rail shows "ZAP 2.x" once it is connected.

The Juice Shop target is registered automatically, with the scope from the proposal and Juice Shop's built-in test account `jim@juice-sh.op`. Inside Compose it is addressed as `http://juice-shop:3000`, which is the same container you reach at `http://localhost:3000` from your browser.

To stop: `docker compose down`. Add `-v` to also delete the database and generated reports.

## Run it without Docker

The `portable/` folder sets up the whole lab inside the project folder: Python, Node.js, a Java runtime, OWASP ZAP and OWASP Juice Shop are downloaded into `portable/runtime`. Nothing is installed system-wide and no administrator rights are needed. It needs about 1.5 GB of disk and an internet connection the first time.

**Windows 10 or 11.** Double-click, or run from a terminal in the project folder:

```bat
setup-portable.cmd
start-portable.cmd
stop-portable.cmd
```

Setup runs once and takes 10 to 20 minutes, mostly downloading. Start launches Juice Shop, ZAP and buns and opens the browser. Stop shuts all three down.

**Linux or macOS:**

```bash
./portable/setup.sh
./portable/start.sh
./portable/stop.sh
```

Juice Shop is then at `http://localhost:3000` (the URL in the proposal) and buns at `http://localhost:8000`. The services keep running after you close the window, until you run stop. Logs are in `portable/logs`, and the database and reports in `portable/data`.

- `.env` in the project folder is read the same way as with Docker, so put `DEEPSEEK_API_KEY` there.
- `setup ... -NoZap` (Windows) or `--no-zap` (Linux/macOS) skips ZAP and Java, saving about 600 MB; scans then run the cURL probes only.
- **Offline machines:** run setup once on a connected computer with the same operating system, then copy the whole project folder. Everything it needs is inside.
- After `git pull`, just run start again: it notices that the interface code changed and rebuilds it (about a minute). Python package changes still need setup to be run again.
- Versions are pinned in `portable/versions.env`. Downloads are cached in `portable/cache`, so re-running setup is quick.
- Intel Macs: Juice Shop publishes no prebuilt package for them, so setup skips it; run Juice Shop another way on port 3000.
- If Windows shows a firewall prompt for Node.js, you can cancel it; everything is used from this computer only.
- Keep the project folder path short on Windows (under about 45 characters, e.g. `C:\buns`): Juice Shop contains very deep paths and Windows limits paths to 260 characters.

### Without a DeepSeek key

If `DEEPSEEK_API_KEY` is empty, buns uses a built-in rules engine that maps each finding's CWE to a written explanation, CVSS vector and Express fix. The interface and the report label this as "Built-in rules" / `offline-rules`, never as model output. It lets the platform be demonstrated offline; the proposal's AI functions need the key.

## A first assessment

1. **Targets.** Open *OWASP Juice Shop (local lab)*. Check the scope. Use *Check whether a URL may be requested* to show that `http://example.com/` or `http://juice-shop:3000/socket.io/` is blocked.
2. **New scan.** Leave all four categories selected. Active scan takes roughly 5 to 15 minutes on Juice Shop depending on the machine; untick it for a quick run (spider, passive scan and cURL probes only, about one minute).
3. **Scan view.** Watch the phases and the activity log. Every request the probes send is listed with its status code.
4. **Findings.** When the scan finishes, findings are analysed in the background. Open the first one.
5. **Review.** Left: the request and response, with the payload and matched evidence highlighted. Right: the explanation, false-positive judgement and CVSS breakdown. *Sent for analysis* shows exactly what left the platform, after redaction. Enter your name, keep or change the severity, and confirm or reject. Changing the severity or rejecting requires a note.
6. **Remediation** is generated as soon as a finding is confirmed and appears under the analysis. Keyboard: `C` confirm, `X` reject, `J`/`K` next/previous.
7. **Alerts.** While the scan ran, the bell lit up for each critical finding. Open it to see what was sent and to which channels; add a Discord or email channel under **Settings** and press **Send test**.
8. **Reports.** Generate the PDF. It contains confirmed findings only; rejected ones are listed in an appendix with the reason.

## Alerts: telling the owner when something breaks

A finding sitting in a dashboard helps no one until the person responsible knows about it. buns raises an alert at each of these moments:

| Event | When |
| --- | --- |
| Serious finding detected | Analysis rates a new finding critical or high (once per finding) |
| Scan analysed | Every finding of a scan has been analysed: one summary with the breakdown |
| Scan failed | A scan stopped before finishing |
| Finding confirmed | An assessor verified a vulnerability |
| Report generated | A PDF report is ready |

Every alert appears in the bell at the top right, as a toast, and as a desktop notification if you allow it in the browser. It is also listed on the **Alerts** page with the delivery status per channel.

To reach people outside the app, add channels under **Settings**: Discord, email, Telegram, Slack, or a generic JSON webhook (n8n, Zapier, your own service). Each channel picks its events, a minimum severity and optionally one target, and has a **Send test** button. Email needs the `SMTP_*` settings in `.env`; an email channel can also copy the **system owner** recorded on each target, so the person who owns the application hears about their own system.

Alerts contain only the title, endpoint, severity and a link back to buns. Request and response evidence, payloads and credentials never leave the platform, and tool text goes through the same sanitiser as the AI calls. A failed delivery (wrong webhook URL, SMTP down) is recorded with its error and never interrupts a scan. Code: `backend/app/notifier.py`.

## How the proposal maps to the code

| Proposal objective | Where |
| --- | --- |
| 1. ZAP and cURL integration, crawling, passive/active scanning, evidence gathering | `backend/app/tools/zap.py`, `tools/curl.py`, `tools/probes.py`, `scanner.py` |
| 2. AI interpretation with CVSS-aligned severity | `backend/app/ai/engine.py` (`analyse_finding`), prompts in `ai/prompts.py`, score in `cvss.py` |
| 3. AI remediation generator | `ai/engine.py` (`remediate_finding`), triggered on confirmation |
| 4. Verification interface, evidence side by side | `frontend/src/pages/Review.tsx`, `POST /api/findings/{id}/review` |
| 5. PDF report | `backend/app/report.py` |
| Alerts to the system owner | `backend/app/notifier.py`, `frontend/src/components/Bell.tsx`, `frontend/src/pages/Settings.tsx` |
| Scope register and enforcement | `backend/app/scope.py`, `Target` in `models.py` |
| AI data protection (sanitisation) | `backend/app/sanitize.py` |
| OWASP Top 10 / WSTG mapping | `backend/app/taxonomy.py` |

## What the cURL probes test

Each probe is a single request or a short fixed burst, checked against the scope before it is sent.

| Category | Probe | WSTG |
| --- | --- | --- |
| Information disclosure | Security headers, CORS, version banners on `/` | INFO-02, CONF-12 |
| | `robots.txt` entries | INFO-05 |
| | Directory listing at `/ftp` | CONF-04 |
| | Stack trace on an unknown API route | ERRH-01 |
| Injection | Single quote in `/rest/products/search?q=` returns a SQL error | INPV-05 |
| | Search term reflected unencoded in HTML | INPV-01 |
| Authentication | `' OR 1=1--` in the login email field returns a token | INPV-05 / ATHN-04 |
| | Six failed logins for one account, checking for 429 or lockout | ATHN-03 |
| | Registration with the password `123` | ATHN-07 |
| Access control | `/api/Users` without a session and with a customer session | ATHZ-02 |
| | Customer session reading another customer's basket (IDOR) | ATHZ-04 |

The password-policy probe creates one account with a random `@example.test` address in Juice Shop. Restarting the Juice Shop container resets its database.

Juice Shop is an Angular single-page app, so ZAP's spider sees the HTML shell but not the JSON API. Before the active scan, buns sends a few read-only API requests (product search, a failed login, a product lookup) through ZAP so those endpoints and their parameters are attacked too (`ZAP_SEEDS` in `scanner.py`). ZAP alerts are grouped: a passive issue seen on many URLs, such as a missing header, becomes one finding listing every affected URL; an active issue becomes one finding per endpoint and parameter. When ZAP and a cURL probe report the same flaw on the same endpoint, the probe's finding is kept because its evidence shows the exploit working.

ZAP's active scan runs with a policy containing only the scan rules for the selected categories (`ZAP_ACTIVE_SCANNERS` in `taxonomy.py`). ZAP alerts on URLs outside the scope are discarded.

## Safety controls

- **Allow-list.** A target can only be registered on a host in `BUNS_ALLOWED_HOSTS` (by default the Juice Shop container and loopback). The check is repeated when a scan starts.
- **Scope on every request.** `scope.check` runs before each cURL request; ZAP gets an equivalent context with include and exclude regexes, and spider and scanner exclusions.
- **No shell.** cURL runs as a subprocess with an argument list, no redirect following, and a timeout.
- **Sanitisation before AI.** Authorization, Cookie, Set-Cookie and token headers, JWTs, bearer tokens, password and secret fields, email addresses, password hashes, card numbers (Luhn-checked) and non-loopback IPs are replaced with typed placeholders. Each finding stores the exact payload that was sent and the redaction counts.
- **Computed scores.** The model proposes a CVSS vector; buns validates it and computes the score itself.
- **Human gate.** Only confirmed findings get remediation or go into the report. Every decision records the assessor, time and note.
- **Local binding.** All published ports bind to `127.0.0.1`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEEPSEEK_API_KEY` | empty | Enables the DeepSeek model. Empty means built-in rules. |
| `DEEPSEEK_MODEL` | `deepseek-chat` | Model name. |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | API endpoint. |
| `ZAP_URL` | `http://localhost:8080` | ZAP daemon API. |
| `ZAP_API_KEY` | empty | Must match the key ZAP was started with. |
| `ZAP_TIMEOUT_S` | `900` | Limit for spider and active scan, each. |
| `BUNS_ALLOWED_HOSTS` | `localhost,127.0.0.1,juice-shop` | Hosts a target may use. |
| `BUNS_SEED_TARGET` | empty | Registers Juice Shop at this URL on first start. |
| `BUNS_DATABASE_URL` | `sqlite:///./data/buns.db` | SQLAlchemy URL. |
| `BUNS_AI_CONCURRENCY` | `3` | Parallel AI calls. |
| `BUNS_PUBLIC_URL` | `http://localhost:8000` | Base of the links inside alerts. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | empty, `587`, `starttls` | Email alerts. `SMTP_SECURITY` is `starttls`, `ssl` or `none`. |

## Development

Back end (Python 3.11+, `curl` on the PATH):

```bash
cd backend
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
BUNS_SEED_TARGET=http://localhost:3000 uvicorn app.main:app --reload
```

Front end (Node 20+), in a second terminal:

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173, proxies /api to :8000
```

Juice Shop alone: `docker compose up -d juice-shop`. For ZAP in this mode, run ZAP on the host as well (ZAP in a container cannot reach `localhost:3000` on your machine); otherwise scans run the cURL probes only and say so in the log.

### Tests

```bash
cd backend
pytest
```

The suite covers scope rules, the sanitiser, CVSS scoring against reference vectors, ZAP alert normalisation, the DeepSeek client (mocked transport) and a full run of the platform: it starts a small stand-in for Juice Shop (`tests/fake_juice_shop.py`) that reproduces the responses the probes look for, runs a scan with the real `curl` binary, waits for analysis, records decisions, and checks that the generated PDF does not contain the test account's email or password.

## Layout

```
backend/
  app/
    main.py          API routes
    models.py        Target, Scan, Endpoint, Finding, Report
    scanner.py       scan orchestration (background thread per scan)
    scope.py         scope rules
    sanitize.py      redaction before AI calls
    cvss.py          CVSS v3.1 base score
    taxonomy.py      CWE to category, OWASP Top 10 and WSTG
    report.py        PDF report
    notifier.py      alerts: in-app, email, Discord, Slack, Telegram, webhook
    ai/              DeepSeek client, prompts, the two AI functions, offline rules
    tools/           ZAP client, cURL wrapper, probes, alert normalisation
  tests/
frontend/
  src/pages/         Overview, Findings, Review, Targets, TargetDetail, ScanView, Reports, Notifications, Settings
  src/components/    bell, toasts, modal, evidence viewer, shared UI
docker-compose.yml   juice-shop, zap, buns
portable/            setup, start and stop scripts for running without Docker
```

## Known limitations

- Juice Shop's XSS flaws are mostly DOM-based in the Angular client. The cURL probe only detects reflection in server HTML, so these come from ZAP (with the AJAX spider enabled) or not at all.
- One scan per target at a time. Scans run in the API process; restarting it marks a running scan as failed.
- SQLite is fine for a single assessor workstation, not for several people reviewing at once.

## References

- DeepSeek API documentation. <https://api-docs.deepseek.com/>
- OWASP Juice Shop. <https://github.com/juice-shop/juice-shop>
- OWASP Top 10:2021. <https://owasp.org/Top10/>
- OWASP Web Security Testing Guide v4.2. <https://owasp.org/www-project-web-security-testing-guide/>
- OWASP ZAP documentation. <https://www.zaproxy.org/docs/>
- FIRST, CVSS v3.1 specification. <https://www.first.org/cvss/v3.1/specification-document>

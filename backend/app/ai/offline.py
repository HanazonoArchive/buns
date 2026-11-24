"""Deterministic fallback used when no DeepSeek key is configured.

This is a rules engine, not a language model: it maps the finding's CWE to a
hand-written explanation, CVSS vector and Express remediation. Results are
stored with ``ai_model = "offline-rules"`` so the UI and report never present
them as AI output. It exists so the platform can be demonstrated and tested
without network access or an API key.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    summary: str
    impact: str
    vector: str
    root_cause: str
    steps: list[str]
    code: str
    language: str = "javascript"
    verification: str = ""
    references: list[str] = field(default_factory=list)


_SQLI = Rule(
    summary="User input from '{param}' is placed directly into a SQL statement on {path}. "
            "A crafted value changes the structure of the query, which is why the database "
            "error or unexpected result appears in the response.",
    impact="An attacker can read or alter data the query can reach, and on the login route "
           "can sign in as another user without a password.",
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    root_cause="The query is built by string concatenation instead of bound parameters.",
    steps=[
        "Replace the concatenated SQL with a parameterised query (Sequelize replacements or bind).",
        "Validate the parameter type and length before it reaches the data layer.",
        "Return a generic error to the client and log the database error server-side only.",
        "Run the database user with the least privileges the route needs.",
    ],
    code="""// Before: models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${q}%'`)
const { QueryTypes } = require('sequelize')

app.get('/rest/products/search', async (req, res, next) => {
  const q = String(req.query.q ?? '').slice(0, 200)
  try {
    const products = await sequelize.query(
      'SELECT * FROM Products WHERE (name LIKE :term OR description LIKE :term) AND deletedAt IS NULL',
      { replacements: { term: `%${q}%` }, type: QueryTypes.SELECT }
    )
    res.json({ status: 'success', data: products })
  } catch (err) {
    req.log?.error(err)
    res.status(500).json({ status: 'error', message: 'Search failed' })
  }
})""",
    verification="Repeat the request with a single quote; the response should be an empty result, not a database error.",
    references=["OWASP Cheat Sheet: Query Parameterization", "CWE-89"],
)

_XSS = Rule(
    summary="The value sent in '{param}' is written into the page without output encoding, so "
            "markup in that value is interpreted by the browser on {path}.",
    impact="Script runs in the victim's session on this origin and can read the session token "
           "from storage or act as the user.",
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    root_cause="Untrusted input is rendered as HTML instead of text.",
    steps=[
        "Render user-controlled values as text; in Angular avoid bypassSecurityTrustHtml for them.",
        "Encode on output for the HTML context where the value lands.",
        "Add a Content-Security-Policy that disallows inline script and javascript: URLs.",
    ],
    code="""// Angular template: bind as text, not [innerHTML]
// <span>{{ searchValue }}</span>

// Express: CSP with helmet
const helmet = require('helmet')
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    objectSrc: ["'none'"],
    frameSrc: ["'none'"],
  },
}))""",
    verification="Submit the same payload; it should appear as literal text and no script or frame should load.",
    references=["OWASP Cheat Sheet: Cross Site Scripting Prevention", "CWE-79"],
)

_IDOR = Rule(
    summary="{path} returns a record selected only by the id in the request. The server does "
            "not check that the record belongs to the logged-in user.",
    impact="Any customer can read other customers' data by changing a number in the URL.",
    vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    root_cause="Authorisation is checked at the session level, not at the object level.",
    steps=[
        "Look up the object together with the caller's user id, not by id alone.",
        "Return 404 when the object exists but is not owned by the caller.",
        "Add an automated test that requests another user's id with a valid session.",
    ],
    code="""app.get('/rest/basket/:id', security.isAuthorized(), async (req, res) => {
  const user = security.authenticatedUsers.from(req)
  const basket = await BasketModel.findOne({
    where: { id: req.params.id, UserId: user.data.id },
    include: [{ model: ProductModel, paranoid: false, as: 'Products' }],
  })
  if (!basket) return res.status(404).json({ status: 'error', message: 'Not found' })
  res.json({ status: 'success', data: basket })
})""",
    verification="Request another user's basket id with the test session; expect 404.",
    references=["OWASP API Security Top 10: API1 Broken Object Level Authorization", "CWE-639"],
)

_AUTHZ = Rule(
    summary="{path} is reachable by callers who should not see it. The endpoint checks that a "
            "session exists (or nothing at all) rather than the caller's role.",
    impact="Account emails and roles of all users are exposed, which feeds phishing and "
           "targeted password attacks against administrators.",
    vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    root_cause="Missing role check on an administrative endpoint.",
    steps=[
        "Require the admin role on user-management routes.",
        "Deny by default: register a role check before any route under /api/Users.",
        "Strip fields such as password hashes and TOTP secrets from every user serialisation.",
    ],
    code="""function requireRole(role) {
  return (req, res, next) => {
    const user = security.authenticatedUsers.from(req)
    if (!user) return res.status(401).end()
    if (user.data.role !== role) return res.status(403).end()
    next()
  }
}

app.get('/api/Users', requireRole('admin'))""",
    verification="Call the endpoint with a customer token and without a token; expect 403 and 401.",
    references=["OWASP Top 10 A01:2021", "CWE-285"],
)

_RATE = Rule(
    summary="Repeated failed logins on {path} are all processed normally. There is no lockout, "
            "delay or 429 response.",
    impact="Automated password guessing and credential stuffing run at full speed against "
           "every account.",
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    root_cause="No throttling on the authentication endpoint.",
    steps=[
        "Rate-limit /rest/user/login per IP and per account.",
        "Add progressive delay or a temporary lock after repeated failures for one account.",
        "Log failed attempts and alert on bursts.",
    ],
    code="""const rateLimit = require('express-rate-limit')

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => `${req.ip}:${String(req.body?.email ?? '').toLowerCase()}`,
})

app.post('/rest/user/login', loginLimiter, login())""",
    verification="Send 11 failed logins in a row; the 11th should return 429 with a Retry-After header.",
    references=["OWASP WSTG-ATHN-03", "CWE-307"],
)

_WEAKPW = Rule(
    summary="Registration on {path} accepted a three-character password. No length or "
            "complexity rule is enforced on the server.",
    impact="Users can choose passwords that fall to the first guesses of any wordlist.",
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    root_cause="Password rules are missing or enforced only in the browser.",
    steps=[
        "Enforce a minimum length of at least 8 characters on the server (NIST SP 800-63B).",
        "Reject passwords found in a breached-password list.",
        "Keep the client-side check for usability, but never rely on it.",
    ],
    code="""const MIN_LENGTH = 8
const common = new Set(require('./common-passwords.json'))

function validatePassword(req, res, next) {
  const pw = String(req.body?.password ?? '')
  if (pw.length < MIN_LENGTH || common.has(pw.toLowerCase())) {
    return res.status(400).json({ message: `Password must be at least ${MIN_LENGTH} characters and not a common password.` })
  }
  if (pw !== req.body?.passwordRepeat) {
    return res.status(400).json({ message: 'Passwords do not match.' })
  }
  next()
}

app.post('/api/Users', validatePassword)""",
    verification="Register with password '123'; expect HTTP 400 and no account created.",
    references=["NIST SP 800-63B 5.1.1", "CWE-521"],
)

_LISTING = Rule(
    summary="{path} returns a browsable list of files. Some of them look like internal "
            "documents or backups.",
    impact="Anyone can download files that were never meant to be public.",
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    root_cause="serve-index is mounted on a directory that holds non-public files.",
    steps=[
        "Remove serve-index from the route.",
        "Move non-public files out of the web root.",
        "Serve only an explicit allow-list of public files.",
    ],
    code="""// Remove: app.use('/ftp', serveIndex('ftp', { icons: true }))
const PUBLIC_FILES = new Set(['legal.md'])

app.get('/ftp/:file', (req, res) => {
  const name = req.params.file
  if (!PUBLIC_FILES.has(name)) return res.status(404).end()
  res.sendFile(name, { root: path.resolve('ftp') })
})""",
    verification="Request the directory URL; expect 404 instead of a listing.",
    references=["OWASP WSTG-CONF-04", "CWE-548"],
)

_ERRORS = Rule(
    summary="An error on {path} returns a stack trace with internal file paths and module names.",
    impact="Attackers learn the framework, file layout and library versions, which speeds up "
           "targeted attacks.",
    vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    root_cause="The default development error handler is active.",
    steps=[
        "Register a final error handler that returns a generic message.",
        "Log the full error server-side with a correlation id.",
        "Run with NODE_ENV=production.",
    ],
    code="""// Must be registered after all routes
app.use((err, req, res, _next) => {
  const id = crypto.randomUUID()
  logger.error({ id, err })
  res.status(err.status || 500).json({ status: 'error', message: 'Unexpected error', id })
})""",
    verification="Request an unknown API route; the body should contain only the generic message and id.",
    references=["OWASP WSTG-ERRH-01", "CWE-209"],
)

_HEADERS = Rule(
    summary="Responses from {path} are missing a browser security control: {title}.",
    impact="On its own this is not exploitable, but it removes a layer that would limit the "
           "damage of other flaws such as XSS or clickjacking.",
    vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    root_cause="Security headers are not set by the application or reverse proxy.",
    steps=[
        "Add helmet to the Express app with an explicit Content-Security-Policy.",
        "Set X-Frame-Options or frame-ancestors to prevent framing.",
        "Remove headers that advertise software versions.",
    ],
    code="""const helmet = require('helmet')

app.disable('x-powered-by')
app.use(helmet({
  contentSecurityPolicy: {
    directives: { defaultSrc: ["'self'"], frameAncestors: ["'none'"], objectSrc: ["'none'"] },
  },
}))""",
    verification="Inspect response headers with curl -I; the missing header should be present.",
    references=["OWASP Secure Headers Project", "CWE-693"],
)

_CORS = Rule(
    summary="{path} answers with Access-Control-Allow-Origin: *, so any website can read its "
            "responses from a visitor's browser.",
    impact="Low on its own because credentials are not sent with a wildcard, but any data the "
           "endpoint returns without auth can be harvested by third-party sites.",
    vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    root_cause="CORS is enabled for every origin.",
    steps=[
        "Replace the wildcard with an explicit list of trusted origins.",
        "Do not reflect the request Origin header back without checking it.",
    ],
    code="""const cors = require('cors')
const allowed = new Set(['https://shop.example.com'])

app.use(cors({
  origin: (origin, cb) => cb(null, !origin || allowed.has(origin)),
}))""",
    verification="Send a request with Origin: https://evil.test; the response should not include an ACAO header.",
    references=["OWASP WSTG-CLNT-07", "CWE-942"],
)

_DISCLOSURE = Rule(
    summary="{path} exposes information that helps an attacker map the application: {title}.",
    impact="Usually low impact by itself; the value is in what it reveals for later attacks.",
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    root_cause="Information intended for internal use is served to everyone.",
    steps=[
        "Confirm which of the exposed details are needed by public clients.",
        "Remove or restrict the rest.",
    ],
    code="""// robots.txt is not access control. Protect the path itself:
app.use('/ftp', requireRole('admin'))""",
    verification="Request the resource anonymously and confirm the sensitive detail is gone.",
    references=["OWASP WSTG-INFO-05", "CWE-200"],
)

_BANNER = Rule(
    summary="{path} announces the server software and version in a response header ({title}).",
    impact="Not exploitable by itself; it lets an attacker match the version against known "
           "vulnerabilities without probing.",
    vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    root_cause="The framework or proxy adds version headers by default.",
    steps=[
        "Disable the X-Powered-By header in Express.",
        "Configure the reverse proxy to send a generic Server header or none.",
    ],
    code="""app.disable('x-powered-by')

// nginx in front of the app
// server_tokens off;
// proxy_hide_header X-Powered-By;""",
    verification="Run curl -I against the site; no header should name a product and version.",
    references=["OWASP WSTG-INFO-02", "CWE-497"],
)

_DEFAULT = Rule(
    summary="{tool} reported '{title}' on {path}. The evidence was not specific enough for an "
            "automatic explanation; review the raw request and response.",
    impact="Depends on the context of the endpoint; assess manually.",
    vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    root_cause="See the tool description.",
    steps=["Reproduce the request with cURL.", "Decide whether the behaviour is intended.",
           "Apply the fix recommended by the tool reference."],
    code="// No generic example for this finding type.",
    language="text",
)

_BY_CWE: dict[int, Rule] = {
    89: _SQLI, 943: _SQLI,
    79: _XSS, 80: _XSS,
    639: _IDOR,
    284: _AUTHZ, 285: _AUTHZ,
    307: _RATE,
    521: _WEAKPW,
    548: _LISTING, 538: _LISTING, 530: _LISTING,
    209: _ERRORS,
    693: _HEADERS, 1021: _HEADERS, 16: _HEADERS, 614: _HEADERS, 1004: _HEADERS, 1275: _HEADERS,
    942: _CORS, 264: _CORS,
    497: _BANNER,
    200: _DISCLOSURE, 615: _DISCLOSURE, 540: _DISCLOSURE,
}

# Tool confidence lowers the FP judgement; these rules are frequently noisy.
_NOISY_RULES = {"zap:10096", "zap:10027", "zap:10109", "zap:10049", "zap:90004"}


def rule_for(cwe_id: int | None) -> Rule:
    return _BY_CWE.get(cwe_id or -1, _DEFAULT)


def _fmt(text: str, payload: dict) -> str:
    from urllib.parse import urlsplit

    path = urlsplit(payload.get("url", "")).path or "/"
    return text.format(
        param=payload.get("parameter") or "the request",
        path=path,
        title=payload.get("title", "finding"),
        tool="OWASP ZAP" if payload.get("tool") == "zap" else "cURL probe",
    )


def analyse(payload: dict) -> dict:
    rule = rule_for(payload.get("cwe"))
    confidence = (payload.get("tool_confidence") or "").lower()
    if payload.get("rule") in _NOISY_RULES or confidence in ("low", "false positive"):
        fp = "Likely to need manual confirmation: this rule is often triggered by benign content."
        conf = "low"
    elif payload.get("tool") == "curl" or confidence in ("high", "confirmed"):
        fp = "Likely a true positive: the evidence shows the behaviour directly."
        conf = "high"
    else:
        fp = "Plausible: the tool matched a known pattern; check the evidence before confirming."
        conf = "medium"
    vector = rule.vector
    if payload.get("tool_severity") == "info":
        # The tool itself classed this as informational; do not inflate it.
        vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"
    summary = _fmt(rule.summary, payload)
    seen = payload.get("seen_on_urls") or 1
    if seen > 1:
        summary += f" The same issue was reported on {seen} URLs across the site."
    return {
        "summary": summary,
        "impact": rule.impact,
        "false_positive_assessment": fp,
        "confidence": conf,
        "cvss_vector": vector,
    }


def remediate(payload: dict) -> dict:
    rule = rule_for(payload.get("cwe"))
    return {
        "root_cause": rule.root_cause,
        "steps": list(rule.steps),
        "code_language": rule.language,
        "code_example": rule.code,
        "verification": rule.verification or "Repeat the original request and confirm the behaviour is gone.",
        "references": list(rule.references),
    }

"""Aegis - Automated Web Application Security Assessment System
Passive checks only: it sends normal GET requests and reads the response."""

from urllib.parse import urlparse
from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

HEADERS = {"User-Agent": "Aegis-Scanner/1.0 (passive security check)"}
TIMEOUT = 10
# points taken off the score for a FAIL (a warning costs half of this)
DEDUCT = {"High": 20, "Medium": 10, "Low": 5}

OWASP_TLS = "OWASP Top 10 - Cryptographic Failures; TLS Cheat Sheet"
OWASP_CFG = "OWASP Top 10 - Security Misconfiguration"
OWASP_HDR = "OWASP Secure Headers Project"
OWASP_SES = "OWASP Session Management Cheat Sheet"


# ---------- Stage 1 and 2: validate the URL ----------
def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        return None, "Please enter a URL."
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        return None, "That does not look like a valid http or https URL."
    return raw, None


# ---------- Stage 3 to 6: collect data, run checks, classify ----------
def scan(url):
    findings = []

    def add(check, result, severity, desc, impact, fix, owasp):
        findings.append(dict(check=check, result=result, severity=severity,
                             desc=desc, impact=impact, fix=fix, owasp=owasp))

    p = urlparse(url)
    https_url = p._replace(scheme="https").geturl()
    http_url = p._replace(scheme="http").geturl()

    # --- HTTPS availability ---
    resp, https_ok, ssl_problem = None, False, False
    try:
        resp = requests.get(https_url, headers=HEADERS, timeout=TIMEOUT)
        https_ok = True
    except requests.exceptions.SSLError:
        ssl_problem = True
    except requests.exceptions.RequestException:
        pass

    if https_ok:
        add("HTTPS availability", "pass", "-",
            "The site can be reached over HTTPS.", "-", "-", OWASP_TLS)
    else:
        why = ("The HTTPS certificate is invalid or could not be verified."
               if ssl_problem else "The site could not be reached over HTTPS.")
        add("HTTPS availability", "fail", "High", why,
            "Data such as passwords and cookies can be read by anyone on the network.",
            "Install a valid TLS certificate (for example a free one from Let's Encrypt) and serve the site over HTTPS.",
            OWASP_TLS)
        # fall back to plain http so the other checks can still run
        try:
            resp = requests.get(http_url, headers=HEADERS, timeout=TIMEOUT)
        except requests.exceptions.RequestException:
            return None, "Could not connect to the target at all. Check the URL and try again."

    # --- HTTP to HTTPS redirect ---
    if https_ok:
        try:
            r = requests.get(http_url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
            loc = r.headers.get("Location", "")
            if 300 <= r.status_code < 400 and loc.lower().startswith("https://"):
                add("HTTP to HTTPS redirect", "pass", "-",
                    "Plain HTTP requests are redirected to HTTPS.", "-", "-", OWASP_TLS)
            else:
                add("HTTP to HTTPS redirect", "fail", "Medium",
                    "The site still answers on plain HTTP without redirecting to HTTPS.",
                    "Users who type the http address stay on an unencrypted connection.",
                    "Add a permanent (301) redirect from HTTP to HTTPS on the server.", OWASP_TLS)
        except requests.exceptions.RequestException:
            add("HTTP to HTTPS redirect", "pass", "-",
                "Plain HTTP is not reachable, so nothing is served insecurely.", "-", "-", OWASP_TLS)

    h = resp.headers  # case insensitive

    # --- Security headers ---
    hsts = h.get("Strict-Transport-Security")
    if not hsts:
        add("Strict-Transport-Security", "fail", "Medium", "The HSTS header is missing.",
            "Browsers may still try plain HTTP first, which allows downgrade attacks.",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", OWASP_HDR)
    else:
        try:
            age = int(hsts.lower().split("max-age=")[1].split(";")[0].strip())
        except (IndexError, ValueError):
            age = 0
        if age < 15552000:
            add("Strict-Transport-Security", "warning", "Medium",
                "HSTS is present but max-age is short (" + hsts + ").",
                "A short lifetime gives weaker protection.",
                "Use a max-age of at least 6 months (15552000), ideally one year.", OWASP_HDR)
        else:
            add("Strict-Transport-Security", "pass", "-", "HSTS is set correctly.", "-", "-", OWASP_HDR)

    csp = h.get("Content-Security-Policy")
    if not csp:
        add("Content-Security-Policy", "fail", "Medium", "The CSP header is missing.",
            "Makes cross site scripting (XSS) attacks easier to carry out.",
            "Define a policy, for example: Content-Security-Policy: default-src 'self'", OWASP_HDR)
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        add("Content-Security-Policy", "warning", "Medium",
            "CSP is present but allows 'unsafe-inline' or 'unsafe-eval'.",
            "These options weaken the protection against XSS.",
            "Remove unsafe-inline / unsafe-eval and use nonces or hashes for scripts.", OWASP_HDR)
    else:
        add("Content-Security-Policy", "pass", "-", "A CSP header is set.", "-", "-", OWASP_HDR)

    xfo = (h.get("X-Frame-Options") or "").upper()
    if xfo in ("DENY", "SAMEORIGIN") or (csp and "frame-ancestors" in csp):
        add("Clickjacking protection", "pass", "-", "Framing is restricted.", "-", "-", OWASP_HDR)
    else:
        add("Clickjacking protection", "fail", "Medium",
            "Neither X-Frame-Options nor CSP frame-ancestors is set.",
            "Another site could load this page in a hidden frame and trick users into clicking.",
            "Add: X-Frame-Options: DENY (or SAMEORIGIN), or use CSP frame-ancestors.", OWASP_HDR)

    if (h.get("X-Content-Type-Options") or "").lower() == "nosniff":
        add("X-Content-Type-Options", "pass", "-", "nosniff is set.", "-", "-", OWASP_HDR)
    else:
        add("X-Content-Type-Options", "fail", "Low", "The nosniff header is missing.",
            "Browsers may guess the content type and run files in an unsafe way.",
            "Add: X-Content-Type-Options: nosniff", OWASP_HDR)

    if h.get("Referrer-Policy"):
        add("Referrer-Policy", "pass", "-", "A Referrer-Policy is set.", "-", "-", OWASP_HDR)
    else:
        add("Referrer-Policy", "fail", "Low", "The Referrer-Policy header is missing.",
            "Full page URLs may be leaked to other sites.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin", OWASP_HDR)

    if h.get("Permissions-Policy"):
        add("Permissions-Policy", "pass", "-", "A Permissions-Policy is set.", "-", "-", OWASP_HDR)
    else:
        add("Permissions-Policy", "fail", "Low", "The Permissions-Policy header is missing.",
            "Browser features such as camera or location are not explicitly restricted.",
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()", OWASP_HDR)

    # --- Cookies ---
    raw_cookies = []
    for r in list(resp.history) + [resp]:
        try:
            raw_cookies += r.raw.headers.getlist("Set-Cookie")
        except AttributeError:
            pass

    if not raw_cookies:
        add("Cookie attributes", "pass", "-", "The server did not set any cookies on this page.",
            "-", "-", OWASP_SES)
    for c in raw_cookies:
        name = c.split("=")[0].strip()
        parts = [x.strip().lower() for x in c.split(";")[1:]]
        for flag, present, sev, why, fix in [
            ("Secure", "secure" in parts, "Medium",
             "can be sent over plain HTTP and intercepted.", "Add the Secure attribute."),
            ("HttpOnly", "httponly" in parts, "Medium",
             "can be read by JavaScript, so an XSS bug could steal it.", "Add the HttpOnly attribute."),
            ("SameSite", any(x.startswith("samesite") for x in parts), "Low",
             "is sent with cross site requests, which helps CSRF attacks.",
             "Add SameSite=Lax or SameSite=Strict."),
        ]:
            label = "Cookie '" + name + "' - " + flag
            if present:
                add(label, "pass", "-", flag + " attribute is set.", "-", "-", OWASP_SES)
            else:
                add(label, "fail", sev, flag + " attribute is missing.",
                    "The cookie " + why, fix, OWASP_SES)

    # --- Information disclosure ---
    server = h.get("Server", "")
    powered = h.get("X-Powered-By", "")
    if powered:
        add("Information disclosure", "fail", "Low",
            "X-Powered-By reveals: " + powered,
            "Attackers can look up known problems for that technology and version.",
            "Remove the X-Powered-By header in the server or framework settings.", OWASP_CFG)
    elif any(ch.isdigit() for ch in server):
        add("Information disclosure", "warning", "Low",
            "The Server header shows a version: " + server,
            "Exact versions make it easier to find matching public vulnerabilities.",
            "Hide the version number in the server configuration.", OWASP_CFG)
    else:
        add("Information disclosure", "pass", "-",
            "No obvious server or version information is exposed.", "-", "-", OWASP_CFG)

    return dict(final_url=resp.url, status=resp.status_code, findings=findings), None


# ---------- Stage 6: score ----------
def calculate_score(findings):
    score = 100
    for f in findings:
        pts = DEDUCT.get(f["severity"], 0)
        if f["result"] == "fail":
            score -= pts
        elif f["result"] == "warning":
            score -= pts // 2
    score = max(score, 0)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return score, grade


# ---------- Stage 8: report page ----------
PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aegis - Security Assessment</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f8;margin:0;color:#222}
 .wrap{max-width:980px;margin:auto;padding:24px}
 h1{margin-bottom:0} .tag{color:#555;margin-top:4px}
 .card{background:#fff;border-radius:8px;padding:20px;margin:16px 0;box-shadow:0 1px 3px #0002}
 input[type=text]{width:100%;padding:10px;font-size:16px;box-sizing:border-box}
 button{background:#1f4e79;color:#fff;border:0;padding:10px 22px;font-size:16px;border-radius:5px;cursor:pointer;margin-top:10px}
 .notice{background:#fff8e1;border-left:4px solid #f0ad00;padding:10px;font-size:14px}
 .err{background:#fdecea;border-left:4px solid #d93025;padding:10px}
 .score{font-size:56px;font-weight:bold} .grade{font-size:56px;font-weight:bold;margin-left:24px}
 table{width:100%;border-collapse:collapse;font-size:14px}
 th,td{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top} th{background:#eee}
 .pass{color:#188038;font-weight:bold} .fail{color:#d93025;font-weight:bold} .warning{color:#e37400;font-weight:bold}
 .stats span{margin-right:18px}
</style></head><body><div class="wrap">
<h1>AEGIS</h1><div class="tag">Automated Web Application Security Assessment System</div>

<div class="card">
 <form method="post">
  <label><b>Target URL</b></label>
  <input type="text" name="url" placeholder="https://example.com" value="{{ url or '' }}" required>
  <p class="notice"><label><input type="checkbox" name="agree" required>
   I own this website or have explicit permission to test it. Aegis only sends normal, read only requests.</label></p>
  <button type="submit">Run assessment</button>
 </form>
</div>

{% if error %}<div class="card err">{{ error }}</div>{% endif %}

{% if result %}
<div class="card">
 <h2>Security Report</h2>
 <p>Target: <b>{{ result.final_url }}</b> (HTTP status {{ result.status }})</p>
 <div><span class="score">{{ score }}/100</span><span class="grade">Grade {{ grade }}</span></div>
 <p class="stats">
  <span class="pass">Passed: {{ counts.pass }}</span>
  <span class="fail">Failed: {{ counts.fail }}</span>
  <span class="warning">Warnings: {{ counts.warning }}</span></p>
</div>
<div class="card">
 <h2>Findings</h2>
 <table>
  <tr><th>Check</th><th>Result</th><th>Severity</th><th>Details</th><th>Impact</th><th>Recommendation</th><th>OWASP reference</th></tr>
  {% for f in result.findings %}
  <tr><td>{{ f.check }}</td><td class="{{ f.result }}">{{ f.result|upper }}</td><td>{{ f.severity }}</td>
      <td>{{ f.desc }}</td><td>{{ f.impact }}</td><td>{{ f.fix }}</td><td>{{ f.owasp }}</td></tr>
  {% endfor %}
 </table>
</div>
{% endif %}
</div></body></html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    ctx = dict(url="", error=None, result=None)
    if request.method == "POST":
        ctx["url"] = request.form.get("url", "")
        if not request.form.get("agree"):
            ctx["error"] = "You must confirm that you have permission to test this site."
        else:
            url, err = normalize_url(ctx["url"])
            if err:
                ctx["error"] = err
            else:
                result, err = scan(url)
                if err:
                    ctx["error"] = err
                else:
                    score, grade = calculate_score(result["findings"])
                    counts = {k: sum(1 for f in result["findings"] if f["result"] == k)
                              for k in ("pass", "fail", "warning")}
                    ctx.update(result=result, score=score, grade=grade, counts=counts)
    return render_template_string(PAGE, **ctx)


if __name__ == "__main__":
    app.run(debug=True)

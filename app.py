from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from html import escape
import re

app = Flask(__name__)


BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36 AgentGuardPrototype/1.0",
    "Accept": "text/html,text/plain,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Connection": "close"
}

def safe_get(url, **kwargs):
    timeout = kwargs.pop("timeout", 10)
    allow_redirects = kwargs.pop("allow_redirects", True)
    headers = kwargs.pop("headers", {}) or {}

    merged_headers = BROWSER_HEADERS.copy()
    merged_headers.update(headers)

    return requests.get(
        url,
        timeout=timeout,
        allow_redirects=allow_redirects,
        headers=merged_headers,
        **kwargs
    )


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

CHATBOT_KEYWORDS = [
    "intercom", "drift", "tawk", "crisp", "zendesk", "freshchat",
    "livechat", "chatbase", "botpress", "tidio", "hubspot",
    "openai", "chatgpt", "claude", "gemini", "assistant"
]

TRACKING_KEYWORDS = [
    "googletagmanager", "google-analytics", "gtag", "doubleclick",
    "facebook", "hotjar", "clarity", "segment", "mixpanel",
    "pinterest", "tiktok", "linkedin"
]

PROMPT_INJECTION_PHRASES = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "system prompt",
    "reveal your prompt",
    "you are now",
    "do not tell the user"
]

ACTIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/backup.sql",
    "/database.sql",
    "/wp-config.php.bak",
    "/phpinfo.php",
    "/server-status",
    "/wp-login.php",
    "/xmlrpc.php",
    "/wp-json/wp/v2/users"
]


def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def get_domain(url):
    return urlparse(url).netloc.replace("www.", "").lower()


def check_policy_file(base_url, path):
    try:
        r = safe_get(urljoin(base_url, path), timeout=8)
        return r.status_code == 200
    except Exception:
        return False


def add_finding(findings, severity, title, evidence, fix):
    findings.append({
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "fix": fix
    })


def run_passive_audit(url):
    findings = []
    facts = {}

    url = normalize_url(url)

    try:
        response = safe_get(
            url,
            timeout=25,
            allow_redirects=True,
            headers={"User-Agent": "AgentGuardPrototype/1.0"}
        )
    except Exception as e:
        return {
            "audit_incomplete": True,
            "score": 0,
            "risk": "Audit incomplete",
            "facts": {
                "Audit status": "Incomplete",
                "Error": str(e)
            },
            "findings": [{
                "severity": "Critical",
                "title": "Could not reach website",
                "evidence": str(e),
                "fix": "The website may be blocking automated requests, responding too slowly, or protected by CDN/WAF rules. Try again later or test a smaller page."
            }]
        }

    final_url = response.url
    base_url = f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}"
    page_domain = get_domain(final_url)

    facts["Final URL"] = final_url
    facts["Status code"] = response.status_code
    facts["HTTPS"] = "Yes" if final_url.startswith("https://") else "No"

    if not final_url.startswith("https://"):
        add_finding(
            findings,
            "Critical",
            "Website does not use HTTPS",
            f"Final URL is {final_url}",
            "Force HTTPS and redirect all HTTP traffic to HTTPS."
        )

    missing_headers = []
    for header in SECURITY_HEADERS:
        if header not in response.headers:
            missing_headers.append(header)

    facts["Missing security headers"] = len(missing_headers)

    for header in missing_headers:
        severity = "High" if header in ["Strict-Transport-Security", "Content-Security-Policy"] else "Medium"
        add_finding(
            findings,
            severity,
            f"Missing {header}",
            f"{header} header was not found.",
            f"Add the {header} response header."
        )

    if "X-Powered-By" in response.headers:
        add_finding(
            findings,
            "Low",
            "Backend technology exposed",
            f"X-Powered-By: {response.headers.get('X-Powered-By')}",
            "Hide X-Powered-By if your hosting setup allows it."
        )

    facts["Cookies detected"] = len(response.cookies)

    for cookie in response.cookies:
        if not cookie.secure and final_url.startswith("https://"):
            add_finding(
                findings,
                "Medium",
                "Cookie missing Secure flag",
                f"Cookie name: {cookie.name}",
                "Add the Secure flag to cookies that should only be sent over HTTPS."
            )

    soup = BeautifulSoup(response.text, "html.parser")

    scripts = []
    external_scripts = []
    tracking_scripts = []
    chatbot_scripts = []

    for script in soup.find_all("script"):
        src = script.get("src")
        if not src:
            continue

        full_src = urljoin(final_url, src)
        scripts.append(full_src)

        script_domain = get_domain(full_src)

        if script_domain and script_domain != page_domain:
            external_scripts.append(full_src)

        lower_src = full_src.lower()

        if any(word in lower_src for word in TRACKING_KEYWORDS):
            tracking_scripts.append(full_src)

        if any(word in lower_src for word in CHATBOT_KEYWORDS):
            chatbot_scripts.append(full_src)

    external_domains = sorted(set(get_domain(s) for s in external_scripts if get_domain(s)))

    facts["Total scripts"] = len(scripts)
    facts["External script domains"] = len(external_domains)
    facts["Tracking scripts"] = len(tracking_scripts)
    facts["AI/chatbot indicators"] = len(chatbot_scripts)

    if len(external_domains) >= 8:
        add_finding(
            findings,
            "Medium",
            "Many third-party scripts detected",
            f"{len(external_domains)} external script domains found.",
            "Review old pixels, plugins, analytics tools, and widgets. Remove what is not needed."
        )

    if tracking_scripts:
        add_finding(
            findings,
            "Low",
            "Tracking or marketing scripts detected",
            f"{len(tracking_scripts)} tracking-related scripts found.",
            "Make sure tracking is explained in the privacy policy and controlled by cookie consent where required."
        )

    if chatbot_scripts:
        add_finding(
            findings,
            "Medium",
            "AI/chatbot script detected",
            f"{len(chatbot_scripts)} possible chatbot or AI assistant scripts found.",
            "Review what data the chatbot collects and whether visitors are clearly informed."
        )

    forms = soup.find_all("form")
    facts["Forms detected"] = len(forms)

    for form in forms:
        action = form.get("action") or final_url
        full_action = urljoin(final_url, action)

        if full_action.startswith("http://"):
            add_finding(
                findings,
                "High",
                "Form submits over HTTP",
                full_action,
                "Change the form action URL to HTTPS."
            )

    page_text = soup.get_text(" ", strip=True).lower()

    for phrase in PROMPT_INJECTION_PHRASES:
        if phrase in page_text:
            add_finding(
                findings,
                "High",
                "Prompt-injection-like text found",
                f"Matched phrase: {phrase}",
                "Review the page text and remove hidden or suspicious AI-instruction style content."
            )
            break

    llms_found = check_policy_file(base_url, "/llms.txt")
    robots_found = check_policy_file(base_url, "/robots.txt")
    security_found = check_policy_file(base_url, "/.well-known/security.txt")

    facts["llms.txt"] = "Found" if llms_found else "Not found"
    facts["robots.txt"] = "Found" if robots_found else "Not found"
    facts["security.txt"] = "Found" if security_found else "Not found"

    if not llms_found:
        add_finding(
            findings,
            "Low",
            "No llms.txt found",
            "/llms.txt did not return HTTP 200.",
            "Add a clean llms.txt file to guide AI assistants to important pages."
        )

    wordpress_result = run_wordpress_passive_checks(response, final_url, base_url, soup)
    facts.update(wordpress_result["facts"])
    findings.extend(wordpress_result["findings"])

    return {
        "facts": facts,
        "findings": findings,
        "final_url": final_url,
        "base_url": base_url
    }



def run_wordpress_passive_checks(response, final_url, base_url, soup):
    findings = []
    facts = {}

    html = response.text or ""
    lower_html = html.lower()

    wp_json_found = False
    try:
        wp_json_response = safe_get(
            urljoin(base_url, "/wp-json/"),
            timeout=8,
            headers={"User-Agent": "AgentGuardPrototype/1.0"}
        )
        wp_json_found = wp_json_response.status_code == 200
    except Exception:
        wp_json_found = False

    generator = soup.find("meta", attrs={"name": "generator"})
    generator_content = generator.get("content", "") if generator else ""

    theme_names = sorted(set(
        re.findall(r"/wp-content/themes/([^/\"'?#]+)", html, re.IGNORECASE)
    ))

    plugin_names = sorted(set(
        re.findall(r"/wp-content/plugins/([^/\"'?#]+)", html, re.IGNORECASE)
    ))

    wordpress_detected = (
        "wp-content" in lower_html
        or "wp-includes" in lower_html
        or "wordpress" in lower_html
        or wp_json_found
    )

    facts["WordPress detected"] = "Yes" if wordpress_detected else "No"
    facts["WordPress REST API"] = "Found" if wp_json_found else "Not found"
    facts["WordPress theme indicators"] = ", ".join(theme_names[:5]) if theme_names else "None found"
    facts["WordPress plugin indicators"] = f"{len(plugin_names)} found" if plugin_names else "None found"

    if wordpress_detected:
        add_finding(
            findings,
            "Info",
            "WordPress site detected",
            "Public WordPress indicators were found.",
            "Keep WordPress core, themes, and plugins updated. Use MFA and login rate limiting."
        )

    if generator_content and "wordpress" in generator_content.lower():
        add_finding(
            findings,
            "Low",
            "WordPress generator tag exposed",
            f"Generator meta tag: {generator_content}",
            "Remove public generator/version tags where possible."
        )

    if theme_names:
        add_finding(
            findings,
            "Low",
            "WordPress theme name visible",
            f"Detected theme indicator: {theme_names[0]}",
            "This is common, but outdated themes can be risky. Keep the active theme updated."
        )

    if plugin_names:
        add_finding(
            findings,
            "Low",
            "WordPress plugin names visible",
            f"Detected {len(plugin_names)} plugin indicator(s).",
            "Review visible plugins and keep them updated. Remove plugins that are no longer needed."
        )

    return {
        "facts": facts,
        "findings": findings
    }


def looks_like_normal_html(text):
    text = text.lower()
    normal_markers = [
        "<html", "<!doctype html", "page not found", "404",
        "wp-content", "elementor", "not found"
    ]
    return any(marker in text for marker in normal_markers)


def run_active_audit(base_url):
    findings = []
    facts = {}

    checked_paths = []
    possible_exposed = 0

    for path in ACTIVE_PATHS:
        full_url = urljoin(base_url, path)

        try:
            r = safe_get(
                full_url,
                timeout=8,
                allow_redirects=True,
                headers={"User-Agent": "AgentGuardPrototype/1.0"}
            )

            checked_paths.append(f"{path}: HTTP {r.status_code}")

            body_sample = (r.text or "")[:1200].lower()

            sensitive_paths = [
                "/.env",
                "/.git/config",
                "/backup.sql",
                "/database.sql",
                "/wp-config.php.bak"
            ]

            if path in sensitive_paths:
                if r.status_code == 200 and len(r.text or "") > 20 and not looks_like_normal_html(body_sample):
                    possible_exposed += 1
                    add_finding(
                        findings,
                        "Critical",
                        "Sensitive file may be publicly accessible",
                        f"{path} returned HTTP 200.",
                        "Block public access to this file immediately and rotate exposed secrets if confirmed."
                    )

            if path == "/phpinfo.php":
                if r.status_code == 200 and "php version" in body_sample:
                    add_finding(
                        findings,
                        "High",
                        "phpinfo page may be exposed",
                        "/phpinfo.php returned PHP configuration information.",
                        "Remove phpinfo.php from the public website."
                    )

            if path == "/server-status":
                if r.status_code == 200 and "apache server status" in body_sample:
                    add_finding(
                        findings,
                        "High",
                        "Server status page may be exposed",
                        "/server-status returned Apache status-like content.",
                        "Restrict server-status to trusted IP addresses or disable it."
                    )

            if path == "/wp-login.php":
                if r.status_code == 200:
                    add_finding(
                        findings,
                        "Info",
                        "WordPress login page detected",
                        "/wp-login.php is publicly reachable.",
                        "Use MFA, strong passwords, login rate limiting, and regular WordPress updates."
                    )

            if path == "/xmlrpc.php":
                if r.status_code in [200, 405]:
                    add_finding(
                        findings,
                        "Low",
                        "WordPress XML-RPC endpoint detected",
                        f"/xmlrpc.php returned HTTP {r.status_code}.",
                        "Disable XML-RPC if the site does not need it. Otherwise, rate-limit and monitor it."
                    )

            if path == "/wp-json/wp/v2/users":
                if r.status_code == 200 and body_sample.strip().startswith("[") and ("slug" in body_sample or "avatar_urls" in body_sample or '"name"' in body_sample):
                    add_finding(
                        findings,
                        "Medium",
                        "Possible WordPress user enumeration via REST API",
                        "/wp-json/wp/v2/users returned a public users-style response.",
                        "If public author data is not needed, restrict this endpoint or reduce exposed user information."
                    )

        except Exception as e:
            checked_paths.append(f"{path}: error")

    facts["Active paths checked"] = len(ACTIVE_PATHS)
    facts["Possible exposed sensitive paths"] = possible_exposed
    facts["Active check summary"] = " | ".join(checked_paths)

    return {
        "facts": facts,
        "findings": findings
    }


def calculate_score(findings):
    penalties = {
        "Critical": 25,
        "High": 18,
        "Medium": 10,
        "Low": 4,
        "Info": 0
    }

    score = 100
    for finding in findings:
        score -= penalties.get(finding["severity"], 0)

    return max(score, 0)


def get_risk(score):
    if score >= 85:
        return "Low"
    elif score >= 65:
        return "Medium"
    elif score >= 40:
        return "High"
    else:
        return "Critical"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "")
    active = "active" in request.form
    permission = "permission" in request.form

    if active and not permission:
        return """
        <h1>Permission required</h1>
        <p>Active audit can only run when you own the website or have permission.</p>
        <p><a href="/">Go back</a></p>
        """

    passive_result = run_passive_audit(url)
    facts = passive_result["facts"]
    findings = passive_result["findings"]

    if passive_result.get("audit_incomplete"):
        score = "N/A"
        risk = "Audit incomplete"
    else:
        if active and permission:
            active_result = run_active_audit(passive_result["base_url"])
            facts.update(active_result["facts"])
            findings.extend(active_result["findings"])

        score = calculate_score(findings)
        risk = get_risk(score)

    facts_html = ""
    for key, value in facts.items():
        facts_html += f"<div class='fact'><strong>{escape(str(key))}</strong><br>{escape(str(value))}</div>"

    findings_html = ""
    for finding in findings:
        findings_html += f"""
        <div class="finding">
            <span class="severity">{escape(finding["severity"])}</span>
            <h3>{escape(finding["title"])}</h3>
            <p><strong>Evidence:</strong> {escape(finding["evidence"])}</p>
            <p><strong>Recommended fix:</strong> {escape(finding["fix"])}</p>
        </div>
        """

    if not findings_html:
        findings_html = "<p>No obvious issues found in this prototype scan.</p>"

    audit_mode = "Passive + Active" if active and permission else "Passive"
    score_display = f"{score}/100" if isinstance(score, int) else score

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AgentGuard Results</title>
        <style>
            body {{
                margin: 0;
                font-family: Arial, sans-serif;
                background: #050505;
                color: #f5f5f5;
            }}

            .container {{
                max-width: 1100px;
                margin: 0 auto;
                padding: 50px 24px;
            }}

            a {{
                color: #39e58c;
            }}

            .result-actions {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 14px;
                margin-bottom: 24px;
            }}

            .print-btn {{
                background: #39e58c;
                color: #050505;
                border: none;
                border-radius: 12px;
                padding: 12px 16px;
                font-weight: bold;
                cursor: pointer;
            }}

            .safety-note {{
                background: #0f1f17;
                border: 1px solid #1f6b46;
                color: #d7ffe9;
                border-radius: 16px;
                padding: 18px;
                line-height: 1.6;
                margin-bottom: 28px;
            }}

            @media print {{
                body {{
                    background: white;
                    color: black;
                }}

                .result-actions,
                .print-btn {{
                    display: none;
                }}

                .score, .fact, .finding, .safety-note {{
                    background: white;
                    color: black;
                    border: 1px solid #ccc;
                }}

                .score-number {{
                    color: black;
                }}

                a {{
                    color: black;
                }}
            }}

            .top {{
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 18px;
                margin: 30px 0;
            }}

            .score, .fact, .finding {{
                background: #111;
                border: 1px solid #262626;
                border-radius: 18px;
                padding: 22px;
            }}

            .score-number {{
                font-size: 52px;
                font-weight: bold;
                color: #39e58c;
            }}

            .facts {{
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 14px;
                margin: 24px 0;
            }}

            .finding {{
                margin-bottom: 16px;
            }}

            .severity {{
                display: inline-block;
                background: #2b1f00;
                color: #ffd36a;
                padding: 6px 10px;
                border-radius: 999px;
                font-size: 13px;
                font-weight: bold;
            }}

            @media (max-width: 800px) {{
                .top, .facts {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="result-actions">
                <a href="/">← Run another audit</a>
                <button onclick="window.print()" class="print-btn">Print / Save report</button>
            </div>

            <div class="safety-note">
                <strong>Scan safety:</strong> Passive audit reviews public website signals. Active audit only checks a small list of common public paths when permission is confirmed. This prototype does not brute-force passwords, exploit vulnerabilities, submit forms, or stress test the website.
            </div>

            <h1>AgentGuard Audit Results</h1>
            <p>Website tested: <strong>{escape(url)}</strong></p>

            <div class="top">
                <div class="score">
                    <p>Safety score</p>
                    <div class="score-number">{score_display}</div>
                </div>

                <div class="score">
                    <p>Risk level</p>
                    <h2>{escape(risk)}</h2>
                </div>

                <div class="score">
                    <p>Audit mode</p>
                    <h2>{escape(audit_mode)}</h2>
                </div>
            </div>

            <h2>Website facts</h2>
            <div class="facts">
                {facts_html}
            </div>

            <h2>Findings and recommendations</h2>
            {findings_html}
        </div>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(debug=True)

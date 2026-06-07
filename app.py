from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from html import escape
import re
import ipaddress
import time
from collections import defaultdict

# dns is used for SPF / DMARC / CAA checks — install with: pip install dnspython
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

app = Flask(__name__)

# ──────────────────────────────────────────────────────────
# RATE LIMITING  (in-memory, no extra library needed)
# 10 scans per IP per 60 seconds
# ──────────────────────────────────────────────────────────
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX    = 10
_rate_store = defaultdict(list)

def is_rate_limited(ip):
    now = time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_store[ip]) >= RATE_LIMIT_MAX:
        return True
    _rate_store[ip].append(now)
    return False


# ──────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36 AgentGuardPrototype/1.0",
    "Accept": "text/html,text/plain,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Connection": "close"
}

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

# Cookie consent platform signatures (script src keywords)
CONSENT_SCRIPT_KEYWORDS = [
    "cookiebot", "onetrust", "cookieyes", "usercentrics",
    "quantcast", "cookieconsent", "tarteaucitron", "axeptio",
    "trustarc", "consentmanager", "iubenda", "didomi"
]

# Cookie consent HTML element signatures
CONSENT_HTML_KEYWORDS = [
    "cookie-banner", "cookie-notice", "cookie-consent", "cookie-modal",
    "cookiebanner", "cookienotice", "cookieconsent", "gdpr-banner",
    "gdpr-notice", "gdpr-modal", "consent-banner", "consent-notice",
    "consent-modal", "privacy-notice", "cookie-popup", "cookie-bar",
    "cc-window", "cc-banner"
]

# Privacy policy link text patterns
PRIVACY_LINK_PATTERNS = [
    "privacy", "privacy policy", "datenschutz", "privacidad",
    "politique de confidentialité", "privacy notice", "data policy",
    "cookie policy"
]

# Patterns that suggest API keys or secrets are exposed in JS
API_KEY_PATTERNS = [
    (r'\bsk-[A-Za-z0-9]{20,}', "OpenAI API key pattern"),
    (r'\bAIza[A-Za-z0-9_\-]{30,}', "Google API key pattern"),
    (r'\bghp_[A-Za-z0-9]{30,}', "GitHub personal access token"),
    (r'\bxoxb-[A-Za-z0-9\-]{40,}', "Slack bot token"),
    (r'\bEAAC[A-Za-z0-9]+', "Facebook access token pattern"),
    (r'Bearer\s+[A-Za-z0-9\-_\.]{20,}', "Bearer token in JS"),
    (r'api[_\-]?key[\s]*[:=][\s]*["\'][A-Za-z0-9\-_]{16,}["\']', "Generic API key assignment"),
    (r'secret[\s]*[:=][\s]*["\'][A-Za-z0-9\-_]{16,}["\']', "Generic secret assignment"),
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

SEVERITY_STYLES = {
    "Critical": "background:#3d0000; color:#ff6b6b;",
    "High":     "background:#2b1400; color:#ff9f43;",
    "Medium":   "background:#2b1f00; color:#ffd36a;",
    "Low":      "background:#001a2b; color:#74b9ff;",
    "Info":     "background:#0d1f0d; color:#55efc4;",
}

# ──────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────
BLOCKED_HOSTNAMES = {
    "localhost", "127.0.0.1", "0.0.0.0",
    "169.254.169.254", "metadata.google.internal",
}

def is_safe_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        if hostname.lower() in BLOCKED_HOSTNAMES:
            return False
        try:
            ip = ipaddress.ip_address(hostname)
            if (ip.is_private or ip.is_loopback or
                    ip.is_link_local or ip.is_reserved or ip.is_multicast):
                return False
        except ValueError:
            pass  # normal hostname — fine
        return True
    except Exception:
        return False


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


def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def get_domain(url):
    return urlparse(url).netloc.replace("www.", "").lower()


def get_root_domain(url):
    """Returns just the registrable domain, e.g. sub.example.com → example.com"""
    netloc = urlparse(url).netloc.lower()
    parts = netloc.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return netloc


def check_policy_file(base_url, path):
    try:
        r = safe_get(urljoin(base_url, path), timeout=8)
        return r.status_code == 200
    except Exception:
        return False


def fetch_policy_file(base_url, path):
    """Returns (found: bool, text: str)"""
    try:
        r = safe_get(urljoin(base_url, path), timeout=8)
        if r.status_code == 200:
            return True, r.text
        return False, ""
    except Exception:
        return False, ""


def add_finding(findings, severity, title, evidence, fix):
    findings.append({
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "fix": fix
    })


def looks_like_normal_html(text):
    text = text.lower()
    markers = ["<html", "<!doctype html", "page not found", "404",
                "wp-content", "elementor", "not found"]
    return any(m in text for m in markers)


# ──────────────────────────────────────────────────────────
# CHECK MODULES
# ──────────────────────────────────────────────────────────

def check_security_headers(response, final_url, findings, facts):
    """Check for missing and weak security headers."""
    missing_headers = []
    for header in SECURITY_HEADERS:
        if header not in response.headers:
            missing_headers.append(header)

    facts["Missing security headers"] = len(missing_headers)

    for header in missing_headers:
        severity = "High" if header in ["Strict-Transport-Security", "Content-Security-Policy"] else "Medium"
        add_finding(findings, severity, f"Missing {header}",
                    f"{header} header was not found.",
                    f"Add the {header} response header.")

    if "X-Powered-By" in response.headers:
        add_finding(findings, "Low", "Backend technology exposed",
                    f"X-Powered-By: {response.headers.get('X-Powered-By')}",
                    "Hide X-Powered-By if your hosting setup allows it.")

    # ── Weak header value checks ──────────────────────────
    csp = response.headers.get("Content-Security-Policy", "")
    if csp:
        if "unsafe-inline" in csp:
            add_finding(findings, "Medium", "CSP allows unsafe-inline",
                        "Content-Security-Policy contains 'unsafe-inline'.",
                        "Remove 'unsafe-inline' from CSP. Use nonces or hashes for inline scripts instead.")
        if "unsafe-eval" in csp:
            add_finding(findings, "Medium", "CSP allows unsafe-eval",
                        "Content-Security-Policy contains 'unsafe-eval'.",
                        "Remove 'unsafe-eval' from CSP. Avoid eval() in JavaScript.")
        if re.search(r"(script-src|default-src)[^;]*\*", csp):
            add_finding(findings, "Medium", "CSP uses wildcard source",
                        "Content-Security-Policy uses a wildcard (*) in script or default source.",
                        "Replace wildcard sources with specific trusted domains.")

    hsts = response.headers.get("Strict-Transport-Security", "")
    if hsts:
        match = re.search(r"max-age=(\d+)", hsts)
        if match:
            max_age = int(match.group(1))
            if max_age < 15552000:  # 180 days
                add_finding(findings, "Low", "HSTS max-age is too short",
                            f"Strict-Transport-Security max-age={max_age} (less than 180 days).",
                            "Set HSTS max-age to at least 31536000 (1 year). Add includeSubDomains.")
        if "includesubdomains" not in hsts.lower():
            add_finding(findings, "Low", "HSTS missing includeSubDomains",
                        "Strict-Transport-Security does not include 'includeSubDomains'.",
                        "Add 'includeSubDomains' to your HSTS header to protect subdomains too.")

    xcto = response.headers.get("X-Content-Type-Options", "")
    if xcto and xcto.strip().lower() != "nosniff":
        add_finding(findings, "Low", "X-Content-Type-Options has wrong value",
                    f"X-Content-Type-Options: {xcto} (expected: nosniff).",
                    "Set X-Content-Type-Options to exactly 'nosniff'.")


def check_cookies(response, final_url, findings, facts):
    """Check cookie flags and retention (expiry)."""
    facts["Cookies detected"] = len(response.cookies)
    long_lived_cookies = []

    for cookie in response.cookies:
        cookie_attrs = {k.lower() for k in (cookie._rest or {})}

        if not cookie.secure and final_url.startswith("https://"):
            add_finding(findings, "Medium", "Cookie missing Secure flag",
                        f"Cookie name: {cookie.name}",
                        "Add the Secure flag to cookies that should only be sent over HTTPS.")

        if "httponly" not in cookie_attrs:
            add_finding(findings, "Medium", "Cookie missing HttpOnly flag",
                        f"Cookie name: {cookie.name}",
                        "Add the HttpOnly flag to prevent JavaScript from accessing this cookie.")

        if "samesite" not in cookie_attrs:
            add_finding(findings, "Low", "Cookie missing SameSite flag",
                        f"Cookie name: {cookie.name}",
                        "Add SameSite=Lax or SameSite=Strict to protect against CSRF attacks.")

        # ── Cookie retention / expiry ─────────────────────
        if cookie.expires:
            now = time.time()
            days_until_expiry = (cookie.expires - now) / 86400
            if days_until_expiry > 730:  # more than 2 years
                long_lived_cookies.append(f"{cookie.name} (expires in ~{int(days_until_expiry)} days)")
            elif days_until_expiry > 365:
                long_lived_cookies.append(f"{cookie.name} (expires in ~{int(days_until_expiry)} days)")

    if long_lived_cookies:
        add_finding(findings, "Low", "Cookies with long retention period detected",
                    "Cookies expiring in over 1 year: " + "; ".join(long_lived_cookies),
                    "GDPR guidance recommends minimising cookie lifetimes. Consider reducing expiry to 6–12 months and explaining retention in your cookie policy.")


def check_gdpr_consent(soup, response, page_domain, findings, facts):
    """Check for cookie consent banners and privacy policy links."""

    # ── Consent banner via scripts ────────────────────────
    consent_scripts_found = []
    for script in soup.find_all("script", src=True):
        src_lower = script["src"].lower()
        for keyword in CONSENT_SCRIPT_KEYWORDS:
            if keyword in src_lower:
                consent_scripts_found.append(keyword)
                break

    # ── Consent banner via HTML elements ─────────────────
    page_html_lower = str(soup).lower()
    consent_html_found = [kw for kw in CONSENT_HTML_KEYWORDS if kw in page_html_lower]

    consent_detected = bool(consent_scripts_found or consent_html_found)
    facts["Cookie consent banner"] = "Detected" if consent_detected else "Not detected"

    if not consent_detected:
        add_finding(findings, "Medium", "No cookie consent banner detected",
                    "No known consent management platform or cookie banner HTML was found on the page.",
                    "If the site sets non-essential cookies (analytics, tracking, ads), a GDPR-compliant cookie consent banner is required for EU visitors. Consider adding CookieBot, OneTrust, CookieYes, or a similar tool.")
    else:
        evidence = ", ".join(consent_scripts_found + consent_html_found[:3])
        add_finding(findings, "Info", "Cookie consent mechanism detected",
                    f"Consent-related signals found: {evidence}.",
                    "Good. Make sure the banner blocks non-essential cookies until consent is given (not just notifies). Verify it covers all tracking scripts.")

    # ── Cookies set before consent ────────────────────────
    # If tracking/non-essential cookies are present on first load without consent,
    # that is a GDPR violation. We can signal this if tracking cookies exist alongside no banner.
    tracking_cookie_names = ["_ga", "_gid", "_fbp", "_fbc", "__utma", "__utmz",
                              "_hjid", "mp_", "ajs_", "_pin_unauth"]
    tracking_cookies_on_load = [c.name for c in response.cookies
                                 if any(c.name.startswith(t) for t in tracking_cookie_names)]
    facts["Tracking cookies on first load"] = len(tracking_cookies_on_load)
    if tracking_cookies_on_load and not consent_detected:
        add_finding(findings, "High", "Tracking cookies set without visible consent banner",
                    f"Tracking cookies found on first page load before any consent: {', '.join(tracking_cookies_on_load)}.",
                    "Under GDPR, non-essential cookies must not be set until the user actively consents. Remove or delay these cookies until consent is obtained.")

    # ── Privacy policy link ───────────────────────────────
    links = soup.find_all("a", href=True)
    privacy_link_found = any(
        any(pattern in (a.get_text(" ", strip=True).lower() + a["href"].lower())
            for pattern in PRIVACY_LINK_PATTERNS)
        for a in links
    )
    facts["Privacy policy link"] = "Found" if privacy_link_found else "Not found"
    if not privacy_link_found:
        add_finding(findings, "Medium", "No privacy policy link found",
                    "No link to a privacy or cookie policy page was detected.",
                    "GDPR requires a clearly accessible privacy policy. Add a link to your privacy policy page in the footer or header.")


def check_scripts_and_sri(soup, final_url, page_domain, findings, facts):
    """Check external scripts, tracking, chatbots, and SRI."""
    scripts = []
    external_scripts = []
    tracking_scripts = []
    chatbot_scripts = []
    missing_sri = []

    for script in soup.find_all("script"):
        src = script.get("src")
        if not src:
            continue
        full_src = urljoin(final_url, src)
        scripts.append(full_src)
        script_domain = get_domain(full_src)

        if script_domain and script_domain != page_domain:
            external_scripts.append(full_src)
            if not script.get("integrity"):
                missing_sri.append(full_src)

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
    facts["External scripts missing SRI"] = len(missing_sri)

    if missing_sri:
        add_finding(findings, "Medium", "External scripts loaded without Subresource Integrity (SRI)",
                    f"{len(missing_sri)} external script(s) have no integrity= attribute.",
                    "Add integrity and crossorigin attributes to external <script> tags so the browser rejects tampered files.")

    if len(external_domains) >= 8:
        add_finding(findings, "Medium", "Many third-party scripts detected",
                    f"{len(external_domains)} external script domains found.",
                    "Review old pixels, plugins, analytics tools, and widgets. Remove what is not needed.")

    if tracking_scripts:
        add_finding(findings, "Low", "Tracking or marketing scripts detected",
                    f"{len(tracking_scripts)} tracking-related scripts found.",
                    "Make sure tracking is explained in the privacy policy and controlled by cookie consent where required.")

    if chatbot_scripts:
        add_finding(findings, "Medium", "AI/chatbot script detected",
                    f"{len(chatbot_scripts)} possible chatbot or AI assistant scripts found.",
                    "Review what data the chatbot collects and whether visitors are clearly informed.")


def check_mixed_content(soup, final_url, findings, facts):
    """Flag HTTP resources loaded on an HTTPS page."""
    if not final_url.startswith("https://"):
        return  # not applicable on HTTP pages

    mixed = []
    for tag, attr in [("script", "src"), ("img", "src"), ("link", "href"),
                       ("iframe", "src"), ("audio", "src"), ("video", "src")]:
        for el in soup.find_all(tag):
            val = el.get(attr, "")
            if val.startswith("http://"):
                mixed.append(f"<{tag}> {val[:80]}")

    facts["Mixed content items"] = len(mixed)
    if mixed:
        add_finding(findings, "High", "Mixed content detected",
                    f"{len(mixed)} resource(s) loaded over HTTP on an HTTPS page: {mixed[0]}{'...' if len(mixed) > 1 else ''}",
                    "Change all resource URLs to HTTPS (or use protocol-relative URLs). Mixed content triggers browser warnings and may be blocked.")


def check_hidden_text(soup, findings):
    """Flag unusually long hidden text that could be prompt injection hiding."""
    hidden_elements = soup.find_all(style=re.compile(
        r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0",
        re.IGNORECASE
    ))
    long_hidden = [el.get_text(" ", strip=True) for el in hidden_elements
                   if len(el.get_text(" ", strip=True)) > 200]

    if long_hidden:
        add_finding(findings, "Medium", "Large hidden text blocks detected",
                    f"{len(long_hidden)} hidden element(s) with substantial text content found.",
                    "Review hidden text on the page. Long hidden content can be used for prompt injection targeting AI assistants that read page content.")


def check_api_key_leaks(soup, findings, facts):
    """Scan inline script content for exposed API keys or secrets."""
    inline_scripts = [s.get_text() for s in soup.find_all("script") if not s.get("src")]
    combined_js = " ".join(inline_scripts)

    matches_found = []
    for pattern, label in API_KEY_PATTERNS:
        if re.search(pattern, combined_js):
            matches_found.append(label)

    facts["Possible API key leaks in JS"] = len(matches_found)
    if matches_found:
        add_finding(findings, "Critical", "Possible API key or secret exposed in inline JavaScript",
                    f"Pattern(s) matched in page JS: {', '.join(matches_found)}.",
                    "Remove API keys from frontend code immediately. Move them to server-side environment variables. Rotate any exposed keys.")


def check_source_comments(soup, findings):
    """Look for developer comments that may leak sensitive info."""
    from bs4 import Comment
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    sensitive_comment_keywords = ["todo", "fix", "hack", "password", "secret",
                                   "key", "token", "credential", "admin", "debug",
                                   "remove", "temp", "test"]
    flagged = []
    for comment in comments:
        comment_lower = comment.lower()
        if any(kw in comment_lower for kw in sensitive_comment_keywords) and len(comment.strip()) > 10:
            flagged.append(comment.strip()[:120])

    if flagged:
        add_finding(findings, "Low", "Sensitive-looking HTML comments found",
                    f"{len(flagged)} comment(s) contain potentially sensitive keywords. First match: \"{flagged[0]}\"",
                    "Remove developer comments from production HTML. They can reveal internal logic, infrastructure, or credentials.")


def check_dns_records(domain, findings, facts):
    """Check SPF, DMARC, and CAA DNS records."""
    if not DNS_AVAILABLE:
        facts["DNS checks"] = "Skipped (dnspython not installed)"
        return

    # ── SPF ───────────────────────────────────────────────
    spf_found = False
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if txt.startswith("v=spf1"):
                spf_found = True
                facts["SPF record"] = "Found"
                if "-all" not in txt and "~all" not in txt:
                    add_finding(findings, "Medium", "SPF record has no hard/soft fail policy",
                                f"SPF record found but does not end with -all or ~all: {txt[:100]}",
                                "End your SPF record with '-all' (hard fail) to prevent unauthorised senders from spoofing your domain.")
                break
        if not spf_found:
            facts["SPF record"] = "Not found"
            add_finding(findings, "High", "No SPF DNS record found",
                        f"No SPF TXT record found for {domain}.",
                        "Add an SPF record to your DNS to prevent email spoofing. Example: 'v=spf1 include:_spf.google.com -all'")
    except Exception:
        facts["SPF record"] = "Lookup failed"

    # ── DMARC ─────────────────────────────────────────────
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        dmarc_found = False
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if txt.startswith("v=DMARC1"):
                dmarc_found = True
                facts["DMARC record"] = "Found"
                if "p=none" in txt:
                    add_finding(findings, "Low", "DMARC policy is set to 'none' (monitor only)",
                                f"DMARC record found but p=none means no enforcement: {txt[:100]}",
                                "Upgrade DMARC policy from p=none to p=quarantine or p=reject once you have reviewed DMARC reports.")
                break
        if not dmarc_found:
            facts["DMARC record"] = "Not found"
            add_finding(findings, "High", "No DMARC DNS record found",
                        f"No DMARC TXT record found at _dmarc.{domain}.",
                        "Add a DMARC record to your DNS to control how email receivers handle spoofed emails from your domain. Example: 'v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com'")
    except Exception:
        facts["DMARC record"] = "Lookup failed"

    # ── CAA ───────────────────────────────────────────────
    try:
        answers = dns.resolver.resolve(domain, "CAA")
        facts["CAA record"] = "Found"
        add_finding(findings, "Info", "CAA DNS record found",
                    "A CAA record restricts which Certificate Authorities can issue SSL certs for this domain.",
                    "Good. Keep CAA records up to date if you change your SSL certificate provider.")
    except dns.resolver.NoAnswer:
        facts["CAA record"] = "Not found"
        add_finding(findings, "Low", "No CAA DNS record found",
                    f"No CAA record found for {domain}.",
                    "Add a CAA record to restrict which CAs can issue SSL certificates for your domain. Example: '0 issue \"letsencrypt.org\"'")
    except Exception:
        facts["CAA record"] = "Lookup failed"


def check_prompt_injection(soup, findings):
    page_text = soup.get_text(" ", strip=True).lower()
    for phrase in PROMPT_INJECTION_PHRASES:
        if phrase in page_text:
            add_finding(findings, "High", "Prompt-injection-like text found",
                        f"Matched phrase: {phrase}",
                        "Review the page text and remove hidden or suspicious AI-instruction style content.")
            break


def check_forms(soup, final_url, findings, facts):
    forms = soup.find_all("form")
    facts["Forms detected"] = len(forms)
    for form in forms:
        action = form.get("action") or final_url
        full_action = urljoin(final_url, action)
        if full_action.startswith("http://"):
            add_finding(findings, "High", "Form submits over HTTP", full_action,
                        "Change the form action URL to HTTPS.")


def check_policy_files(base_url, findings, facts):
    llms_found, llms_text = fetch_policy_file(base_url, "/llms.txt")
    robots_found = check_policy_file(base_url, "/robots.txt")
    security_found = check_policy_file(base_url, "/.well-known/security.txt")

    facts["llms.txt"] = "Found" if llms_found else "Not found"
    facts["robots.txt"] = "Found" if robots_found else "Not found"
    facts["security.txt"] = "Found" if security_found else "Not found"

    if not llms_found:
        add_finding(findings, "Low", "No llms.txt found",
                    "/llms.txt did not return HTTP 200.",
                    "Add a clean llms.txt file to guide AI assistants to important pages.")
    else:
        # Basic llms.txt quality check
        if llms_text and len(llms_text.strip()) < 30:
            add_finding(findings, "Info", "llms.txt exists but appears minimal",
                        f"llms.txt is very short ({len(llms_text.strip())} characters).",
                        "Consider expanding llms.txt with proper sections: # AgentGuard, > Description, and relevant URLs.")

    if not security_found:
        add_finding(findings, "Low", "No security.txt found",
                    "/.well-known/security.txt did not return HTTP 200.",
                    "Add a security.txt file (RFC 9116) so security researchers know how to report vulnerabilities responsibly.")


# ──────────────────────────────────────────────────────────
# WORDPRESS CHECKS
# ──────────────────────────────────────────────────────────
def run_wordpress_passive_checks(response, final_url, base_url, soup):
    findings = []
    facts = {}
    html = response.text or ""
    lower_html = html.lower()

    wp_json_found = False
    try:
        wp_json_response = safe_get(urljoin(base_url, "/wp-json/"), timeout=8)
        wp_json_found = wp_json_response.status_code == 200
    except Exception:
        wp_json_found = False

    generator = soup.find("meta", attrs={"name": "generator"})
    generator_content = generator.get("content", "") if generator else ""

    theme_names = sorted(set(re.findall(r"/wp-content/themes/([^/\"'?#]+)", html, re.IGNORECASE)))
    plugin_names = sorted(set(re.findall(r"/wp-content/plugins/([^/\"'?#]+)", html, re.IGNORECASE)))

    wordpress_detected = (
        "wp-content" in lower_html or "wp-includes" in lower_html
        or "wordpress" in lower_html or wp_json_found
    )

    facts["WordPress detected"] = "Yes" if wordpress_detected else "No"
    facts["WordPress REST API"] = "Found" if wp_json_found else "Not found"
    facts["WordPress theme indicators"] = ", ".join(theme_names[:5]) if theme_names else "None found"
    facts["WordPress plugin indicators"] = f"{len(plugin_names)} found" if plugin_names else "None found"

    if wordpress_detected:
        add_finding(findings, "Info", "WordPress site detected",
                    "Public WordPress indicators were found.",
                    "Keep WordPress core, themes, and plugins updated. Use MFA and login rate limiting.")

    if generator_content and "wordpress" in generator_content.lower():
        add_finding(findings, "Low", "WordPress generator tag exposed",
                    f"Generator meta tag: {generator_content}",
                    "Remove public generator/version tags where possible.")

    if theme_names:
        add_finding(findings, "Low", "WordPress theme name visible",
                    f"Detected theme indicator: {theme_names[0]}",
                    "This is common, but outdated themes can be risky. Keep the active theme updated.")

    if plugin_names:
        add_finding(findings, "Low", "WordPress plugin names visible",
                    f"Detected {len(plugin_names)} plugin indicator(s).",
                    "Review visible plugins and keep them updated. Remove plugins that are no longer needed.")

    return {"facts": facts, "findings": findings}


# ──────────────────────────────────────────────────────────
# ACTIVE AUDIT
# ──────────────────────────────────────────────────────────
def run_active_audit(base_url):
    findings = []
    facts = {}
    checked_paths = []
    possible_exposed = 0

    for path in ACTIVE_PATHS:
        full_url = urljoin(base_url, path)
        try:
            r = safe_get(full_url, timeout=8, allow_redirects=True)
            checked_paths.append(f"{path}: HTTP {r.status_code}")
            body_sample = (r.text or "")[:1200].lower()

            sensitive_paths = ["/.env", "/.git/config", "/backup.sql",
                                "/database.sql", "/wp-config.php.bak"]

            if path in sensitive_paths:
                if r.status_code == 200 and len(r.text or "") > 20 and not looks_like_normal_html(body_sample):
                    possible_exposed += 1
                    add_finding(findings, "Critical", "Sensitive file may be publicly accessible",
                                f"{path} returned HTTP 200.",
                                "Block public access to this file immediately and rotate exposed secrets if confirmed.")

            if path == "/phpinfo.php" and r.status_code == 200 and "php version" in body_sample:
                add_finding(findings, "High", "phpinfo page may be exposed",
                            "/phpinfo.php returned PHP configuration information.",
                            "Remove phpinfo.php from the public website.")

            if path == "/server-status" and r.status_code == 200 and "apache server status" in body_sample:
                add_finding(findings, "High", "Server status page may be exposed",
                            "/server-status returned Apache status-like content.",
                            "Restrict server-status to trusted IP addresses or disable it.")

            if path == "/wp-login.php" and r.status_code == 200:
                add_finding(findings, "Info", "WordPress login page detected",
                            "/wp-login.php is publicly reachable.",
                            "Use MFA, strong passwords, login rate limiting, and regular WordPress updates.")

            if path == "/xmlrpc.php" and r.status_code in [200, 405]:
                add_finding(findings, "Low", "WordPress XML-RPC endpoint detected",
                            f"/xmlrpc.php returned HTTP {r.status_code}.",
                            "Disable XML-RPC if the site does not need it. Otherwise, rate-limit and monitor it.")

            if path == "/wp-json/wp/v2/users":
                if r.status_code == 200 and body_sample.strip().startswith("[") and \
                        ("slug" in body_sample or "avatar_urls" in body_sample or '"name"' in body_sample):
                    add_finding(findings, "Medium", "Possible WordPress user enumeration via REST API",
                                "/wp-json/wp/v2/users returned a public users-style response.",
                                "If public author data is not needed, restrict this endpoint or reduce exposed user information.")

        except Exception:
            checked_paths.append(f"{path}: error")

    facts["Active paths checked"] = len(ACTIVE_PATHS)
    facts["Possible exposed sensitive paths"] = possible_exposed
    facts["Active check summary"] = " | ".join(checked_paths)
    return {"facts": facts, "findings": findings}


# ──────────────────────────────────────────────────────────
# MAIN PASSIVE AUDIT ORCHESTRATOR
# ──────────────────────────────────────────────────────────
def run_passive_audit(url):
    findings = []
    facts = {}

    url = normalize_url(url)

    if not is_safe_url(url):
        return {
            "audit_incomplete": True,
            "risk": "Blocked",
            "facts": {"Audit status": "Blocked — unsafe URL"},
            "findings": [{
                "severity": "Critical",
                "title": "URL blocked for safety",
                "evidence": url,
                "fix": "Only public website URLs are allowed. Private IPs, localhost, and internal addresses are blocked."
            }]
        }

    try:
        response = safe_get(url, timeout=25, allow_redirects=True)
    except Exception as e:
        return {
            "audit_incomplete": True,
            "risk": "Audit incomplete",
            "facts": {"Audit status": "Incomplete", "Error": str(e)},
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
    root_domain = get_root_domain(final_url)

    facts["Final URL"] = final_url
    facts["Status code"] = response.status_code
    facts["HTTPS"] = "Yes" if final_url.startswith("https://") else "No"

    if not final_url.startswith("https://"):
        add_finding(findings, "Critical", "Website does not use HTTPS",
                    f"Final URL is {final_url}",
                    "Force HTTPS and redirect all HTTP traffic to HTTPS.")

    soup = BeautifulSoup(response.text, "html.parser")

    # Run all check modules
    check_security_headers(response, final_url, findings, facts)
    check_cookies(response, final_url, findings, facts)
    check_gdpr_consent(soup, response, page_domain, findings, facts)
    check_scripts_and_sri(soup, final_url, page_domain, findings, facts)
    check_mixed_content(soup, final_url, findings, facts)
    check_forms(soup, final_url, findings, facts)
    check_prompt_injection(soup, findings)
    check_hidden_text(soup, findings)
    check_api_key_leaks(soup, findings, facts)
    check_source_comments(soup, findings)
    check_policy_files(base_url, findings, facts)
    check_dns_records(root_domain, findings, facts)

    wp_result = run_wordpress_passive_checks(response, final_url, base_url, soup)
    facts.update(wp_result["facts"])
    findings.extend(wp_result["findings"])

    return {
        "facts": facts,
        "findings": findings,
        "final_url": final_url,
        "base_url": base_url
    }


# ──────────────────────────────────────────────────────────
# SCORING
# ──────────────────────────────────────────────────────────
def calculate_score(findings):
    penalties = {"Critical": 25, "High": 18, "Medium": 10, "Low": 4, "Info": 0}
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


# ──────────────────────────────────────────────────────────
# FLASK ROUTES
# ──────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    client_ip = request.remote_addr or "unknown"
    if is_rate_limited(client_ip):
        return """
        <h1>Too many requests</h1>
        <p>You have made too many scan requests. Please wait a minute and try again.</p>
        <p><a href="/">Go back</a></p>
        """, 429

    url = request.form.get("url", "").strip()
    if not url:
        return """
        <h1>No URL provided</h1>
        <p>Please enter a website URL to scan.</p>
        <p><a href="/">Go back</a></p>
        """

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
        risk = passive_result.get("risk", "Audit incomplete")
    else:
        if active and permission:
            active_result = run_active_audit(passive_result["base_url"])
            facts.update(active_result["facts"])
            findings.extend(active_result["findings"])
        score = calculate_score(findings)
        risk = get_risk(score)

    # Group findings by severity for display
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    findings_sorted = sorted(findings, key=lambda f: severity_order.index(f.get("severity", "Info"))
                             if f.get("severity") in severity_order else 99)

    facts_html = ""
    for key, value in facts.items():
        facts_html += f"<div class='fact'><strong>{escape(str(key))}</strong><br>{escape(str(value))}</div>"

    findings_html = ""
    for finding in findings_sorted:
        sev = finding["severity"]
        sev_style = SEVERITY_STYLES.get(sev, "background:#222; color:#fff;")
        findings_html += f"""
        <div class="finding">
            <span class="severity" style="{sev_style}">{escape(sev)}</span>
            <h3>{escape(finding["title"])}</h3>
            <p><strong>Evidence:</strong> {escape(finding["evidence"])}</p>
            <p><strong>Recommended fix:</strong> {escape(finding["fix"])}</p>
        </div>
        """

    if not findings_html:
        findings_html = "<p>No obvious issues found in this prototype scan.</p>"

    audit_mode = "Passive + Active" if active and permission else "Passive"
    score_display = f"{score}/100" if isinstance(score, int) else score

    # Severity summary counts
    severity_counts = {s: 0 for s in severity_order}
    for f in findings:
        if f["severity"] in severity_counts:
            severity_counts[f["severity"]] += 1

    summary_html = ""
    for sev in severity_order:
        count = severity_counts[sev]
        if count > 0:
            style = SEVERITY_STYLES.get(sev, "")
            summary_html += f'<span class="severity" style="{style}">{escape(sev)}: {count}</span> '

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
            a {{ color: #39e58c; }}
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
            .summary-bar {{
                margin: 16px 0;
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
                align-items: center;
            }}
            @media print {{
                body {{ background: white; color: black; }}
                .result-actions, .print-btn {{ display: none; }}
                .score, .fact, .finding, .safety-note {{
                    background: white; color: black; border: 1px solid #ccc;
                }}
                .score-number {{ color: black; }}
                a {{ color: black; }}
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
            .finding {{ margin-bottom: 16px; }}
            .severity {{
                display: inline-block;
                padding: 6px 10px;
                border-radius: 999px;
                font-size: 13px;
                font-weight: bold;
            }}
            @media (max-width: 800px) {{
                .top, .facts {{ grid-template-columns: 1fr; }}
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
                <strong>Scan safety:</strong> Passive audit reviews public website signals only. Active audit checks a small list of common public paths when permission is confirmed. This prototype does not brute-force passwords, exploit vulnerabilities, submit forms, or stress test websites.
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
            <div class="summary-bar">
                <strong>Finding summary:</strong> {summary_html}
            </div>
            <h2>Website facts</h2>
            <div class="facts">{facts_html}</div>
            <h2>Findings and recommendations</h2>
            {findings_html}
        </div>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(debug=True)

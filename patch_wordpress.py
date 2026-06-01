from pathlib import Path

p = Path("app.py")
s = p.read_text()

if "def run_wordpress_passive_checks" in s:
    print("WordPress module already added.")
    raise SystemExit

s = s.replace(
'''    "/wp-login.php",
    "/xmlrpc.php"
]''',
'''    "/wp-login.php",
    "/xmlrpc.php",
    "/wp-json/wp/v2/users"
]'''
)

helper = r'''

def run_wordpress_passive_checks(response, final_url, base_url, soup):
    findings = []
    facts = {}

    html = response.text or ""
    lower_html = html.lower()

    wp_json_found = False
    try:
        wp_json_response = requests.get(
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

'''

s = s.replace(
"\ndef looks_like_normal_html(text):",
helper + "\ndef looks_like_normal_html(text):"
)

target = '''    if not llms_found:
        add_finding(
            findings,
            "Low",
            "No llms.txt found",
            "/llms.txt did not return HTTP 200.",
            "Add a clean llms.txt file to guide AI assistants to important pages."
        )

    return {
'''

replacement = '''    if not llms_found:
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
'''

if target not in s:
    raise SystemExit("Could not find passive audit insert point.")

s = s.replace(target, replacement)

active_insert = '''            if path == "/wp-json/wp/v2/users":
                if r.status_code == 200 and body_sample.strip().startswith("[") and ("slug" in body_sample or "avatar_urls" in body_sample or '"name"' in body_sample):
                    add_finding(
                        findings,
                        "Medium",
                        "Possible WordPress user enumeration via REST API",
                        "/wp-json/wp/v2/users returned a public users-style response.",
                        "If public author data is not needed, restrict this endpoint or reduce exposed user information."
                    )

        except Exception as e:
'''

s = s.replace("        except Exception as e:\n", active_insert)

if "import re" not in s:
    s = s.replace("import requests\n", "import requests\nimport re\n")

p.write_text(s)
print("WordPress module added successfully.")

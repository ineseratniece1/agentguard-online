# AgentGuard Website Audit

AgentGuard is a CyberStart final project prototype for website security and AI-agent exposure auditing.

It is a working online web app where a user can enter a website URL and run a basic audit. The tool checks public website security signals, AI-related exposure signals, and WordPress exposure indicators.

Live demo:

https://agentguard-online.onrender.com

GitHub repository:

https://github.com/ineseratniece1/agentguard-online

## What it does

AgentGuard checks:

- HTTPS and status code
- security headers
- cookies
- forms
- external scripts
- tracking scripts
- chatbot / AI indicators
- robots.txt
- llms.txt
- security.txt
- WordPress indicators
- WordPress REST API
- visible theme and plugin clues
- common public exposure paths in active mode

## Passive audit

Passive audit is the default mode.

It only checks public website signals and does not attack the website.

It reviews headers, cookies, forms, scripts, policy files, AI indicators, and WordPress signs.

## Active audit

Active audit is optional and requires permission.

Before it runs, the user must confirm:

I have permission.

The active audit checks a small list of common public paths, such as:

- /.env
- /.git/config
- /backup.zip
- /backup.sql
- /database.sql
- /wp-login.php
- /xmlrpc.php
- /phpinfo.php
- /server-status

It does not brute-force passwords, exploit vulnerabilities, submit forms, upload files, or stress test websites.

## AI exposure checks

The AI part checks for:

- llms.txt
- robots.txt
- chatbot or AI script indicators
- third-party scripts
- tracking scripts
- hidden prompt-like text
- forms that may collect user data

This makes the tool more modern than a basic website security scanner.

## WordPress exposure checks

The WordPress module checks:

- whether WordPress is detected
- whether the WordPress REST API is visible
- visible theme indicators
- visible plugin indicators
- wp-login.php
- xmlrpc.php
- possible public user enumeration risk

The tool does not brute-force WordPress logins.

## Technologies used

This project uses:

- Python
- Flask
- HTML
- CSS
- JavaScript
- Requests
- BeautifulSoup
- Gunicorn
- GitHub
- Render

Python runs the audit logic.  
Flask connects the web page with the Python backend.  
HTML, CSS, and JavaScript create the user interface.  
GitHub stores the code.  
Render hosts the live app online.

## How to run locally

Clone the repository:

git clone https://github.com/ineseratniece1/agentguard-online.git

Go into the project folder:

cd agentguard-online

Create virtual environment:

python3 -m venv .venv

Activate it:

source .venv/bin/activate

Install dependencies:

pip install -r requirements.txt

Run the app:

python app.py

Open in browser:

http://127.0.0.1:5000

## Safety note

This is an educational cybersecurity prototype.

It does not:

- brute-force passwords
- exploit vulnerabilities
- bypass firewalls
- perform stealth scanning
- submit malicious payloads
- stress test websites

Active audit should only be used on websites the user owns or is authorised to test.

## Project status

Current version includes:

- working online prototype
- passive audit
- active audit with permission checkbox
- AI exposure checks
- WordPress exposure checks
- loading animation
- AgentGuard logo
- printable / saveable report
- deployment on Render

## Future improvements

Possible next steps:

- better risk scoring
- PDF report generation
- separate business-owner and developer reports
- CVE lookup for vulnerable WordPress plugins
- scheduled monitoring
- better llms.txt format validation
- more detailed AI-agent risk detection

# Aegis: Automated Web Application Security Assessment System

Aegis is a small web based tool I built for my Advanced internship at THE ARZENS (Private) Limited. You enter a website URL, and Aegis runs some safe checks on it and shows a report explaining what is weak and how to fix it.

## What it checks
- **HTTPS:** whether the site works over HTTPS and redirects HTTP to HTTPS
- **Security headers:** Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Cookies:** Secure, HttpOnly and SameSite attributes
- **Information disclosure:** server version or technology shown in the Server and X-Powered-By headers

## How the report works
- Every check is marked as pass, fail or warning
- Each finding has a severity (High, Medium or Low)
- Each finding has an explanation, impact, recommended fix and OWASP reference
- An overall score out of 100 and a grade (A to F) is calculated from all the findings

## Technologies
Python, Flask, Requests, HTML and CSS

## How to run
```
pip install -r requirements.txt
python app.py
```
Then open http://127.0.0.1:5000 in your browser.

## Ethical use
Only test websites that you own or have permission to test. Aegis only sends normal read only requests and does not exploit anything.

## Limitations
Aegis is only a preliminary checker. It cannot find deeper problems like SQL injection or broken access control, and it is not a replacement for a full penetration test.

Author: Umaymah Gul

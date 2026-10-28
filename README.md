# Phishing Awareness Analyzer

An educational, privacy-preserving, enterprise-grade cybersecurity tool for detecting and explaining social engineering indicators in suspicious URLs and phishing email lures.

This application provides local static analysis, deterministic risk modeling, and defensive security engineering without generating outbound network traffic or persisting sensitive data.

---

## 1. Project Overview & Problem Statement

Phishing remains the primary initial access vector in modern cyber intrusions. Threat actors exploit cognitive biases&mdash;such as artificial urgency, institutional authority, and threat of severe consequences&mdash;to coerce users into surrendering authentication credentials or executing malicious payloads.

While enterprise email gateways and dynamic analysis sandboxes play a crucial role in enterprise defense, security awareness training and immediate triage tools are necessary for rapid local screening. However, analyzing suspicious links dynamically poses acute risks:
- Resolving DNS queries or connecting to suspicious servers leaks user IP addresses and active beaconing telemetry to threat actors.
- Cloud-based scanners frequently persist user-submitted strings, risking the disclosure of internal tokens or sensitive enterprise data.

The **Phishing Awareness Analyzer** solves this challenge through **strictly offline, deterministic static evaluation**. It inspects lexical structures, psychological manipulation cues, and known evasion patterns directly in memory with **zero network egress** and **zero data persistence**.

---

## 2. Key Architecture & Modular Design

The project is structured according to modular Python architectural best practices, decoupling presentation, routing, heuristic inspection engines, and scoring logic.

```
phishing_awareness_analyzer/
├── app/
│   ├── __init__.py               # Flask application factory, CSP & security headers, error handlers
│   ├── config.py                 # Security headers, max payload limits (100 KB), runtime settings
│   ├── routes.py                 # Hardened blueprint routes: UI index, /api/analyze-url, /api/analyze-email
│   ├── analyzers/
│   │   ├── __init__.py           # Package exports for clean imports
│   │   ├── url_analyzer.py       # Safe static URL parsing and RFC 3986 heuristic rules
│   │   ├── email_analyzer.py     # Regex/heuristic email text & header-metadata parsing
│   │   └── scoring_engine.py     # Centralized, deduplicated risk scoring engine
│   ├── data/
│   │   ├── __init__.py
│   │   └── sample_payloads.py    # Reference test payloads
│   ├── static/
│   │   ├── css/
│   │   │   └── styles.css        # Enterprise dark navy/black cybersecurity SaaS theme
│   │   └── js/
│   │       └── main.js           # Asynchronous Fetch API, mode switching, DOM updates, XSS prevention
│   └── templates/
│       ├── base.html             # HTML5 layout shell, compact navbar, semantic footer
│       └── index.html            # URL scanner hero centerpiece, Email mode, Results dashboard
├── data/                         # Local benchmark datasets (gitignored)
│   └── malicious_phish.csv       # Kaggle 651k benchmark dataset
├── reports/                      # Benchmark reports and metrics
│   ├── kaggle_benchmark_report.md# Comprehensive 651k evaluation report
│   └── kaggle_benchmark_metrics.json # Machine-readable benchmark metrics
├── scripts/                      # Standalone CLI tools and dataset inspectors
│   └── inspect_dataset.py        # Streaming dataset validator (null checks, schema, distribution)
├── tests/
│   ├── __init__.py
│   ├── test_url_analyzer.py      # Unit tests for URL heuristics, edge cases, IDN/punycode
│   ├── test_email_analyzer.py    # Unit tests for urgency, credentials, threats, link heuristics
│   ├── test_scoring_engine.py    # Unit tests for scoring weights, deduplication, thresholds
│   ├── test_routes.py            # Integration tests via Flask test_client
│   ├── test_security_audit.py    # Automated security regression suite (headers, DoS, XSS, zero-network)
│   └── benchmark_kaggle_dataset.py # Streaming full-dataset benchmark runner (651k URLs)
├── .gitignore                    # Python cache, virtual environments (.venv), IDE files, data/
├── requirements.txt              # Stable, pinned dependencies (Flask, Werkzeug, pytest)
├── run.py                        # Root entry point to execute the Flask development server
└── README.md                     # Comprehensive project documentation & run guide
```

---

## 3. Heuristic Rules & Detection Capabilities

### A. URL Static Inspection (`url_analyzer.py`)
Standard libraries (`urllib.parse`, `ipaddress`, `re`) evaluate targets strictly in memory:
1. **Protocol & Dangerous Schemes**: Validates scheme against `http`/`https`. Immediately flags dangerous non-web protocols like `javascript:`, `data:`, `file:`, `ftp:`, and `blob:`.
2. **Raw IP Address as Host**: Detects direct IPv4 and IPv6 hosts (e.g., `http://192.168.1.100/`) frequently used to bypass domain reputation blocklists.
3. **Transport Security Evaluation**: Clarifies the distinction between cleartext HTTP and HTTPS. Notes that modern phishers leverage free SSL certificates, meaning HTTPS does not imply a site is benign.
4. **Known URL Shorteners**: Identifies domain redirection services (e.g., `bit.ly`, `tinyurl.com`, `t.co`, `ow.ly`, `is.gd`) used to mask ultimate destinations.
5. **Sensitive Keyword Tokens**: Flags authentication and financial keywords (`login`, `verify`, `account`, `banking`, `credential`, `signin`, `wallet`, `password`, `security`) embedded in paths or query strings.
6. **Subdomain Anomalies & Depth**: Detects excessive subdomain depth (> 3 levels) used to truncate visible address bars on mobile screens.
7. **Brand Impersonation in Subdomains & Paths**: Detects well-known brand names (`paypal`, `microsoft`, `apple`, `google`, etc.) configured as subdomains or embedded in path segments on unrelated hosts (e.g., `paypal.com.verify.attacker.net` or `http://192.168.1.100/paypal.com/login`).
8. **Userinfo Redirection (@ Trick)**: Identifies `@` characters in URLs where browsers treat preceding strings as user credentials and redirect to the host following the symbol.
9. **Punycode & IDN Homographs**: Detects `xn--` Internationalized Domain Name prefixes commonly weaponized to visually impersonate familiar ASCII brands with lookalike Unicode characters.
10. **Typosquatting & Compound Names**: Identifies common substitution patterns (e.g., `paypa1`, `arnazon`, `micros0ft`) and hyphenated brand compounds (`secure-login-apple.com`, `paypal-security-update.com`).
11. **Heavy Percent-Encoding**: Detects excessive hexadecimal URL encoding (`%20`, `%2F`, `%40`, etc.) designed to evade string matching.
12. **Non-Standard Ports**: Detects explicit custom ports (e.g., `:8080`, `:8443`, `:8888`) bypassing standard port 80/443 configurations.

### B. Email Content & Lure Inspection (`email_analyzer.py`)
1. **Urgency & Coercive Pressure**: Scans for panic-inducing ultimatums (e.g., *"within 24 hours"*, *"act immediately"*, *"account will be suspended"*, *"password will expire today"*).
2. **Threat Language & Extortion**: Detects punitive rhetoric including legal action, police notification, collections, and immediate termination.
3. **Credential & Financial Solicitation**: Flags direct solicitations for passwords, PINs, two-factor tokens (2FA/MFA), banking numbers, identity confirmations, or gift card purchases.
4. **Embedded Hyperlink Extraction**: Discovers all external web addresses in the email body and runs them through the URL analyzer engine to surface high-risk links.
5. **Generic Salutations**: Identifies impersonal greetings typical of mass automated phishing blasts (*"Dear Customer"*, *"Undisclosed Recipient"*).
6. **Sender Display Name Mismatch**: Compares the display name against the authenticated sender domain (e.g., `PayPal Support <alert@random-domain.xyz>`) to detect identity spoofing.

---

## 4. Centralized Risk Scoring Model

The risk engine (`scoring_engine.py`) maps detected indicators to deterministic weights, deduplicates related triggers to prevent artificial inflation, and enforces strict score boundaries:

$$\text{Final Score} = \min\left(100, \sum_{\text{unique } i} \text{Weight}(i)\right)$$

| Severity Tier | Points | Example Triggers |
| :--- | :---: | :--- |
| **CRITICAL** | **35** | Raw IP host, Userinfo `@` trick, Direct credential/2FA requests, Critical embedded URL |
| **HIGH** | **20&ndash;25** | Known URL shorteners, Typosquatted domain, Subdomain/path brand impersonation, Severe extortion threats |
| **MEDIUM** | **10** | Cleartext HTTP, Sensitive path keywords, Punycode IDN, Non-standard ports, Urgency phrases |
| **LOW** | **5** | Generic greetings, mild formatting cues |
| **INFORMATIONAL**| **0** | Standard HTTPS transport present, Embedded benign links |

### Risk Classification Categories
- **No Obvious Threat Detected (0 &ndash; 24)** &mdash; Clean Emerald (`#10b981`): *"No immediate suspicious indicators detected by these static checks"* (when clean), or minor potential indicators noted. Never labeled definitively safe.
- **Suspicious (25 &ndash; 59)** &mdash; Warning Amber (`#f59e0b`): *"Suspicious indicators detected. Exercise caution and verify via independent channels."*
- **High Risk (60 &ndash; 100)** &mdash; Critical Crimson (`#ef4444`): *"Multiple high-severity phishing indicators detected. Do not interact, click links, or supply credentials."*

---

## 5. Security Hardening & Privacy Constraints

- **Strictly Offline & Static**: Zero DNS requests, zero socket connections, zero HTTP GET/POST queries to submitted targets.
- **Privacy Guaranteed**: Text and URLs are processed in transient memory; submissions are never logged, stored in databases, or persisted to disk.
- **Payload Size Limits**: Strict `MAX_CONTENT_LENGTH = 102400` (100 KB max) enforced at the Flask layer to prevent resource exhaustion or memory denial-of-service.
- **XSS & Injection Protection**: User strings are safely escaped before rendering in the DOM using standard HTML entity serialization.
- **Security Headers**: Injected via `@app.after_request`:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self';`
  - `Referrer-Policy: no-referrer`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- **Hardened Error Handlers**: Dedicated 400, 404, 405, 413, and 500 error handlers returning structured JSON for API calls.

---

## 6. Windows Setup & Local Execution Guide

Follow these step-by-step instructions in PowerShell or Windows Terminal:

### Step 1: Open Terminal in Project Directory
Open your terminal in the root of the project directory:
```powershell
cd phishing_awareness_analyzer
```

### Step 2: Create a Virtual Environment
```powershell
python -m venv .venv
```

### Step 3: Activate the Virtual Environment
```powershell
.\.venv\Scripts\activate
```

### Step 4: Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 5: Run the Automated Test Suite
```powershell
python -m unittest discover -s tests -v
```
*All 63 automated unit, integration, and security tests will pass with 100% success.*

### Step 6: Launch the Web Application
```powershell
python run.py
```

### Step 7: Access the Dashboard
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 7. Interactive Triage Capabilities

The interface provides two primary assessment modes:
1. **Primary URL Scanner**:
   - Inspect any candidate URL or IP address in memory.
   - Evaluates scheme, authority, subdomains, typosquatting patterns, and evasion markers.
   - Provides Clear and Analyze actions with instant in-memory feedback.
2. **Email Content Analyzer**:
   - Inspect message lures, urgent extortion language, credential solicitations, and spoofed display headers.
   - Automatically extracts and assesses all embedded hyperlinks found inside message bodies.

---

## 8. Kaggle Dataset Benchmark & Empirical Validation

The analyzer includes an automated, streaming full-dataset benchmark runner ([`tests/benchmark_kaggle_dataset.py`](tests/benchmark_kaggle_dataset.py)) that validates the production heuristic pipeline against all **651,191 records** of the Kaggle `malicious_phish.csv` dataset under strictly offline conditions (zero DNS/network traffic).

### Full-Scale Empirical Results (651,191 URLs)
- **Throughput:** 3,734.8 records / second (evaluated in 2.91 minutes)
- **Benign Specificity:** **95.93%** (410,695 / 428,103 clean URLs correctly identified, FPR: 4.07%)
- **Phishing Detections:** **10,295** confirmed phishing campaigns identified purely through lexical heuristics
- **Malware Detections:** **56.74%** recall (18,453 / 32,520) on executable payload dropper links
- **Investigative Sample Verified:** `https://signin.eby.de.zukruygxctzmmqi.civpro.co.za` scores **90/100 (HIGH RISK)**

| Ground Truth Class | Total Records | Correctly Evaluated | Classification Rate | Incorrectly Evaluated | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`benign`** | 428,103 | 410,695 (True Negative) | **95.93% (Specificity)** | 17,408 (False Positive) | 4.07% (FPR) |
| **`phishing`** | 94,111 | 10,295 (True Positive) | **10.94% (Recall)** | 83,816 (False Negative) | 89.06% (FNR) |
| **`malware`** | 32,520 | 18,453 (True Positive) | **56.74% (Recall)** | 14,067 (False Negative) | 43.26% (FNR) |
| **`defacement`** | 96,457 | 206 (True Positive) | **0.21% (Recall)** | 96,251 (False Negative) | 99.79% (FNR) |

*For complete error analysis, confusion matrices, and architectural findings, see [`reports/kaggle_benchmark_report.md`](reports/kaggle_benchmark_report.md) and [`reports/kaggle_benchmark_metrics.json`](reports/kaggle_benchmark_metrics.json).*

### How to Run the Benchmark
Execute the streaming benchmark script:
```powershell
python tests/benchmark_kaggle_dataset.py --output reports/kaggle_benchmark_metrics.json
```
To run a fast test on a subset:
```powershell
python tests/benchmark_kaggle_dataset.py --limit 10000
```

---

## 9. Limitations & Educational Boundaries

To ensure transparent cybersecurity reporting, the following limitations must be recognized:
- **Heuristics Are Advisory**: Heuristic scoring evaluates surface-level lexical patterns. It cannot detect zero-day spear-phishing crafted with sophisticated tone mimicry.
- **Absence of SPF/DKIM/DMARC Verification**: Static text processing cannot inspect RFC 5321/5322 email headers, cryptographic DKIM signatures, SPF DNS records, or DMARC enforcement policies.
- **Zero Live Reputation Feeds**: Without external API calls, freshly registered phishing domains or weaponized redirects that lack obvious lexical indicators cannot be identified.
- **Never "Guaranteed Safe"**: The system never declares a sample "Guaranteed Safe." Clean inputs receive a `No Obvious Threat Detected` rating accompanied by advice to maintain ongoing cyber vigilance.

---

## 10. Verification & Walkthrough Evidence

When presenting or documenting the application, capture the following operational evidence:

| Check # | View to Capture | Purpose & Description |
| :---: | :--- | :--- |
| **Check 1** | **Passing Test Suite in Terminal** | Run `python -m unittest discover -s tests -v` in PowerShell showing 63 tests passing with `OK`. |
| **Check 2** | **Application Launch** | Terminal output showing `python run.py` running on `http://127.0.0.1:5000`. |
| **Check 3** | **Suspicious / High-Risk URL Result** | Analyze `http://paypa1-security-verification.com/login` to show score meter, triggered indicators (Typosquatting, HTTP Cleartext, Sensitive Tokens), and category badge. |
| **Check 4** | **Clean URL Result** | Analyze `https://www.google.com` to show low score and `No Obvious Threat Detected` clean badge. |
| **Check 5** | **Phishing Email Analysis** | Switch to Email Analyzer tab, submit an urgent lure with suspended account threats to show score, trigger pill cards, and extracted links section. |
| **Check 6** | **Kaggle Benchmark Execution** | Terminal run of `benchmark_kaggle_dataset.py` demonstrating 651k evaluation at ~3,700 rec/s with 95.93% benign specificity. |

---

## 11. Manual Git & GitHub Setup Guide

To upload this completed project to your GitHub repository manually:

```powershell
# 1. Initialize git repository
git init

# 2. Add all files (respecting .gitignore)
git add .

# 3. Create initial commit
git commit -m "feat: complete Phishing Awareness Analyzer for CodeNova Task 2"

# 4. Set main branch
git branch -M main

# 5. Link to your personal GitHub repository (replace with your repo URL)
git remote add origin https://github.com/<your-username>/phishing_awareness_analyzer.git

# 6. Push code to GitHub
git push -u origin main
```

---

## 12. Future Enhancements

- Integration with optional offline public suffix lists (PSL) for even broader international domain parsing.
- Optional local parsing of `.eml` and `.msg` raw RFC 822 email files to inspect full header chains.
- Optical Character Recognition (OCR) heuristics to evaluate image-only phishing lures.
- Exportable PDF threat assessment reports for security operations center (SOC) awareness training.

# 🛡️ Phishing URL Detector Using Python

> **Protect Yourself from Malicious Websites & Phishing Attacks**  
> An explainable, offline, rule-based cybersecurity project built with Python and Streamlit.

---

## 📌 1. Project Introduction

Phishing is one of the oldest and most dangerous cyber threats on the Internet today. Attackers disguise malicious links to look like legitimate websites (such as PayPal, Google, Microsoft, or banking portals) to deceive users into revealing confidential information, such as login passwords, credit card numbers, or cryptocurrency private keys.

The **Phishing URL Detector** is an interactive, web-based cybersecurity application developed using **Python 3** and **Streamlit**. It allows users to inspect any given URL in real time and ascertain whether it is **LOW RISK**, **MEDIUM RISK**, or **HIGH RISK**.

Unlike opaque "black-box" systems, this application operates using **transparent, deterministic heuristic rules** based on real-world attack vectors. Best of all, **it performs 100% offline lexical analysis without visiting or making network connections to suspicious web servers**, ensuring total safety for the investigator.

---

## 🎯 2. Problem Statement

Every day, millions of phishing emails, SMS messages (smishing), and fraudulent social media links are distributed across the globe. Traditional users often lack the technical expertise to analyze the subtle lexical indicators that differentiate a legitimate link from an attacker's fake domain.

Furthermore, running live web queries or visiting suspicious URLs directly can expose the user's machine to drive-by downloads, IP tracking, or browser exploit kits.

**The Solution:** A lightweight, offline, rule-based URL detection system that dissects the syntax and structural patterns of any web address and generates an instant, human-understandable risk score.

---

## 🏆 3. Project Objectives

1. **Safety First**: Analyze URLs entirely offline through lexical and structural inspection without issuing HTTP/socket requests to potentially hostile hosts.
2. **Transparent Scoring**: Calculate an objective risk score (0–100) based on 8 core attack indicators.
3. **Categorized Verdicts**: Classify targets into three distinct risk tiers:
   - 🟢 **LOW RISK (0 – 29)**: Standard domain structure with no major anomalies detected.
   - 🟡 **MEDIUM RISK (30 – 64)**: Noticeable irregularities (e.g., missing SSL, suspicious keywords, or shortener).
   - 🔴 **HIGH RISK (65 – 100)**: Multiple critical phishing patterns (e.g., raw IP address, deceptive `@` symbol, excessive subdomains, or abusive TLD).
4. **Beginner-Friendly Architecture**: Maintain a clean separation between the detection logic (`detector.py`) and the web frontend (`app.py`).
5. **Interactive Cybersecurity Dashboard**: Provide a modern dark-themed UI featuring instant sample presets, metric cards, visual gauges, and detailed rule-by-rule breakdowns.

---

## 💻 4. Technologies Used

- **Python 3.10+**: Core programming language.
- **Streamlit**: Fast, reactive web framework for building data science and cybersecurity user interfaces.
- **Pandas**: Efficient handling, formatting, and batch display of URL datasets.
- **Regular Expressions (`re`)**: Pattern matching for IP addresses, domain validation, and character extraction.
- **Python Standard Libraries**:
  - `urllib.parse` (`urlparse`): For decomposing URLs into protocol, hostname, path, and query strings.
  - `ipaddress`: For safe, standard-compliant IPv4 and IPv6 detection.
  - `typing`: Type hinting for clean and maintainable code.

> **Note on Safety:** This project explicitly avoids making web requests or requiring third-party paid API keys. All calculations are computed locally in microseconds.

---

## 🏗️ 5. System Architecture

The following diagram illustrates how an input URL flows through the detection pipeline:

```
+-------------------------------------------------------------+
|                     User Interface (app.py)                 |
|   - URL Input Field / Sample Test Buttons                   |
|   - Streamlit Reactive Frontend                             |
+-------------------------------------------------------------+
                              │
                              ▼
+-------------------------------------------------------------+
|                 Input Validation (validate_url)             |
|   - Checks for empty input, internal whitespace,            |
|     illegal characters, and valid syntax                    |
+-------------------------------------------------------------+
                              │
                              ▼
+-------------------------------------------------------------+
|            URL Decomposition (urllib.parse.urlparse)        |
|   - Scheme, Hostname, Path, Query Parameters, Subdomains    |
+-------------------------------------------------------------+
                              │
                              ▼
+-------------------------------------------------------------+
|              8 Core Rule Heuristic Engine                   |
|   [1] URL Length Check            (max 15 pts)              |
|   [2] HTTPS Protocol Check        (max 15 pts)              |
|   [3] IP-Based Hostname Check     (max 30 pts)              |
|   [4] Suspicious Keywords Check   (max 20 pts)              |
|   [5] URL Shortener Check         (max 15 pts)              |
|   [6] Excessive Subdomain Check   (max 15 pts)              |
|   [7] Special Characters (@, -, //)(max 30 pts)             |
|   [8] Suspicious TLD / Punycode   (max 25 pts)              |
+-------------------------------------------------------------+
                              │
                              ▼
+-------------------------------------------------------------+
|              Scoring & Risk Aggregation Engine              |
|   - Raw Points Summed & Capped at 100                       |
|   - Risk Tier Mapping: LOW (0-29) | MEDIUM (30-64) | HIGH (65+) |
+-------------------------------------------------------------+
                              │
                              ▼
+-------------------------------------------------------------+
|                     Final Output Dashboard                  |
|   - Threat Badge & Color Coding (Green / Amber / Crimson)   |
|   - Numeric Score Gauge & Analysis Summary                  |
|   - Detailed Indicator Cards & Safety Recommendations       |
+-------------------------------------------------------------+
```

---

## ⚙️ 6. Working Procedure

1. **Input Reception**: The user pastes a URL into the input field or selects one of the pre-loaded quick sample buttons.
2. **Sanitization & Parsing**:
   - The application trims extraneous whitespace.
   - If a scheme is omitted (e.g. `google.com`), the parser normalizes it with `http://` for structural inspection.
   - The hostname, path, and subdomains are parsed into distinct components.
3. **Multi-Vector Rule Evaluation**: Each of the 8 rules runs independently, evaluating specific risk factors and assigning weighted penalty points when suspicious traits are uncovered.
4. **Score Aggregation**: Individual points are summed. The aggregate score is bounded between 0 and 100.
5. **Verdict Generation**:
   - Score `< 30`: Classified as **LOW RISK**.
   - Score `30` to `64`: Classified as **MEDIUM RISK**.
   - Score `>= 65`: Classified as **HIGH RISK**.
6. **Result Display**: The Streamlit interface updates immediately, rendering visual metrics, expandable structural breakdowns, and actionable cybersecurity guidance.

---

## 🔍 7. The 8 Core Detection Rules

| # | Rule Name | Max Points | Why It Indicates Phishing |
|---|---|:---:|---|
| **1** | **URL Length Detection** | `15 pts` | Real URLs are usually concise. Phishers use long URLs (>54 or >75 chars) to hide malicious tokens or simulate legitimate paths. |
| **2** | **HTTPS Protocol Detection** | `15 pts` | Legitimate modern services use encrypted SSL/TLS. Unencrypted HTTP URLs transmit credentials in plaintext and are vulnerable to interception. |
| **3** | **IP Address Hostname Detection** | `30 pts` | Direct IP addresses (e.g., `http://192.168.1.1/login`) are used by attackers to bypass domain name registration and DNS blacklists. |
| **4** | **Suspicious Keyword Detection** | `20 pts` | Phishing links employ urgent or sensitive keywords like `login`, `verify`, `banking`, `password`, `wallet`, or `recovery`. |
| **5** | **URL Shortener Service Detection** | `15 pts` | Services like `bit.ly` or `tinyurl.com` mask the actual destination, preventing users from seeing where the link leads before clicking. |
| **6** | **Excessive Subdomain Detection** | `15 pts` | Legitimate sites have 0–1 subdomains. Phishers chain 3+ subdomains (e.g. `paypal.com.verify.account-portal.xyz`) to deceive users on mobile screens. |
| **7** | **Special Character Detection** | `30 pts` | Checks for `@` (browser credential injection trick), multiple hyphens `-` (brand spoofing), and `//` in URL path (open redirects). |
| **8** | **Suspicious Domain Pattern Detection** | `25 pts` | Identifies cheap, high-abuse TLDs (`.xyz`, `.top`, `.click`, `.buzz`), Punycode (`xn--`), and hex-encoded characters (`%20`, `%2e`). |

---

## 📁 8. Project File Structure

```text
phishing-url-detector/
│
├── app.py                # Streamlit web application & cybersecurity dashboard
├── detector.py           # Core detection engine (8 rules & scoring logic)
├── sample_urls.csv       # Pre-loaded test cases for batch evaluation & demo
├── test_detector.py      # Automated unit test suite (18 test scenarios)
├── requirements.txt      # Project Python dependencies
├── run.bat               # Windows one-click batch launcher
├── run.ps1               # Windows PowerShell launcher
└── README.md             # Complete project documentation
```

---

## 🚀 9. Installation & Setup Guide

### Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, 3.14, or 3.15 installed on your machine.
- Git (optional).

### Step 1: Open Terminal in VS Code
Open Visual Studio Code, press <kbd>Ctrl</kbd> + <kbd>`</kbd> (or go to **Terminal > New Terminal**), and navigate to the project directory:

```bash
cd D:\Coding\phishing-url-detector
```

### Step 2: Create a Virtual Environment (Recommended)
Creating a virtual environment ensures dependencies remain isolated and clean:

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**On Windows (Command Prompt):**
```cmd
python -m venv .venv
.\.venv\Scripts\activate.bat
```

**On Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Required Dependencies
Run pip to install the required packages:

```bash
pip install -r requirements.txt
```

---

## 🖥️ 10. How to Run the Application

### Option A: Standard Command (VS Code Terminal)
With your virtual environment activated, execute:

```bash
streamlit run app.py
```

Streamlit will automatically launch the local server and open your browser at:
```
Local URL: http://localhost:8501
```

### Option B: Quick Double-Click Launch (Windows)
Double-click `run.bat` or execute `.\run.ps1` in PowerShell. The script will automatically activate the virtual environment and start the application.

---

## 🧪 11. Running the Automated Test Suite

We have included a comprehensive unit test suite covering empty inputs, invalid formats, IP addresses, HTTP vs. HTTPS, keyword detection, and edge cases.

To run the automated tests:

```bash
pytest -v test_detector.py
```

**Expected Result:**
```text
============================= 18 passed in 0.04s ==============================
```

---

## 📊 12. Sample Inputs and Outputs

| # | Input URL | Calculated Score | Risk Level | Key Triggered Indicators |
|:---:|---|:---:|:---:|---|
| **1** | `https://www.google.com` | **0 / 100** | 🟢 **LOW RISK** | Valid domain, HTTPS active, standard length, no keywords. |
| **2** | `https://www.wikipedia.org/wiki/Computer_science` | **0 / 100** | 🟢 **LOW RISK** | Trusted educational portal, HTTPS, standard structure. |
| **3** | `http://bit.ly/verify-account-update-2026` | **50 / 100** | 🟡 **MEDIUM RISK** | URL Shortener (+15), Sensitive Keywords (+20), Insecure HTTP (+15). |
| **4** | `http://account-support-service.com/signin` | **35 / 100** | 🟡 **MEDIUM RISK** | Insecure HTTP (+15), Sensitive Keyword (+10), Hyphens (+10). |
| **5** | `http://192.168.1.100/banking/login.php` | **65 / 100** | 🔴 **HIGH RISK** | Raw IP Host (+30), Insecure HTTP (+15), Keywords 'banking' & 'login' (+20). |
| **6** | `http://paypal.verification-account-security-update.xyz/login.php` | **85 / 100** | 🔴 **HIGH RISK** | Long URL (+15), HTTP (+15), Keywords (+20), Hyphens (+10), Abuse TLD .xyz (+15). |
| **7** | `http://google.com@malicious-attacker-host.top/auth.php` | **65 / 100** | 🔴 **HIGH RISK** | '@' Symbol Injection (+20), HTTP (+15), Keyword 'auth' (+10), Abuse TLD .top (+15). |

---

## ⚠️ 13. Limitations

1. **Rule-Based Heuristic Nature**: Attackers continually evolve their techniques. A brand new phishing URL hosted on a legitimate compromised domain using valid HTTPS might bypass purely static syntactic checks.
2. **Offline Scope**: Because the detector deliberately refrains from querying live WHOIS records, SSL certificates, or live web servers (for user safety), it does not verify domain creation dates or DNS resolution.
3. **Context Sensitivity**: Some legitimate development URLs (e.g., local network routers at `192.168.1.1`) or legitimate URL shorteners (e.g., sharing a news link via `bit.ly`) will trigger moderate warnings.

> **Important Security Reminder:**  
> This system is designed as an educational and defensive analysis tool. Never rely exclusively on automated tools to decide whether a website is 100% trustworthy. Always confirm the exact domain spelling in your browser address bar.

---

## 🔮 14. Future Scope

- **Domain Age & WHOIS Integration**: Integrate an offline WHOIS cache or safe API to flag domains registered less than 30 days ago.
- **SSL Certificate Verification**: Inspect the issuer and validity period of the target's TLS certificate.
- **Machine Learning Ensemble**: Combine these 8 heuristic rules with an offline Random Forest / XGBoost classifier trained on historical PhishTank and Tranco datasets.
- **Browser Extension**: Package the detection engine into a lightweight Chrome/Firefox extension that inspects links directly as you browse.

---

## 👨‍💻 15. Beginner-Friendly Code Walkthrough

### How `detector.py` Works
- **`validate_url(url)`**: Ensures the user didn't enter blank spaces, invalid characters, or corrupted text.
- **`is_ip_address(hostname)`**: Uses Python's native `ipaddress.ip_address` module. If the string is a valid IPv4 or IPv6 address, it returns `True`.
- **`extract_subdomains(hostname)`**: Splits the domain name by `.` and filters out top-level domains (including two-part country codes like `.co.uk`) to count how many subdomains exist.
- **`analyze_url(raw_url)`**: Executes the 8 distinct rules, sums the scores, checks against the thresholds, and bundles the result into an organized Python dictionary.

### How `app.py` Works
- **`st.set_page_config`**: Sets up the browser tab title and favicon.
- **Custom CSS**: Injects dark cybersecurity-themed CSS rules into Streamlit to deliver sleek card containers and glowing risk badges.
- **`tab_scan`**: Renders the input box, quick test buttons, and analysis cards.
- **`tab_samples`**: Reads `sample_urls.csv` using Pandas and provides an instant 1-click batch analysis button.
- **`tab_about`**: Provides educational background on every attack vector.

---

## 📜 16. License

This project is released under the **MIT License**. You are free to use, study, modify, and present this project for academic and personal learning purposes.

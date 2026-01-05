# fath0m 🕳️  
**Service-Aware Vulnerability & Exploit Correlation Tool**

fath0m is a lightweight, terminal-based vulnerability scanner that bridges the gap between raw service detection and actionable CVE intelligence.

It combines **Nmap service fingerprinting** with **NVD CVE correlation**, adding **version-aware confidence scoring** and **exploit signal detection** to reduce false positives and over-reporting — a common flaw in basic scanners.

---

## ✨ Key Features

- 🔍 **Accurate Service Detection**
  - Uses Nmap service/version fingerprinting
  - Supports multiple scan intensity profiles

- 🧠 **Version-Aware CVE Correlation**
  - Queries NVD CVE 2.0 API
  - Evaluates CPE version ranges
  - Safely handles malformed or non-semantic versions

- 📊 **Confidence Scoring**
  - `HIGH` – Exact version-bounded CPE match  
  - `MEDIUM` – Product + version range match  
  - Helps users reason about false positives and vendor backports

- 💥 **Exploit Awareness (Fast & Safe)**
  - Detects exploit signals from:
    - Exploit-DB
    - Metasploit
    - PacketStorm
    - Public PoC repositories
  - No scraping, no extra APIs, no ToS risk

- 🎨 **Readable Terminal Output**
  - Colorized, structured tables using Rich
  - CVSS-based risk classification
  - Clear exploit indicators

---

## 🧩 Why fath0m?

Most beginner scanners:
- Flag every CVE as exploitable ❌
- Ignore version ranges ❌
- Crash on malformed CVE data ❌

fath0m is designed to behave like **real unauthenticated scanners** (e.g., Nessus/OpenVAS in basic mode):
- Conservative exploit claims
- Defensive parsing
- Transparent confidence levels

This makes the output **trustworthy**, not noisy.

---

## 📦 Project Structure

```text
fath0m/
├── fath0m.py              # CLI entrypoint
├── core/
│   ├── scanner.py         # Nmap-based service detection
│   ├── nvd_client.py      # NVD CVE correlation + exploit logic
│   └── reporter.py        # Rich-based terminal reporting
├── utils/
│   └── logger.py          # Structured logging
└── README.md
```

---

## 🚀 Installation

### Requirements
- Python 3.10+
- Nmap installed and accessible in PATH

### Install dependencies
```bash
pip install -r requirements.txt
```

### Required Python packages
```text
- python-nmap
- requests
- packaging
- rich
```

---

## 🛠️ Usage
```bash
python3 fath0m.py <target> [options]
```

### Example
```bash
python3 fath0m.py testphp.vulnweb.com -m normal
```

### Options
- -p, --ports   Ports to scan (default: 22,80,443,8080)
- -m, --mode    Scan profile: stealth, normal, aggressive, insane

---

## 📊 Sample Output
```
Port  Service        Version       CVE            Risk (Confidence)     Exploit
80    http | nginx   1.19.0        CVE-2013-0337  7.5 HIGH (MEDIUM)      No
80    http | nginx   1.19.0        CVE-2014-0088  7.5 HIGH (MEDIUM)      No
```

### Interpretation
- CVE applies to the detected version range
- Confidence reflects fingerprint accuracy
- Exploit flag only shown when evidence exists

---

## ⚠️ Important Notes

Results may include false positives due to:
- Vendor backported patches
- Header-based version fingerprinting

fath0m intentionally avoids aggressive assumptions.  
Exploit availability is reported only when supported by references.

---

## 🧠 Design Philosophy

“It’s better to be honest and conservative than loud and wrong.”

---

## 🛣️ Future Improvements

- JSON / SARIF output for CI/CD
- OS & distro-aware CVE pruning
- Grouped CVE output per service
- Exploit type classification (PoC vs weaponized)
- Async CVE fetching for performance

---

## 👤 Author

b3tar00t

Built as a practical security engineering tool — not a toy scanner.

---

## 📄 License

MIT License

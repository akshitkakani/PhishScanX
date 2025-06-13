# 📧 PhishScanX: Phishing Email Analysis & IOC Enrichment

## 🔭 Overview

PhishScanX is a **Streamlit-based** tool designed to analyze suspicious `.eml` email files. It extracts Indicators of Compromise (IOCs), enriches them using external APIs, and provides a comprehensive verdict, all within an intuitive graphical interface.

---

## 📌 Table of Contents

1. [🎯 Project Goals](#--project-goals)
2. [🧠 How Phishing Works](#--how-phishing-works)
3. [🕵️‍♂️ How Analysts Investigate](#--how-analysts-investigate)
4. [⚙️ Features](#--features)
5. [🛠️ Installation & Usage](#---installation---usage)
6. [📁 Project Structure](#--project-structure)
7. [🧩 Implementation Details](#--implementation-details)
8. [🙏 Credits](#--credits)

---

## 🎯 Project Goals

| Objective               | Details                                             |
| ----------------------- | --------------------------------------------------- |
| 🎯 Analyze `.eml` files | Parse headers & body, detect spoofing, extract IOCs |
| 🧬 Extract IOCs         | IPs, Domains, URLs, Hashes                          |
| 🌐 Enrich IOCs          | Use VirusTotal, AbuseIPDB, URLScan.io               |
| 🧠 Generate Verdict     | Based on rules and enrichment data                  |
| 📄 Report Output        | JSON + Markdown + CSV reports                       |
| 🖥️ Streamlit GUI       | Upload `.eml` file → see results visually           |

---

## 🧠 How Phishing Works

Phishing is a form of social engineering where attackers deceive individuals into revealing sensitive information by masquerading as a trustworthy entity. Common tactics include:

* **Spoofed sender addresses**: Mimicking legitimate email addresses.
* **Malicious links**: Directing users to fraudulent websites.
* **Urgent calls to action**: Prompting immediate responses or actions.

*Reference: [Phishing - Wikipedia](https://en.wikipedia.org/wiki/Phishing)*

---

## 🕵️‍♂️ How Analysts Investigate

Security analysts typically follow these steps when investigating a suspicious email:

1. **Identification**: Recognize potential phishing attempts through user reports or automated alerts.
2. **Header Analysis**: Examine email headers for anomalies in sender information and routing.
3. **Content Review**: Assess the email body for suspicious links, attachments, and language.
4. **URL Analysis**: Investigate embedded URLs for legitimacy using tools like VirusTotal.
5. **Attachment Inspection**: Analyze attachments in a controlled environment for malware.

*Reference: [Incident response template for phishing attack - GitHub](https://gist.github.com/skjoher/c249a6ef2620a3ecdec2efe394af445f)*

---

## ⚙️ Features

* **📤 Upload `.eml` files**: Drag and drop your email files for analysis.

![Dashboard](docs/dashboard.gif)

* **🔍 IOC Extraction**: Automatically extracts IPs, domains, URLs, and hashes.
* **🌐 IOC Enrichment**: Retrieves additional information from VirusTotal, AbuseIPDB, and URLScan.io.
* **🧠 Verdict Generation**: Provides a risk assessment based on extracted and enriched data.
* **📄 Report Generation**: Downloads reports in JSON, CSV, and Markdown formats.
* **🖼️ Screenshot Display**: Displays URLScan.io screenshots for visual context.

---

## 🛠️ Installation & Usage

### Prerequisites

* Python 3.8+
* Streamlit
* Required Python libraries

### Installation Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/akshitkakani/PhishScanX.git
   cd PhishScanX
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:

   ```bash
   streamlit run app.py
   ```

4. Upload a `.eml` file through the web interface to begin analysis.

---

## 📁 Project Structure

```
PhishScanX/
├── app.py                   # Main Streamlit application
├── main.py                  # CLI or main logic entry point
│
├── modules/                 # Core functionality modules
│   ├── email_parser.py      # Parses email headers and bodies
│   ├── ioc_extractor.py     # Extracts Indicators of Compromise (IOCs)
│   ├── ioc_enricher.py      # Enriches IOCs via external APIs
│   ├── verdict_engine.py    # Evaluates phishing verdict
│   └── report_generator.py  # Generates analysis reports
│
├── config/                  # Configuration files
│   └── api_keys.json        # API keys (ignored in .gitignore)
│
├── output/                  # Output results
│   ├── reports/             # Final reports in various formats
│   │   ├── csv/
│   │   ├── json/
│   │   └── markdown/
│   └── screenshots/         # Screenshots (e.g., from URLScan)
│
├── sample_emails/           # Test .eml files
├── docs/                    # Documentation and visuals
│
├── requirements.txt         # Project dependencies
└── README.md                # Project overview and usage guide
```

---

## 🧩 Implementation Details

* **Email Parsing**: Utilizes Python's built-in `email` module to parse `.eml` files.
* **IOC Extraction**: Employs regular expressions and `tldextract` to identify potential IOCs.
* **IOC Enrichment**: Integrates with external APIs like VirusTotal, AbuseIPDB, and URLScan.io for detailed information.
* **Verdict Engine**: Applies predefined rules to assess the risk level of the email.
* **Report Generation**: Formats findings into JSON, CSV, and Markdown reports for easy sharing and documentation.

---

## 🙏 Credits

Developed by [Akshit Kakani](https://github.com/akshitkakani).

Special thanks to the contributors of the following libraries and APIs:

* [Streamlit](https://streamlit.io/)
* [VirusTotal](https://www.virustotal.com/)
* [AbuseIPDB](https://www.abuseipdb.com/)
* [URLScan.io](https://urlscan.io/)

---
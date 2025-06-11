# PhishScanX
A GUI-based tool to analyze suspicious emails and extract+enrich Indicators of Compromise (IOCs).

| Objective               | Details                                             |
| ----------------------- | --------------------------------------------------- |
| 🎯 Analyze `.eml` files | Parse headers & body, detect spoofing, extract IOCs |
| 🧬 Extract IOCs         | IPs, Domains, URLs, Hashes                          |
| 🌐 Enrich IOCs          | Use VirusTotal, AbuseIPDB, URLScan.io               |
| 🧠 Generate Verdict     | Based on rules and enrichment data                  |
| 📄 Report Output        | JSON + Markdown + CSV reports                       |
| 🖥️ Streamlit GUI       | Upload `.eml` file → see results visually           |

| Tool / Tech               | Use Case                                 |
| ------------------------- | ---------------------------------------- |
| **Python**                | Core programming language                |
| `email` module            | Parse `.eml` headers & body              |
| `re`, `tldextract`        | Extract IOCs (IPs, Domains, URLs)        |
| `requests`                | API integration (VT, AbuseIPDB, URLScan) |
| `pandas`                  | Tables in GUI & CSV generation           |
| **Streamlit**             | GUI to upload `.eml` and view report     |
| `json`, `csv`, `markdown` | Output reports                           |

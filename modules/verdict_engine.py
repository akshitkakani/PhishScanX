import re

# Suspicious phrases often found in phishing
suspicious_keywords = [
    "update your account", "verify your identity", "gift card",
    "lottery", "reset password", "bank login", "click here", "urgent", "winner", "donation"
]

def safe_lower(headers, key):
    val = headers.get(key)
    if val is None:
        return ""
    return str(val).lower()

def analyze_verdict(headers, body, enriched_data):
    verdict = "Benign"
    reasons = []

    auth_results = safe_lower(headers, "Authentication-Results")

    # Check header authentication failures
    if "spf=fail" in auth_results:
        reasons.append("SPF failed")
    if "dmarc=fail" in auth_results:
        reasons.append("DMARC failed")

    # Check for DKIM signature presence and validity
    dkim_header = headers.get("DKIM-Signature")
    dkim_header_val = "" if dkim_header is None else str(dkim_header).lower()
    # You might want to improve this check if you have more info on valid signatures
    if not dkim_header_val or dkim_header_val == "none":
        reasons.append("Missing or invalid DKIM signature")

    # Check suspicious reply-to or return-path mismatch
    from_addr = safe_lower(headers, "From")
    reply_to = safe_lower(headers, "Reply-To")
    if reply_to and reply_to not in from_addr:
        reasons.append("Reply-To mismatch")

    # Keyword match in body (case-insensitive)
    if any(re.search(rf"\b{re.escape(kw)}\b", body, re.IGNORECASE) for kw in suspicious_keywords):
        reasons.append("Suspicious phishing keywords in body")

    # IOC score analysis
    for ip, result in enriched_data.get("ips", {}).items():
        if isinstance(result, dict) and result.get("abuseConfidenceScore", 0) >= 50:
            reasons.append(f"IP {ip} has high abuse score")

    for url, result in enriched_data.get("urls", {}).items():
        vt = result.get("virustotal", {})
        # Note: your enrich_virustotal_url returns keys: malicious, suspicious, harmless, last_analysis_date
        if vt and vt.get("malicious", 0) >= 3:
            reasons.append(f"URL {url} flagged by VirusTotal")

        urlscan_verdict = result.get("urlscan", {}).get("verdict", "").lower()
        if urlscan_verdict == "malicious":
            reasons.append(f"URL {url} marked malicious by URLScan")

    # Final verdict logic
    if reasons:
        # Check for any indication of maliciousness to assign verdict
        if any(keyword in r.lower() for r in reasons for keyword in ["malicious", "high abuse", "flagged"]):
            verdict = "Malicious"
        else:
            verdict = "Suspicious"

    return verdict, reasons

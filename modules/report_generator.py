import datetime
import os
import json
import csv
from pathlib import Path

def create_output_folders():
    Path("output/reports/json").mkdir(parents=True, exist_ok=True)
    Path("output/reports/csv").mkdir(parents=True, exist_ok=True)
    Path("output/reports/markdown").mkdir(parents=True, exist_ok=True)


def generate_json_report(headers, iocs, enriched_data, verdict, reasons, prefix):
    data = {
        "headers": headers,
        "iocs": iocs,
        "enrichment": enriched_data,
        "verdict": verdict,
        "reasons": reasons
    }

    output_path = Path(f"output/reports/json/{prefix}_report.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    return str(output_path)


def generate_csv_report(enriched_data, prefix):
    output_path = Path(f"output/reports/csv/{prefix}_ioc_enrichment.csv")
    with open(output_path, "w", newline='', encoding="utf-8") as csvfile:
        fieldnames = ["Type", "Value", "Key", "Data"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ioc_type, ioc_dict in enriched_data.items():
            for ioc_value, details in ioc_dict.items():
                if isinstance(details, dict):
                    for key, val in details.items():
                        writer.writerow({
                            "Type": ioc_type,
                            "Value": ioc_value,
                            "Key": key,
                            "Data": val
                        })
                else:
                    writer.writerow({
                        "Type": ioc_type,
                        "Value": ioc_value,
                        "Key": "N/A",
                        "Data": details
                    })

    return str(output_path)


def generate_markdown_report(headers, iocs, verdict, reasons, prefix):
    output_path = Path(f"output/reports/markdown/{prefix}_report.md")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# 🛡️ Phishing Report - {prefix}\n\n")
        f.write("## Verdict\n")
        f.write(f"**Final Verdict:** `{verdict}`\n\n")

        if reasons:
            f.write("### Reasons:\n")
            for reason in reasons:
                f.write(f"- {reason}\n")
        else:
            f.write("_No suspicious indicators found._\n")

        f.write("\n---\n\n## Headers\n")
        for key, val in headers.items():
            f.write(f"- **{key}:** {val}\n")

        f.write("\n---\n\n## Extracted IOCs\n")
        for ioc_type, values in iocs.items():
            f.write(f"\n### {ioc_type.upper()}\n")
            for val in values:
                f.write(f"- {val}\n")

    return str(output_path)



def format_headers(headers):
    lines = ["Email Headers:"]
    for key, value in headers.items():
        lines.append(f"  {key}: {value if value else 'N/A'}")
    return "\n".join(lines)


def format_body(body_plain, preview_length=500):
    preview = body_plain[:preview_length] + ("..." if len(body_plain) > preview_length else "")
    return f"Email Body (plain text preview, {preview_length} chars):\n{preview}"


def format_iocs(iocs):
    lines = ["\nExtracted Indicators of Compromise (IOCs):"]
    if not any(iocs.values()):
        lines.append("  None found.")
        return "\n".join(lines)

    for ioc_type, items in iocs.items():
        lines.append(f"  {ioc_type.upper()} ({len(items)}):")
        if items:
            for ioc in items:
                lines.append(f"    - {ioc}")
        else:
            lines.append("    (None)")
    return "\n".join(lines)


def format_enriched_data(enriched_data):
    lines = ["\nEnrichment Results:"]
    if not any(enriched_data.values()):
        lines.append("  No enrichment data available.")
        return "\n".join(lines)

    for ioc_type, ioc_dict in enriched_data.items():
        lines.append(f"  {ioc_type.upper()} ({len(ioc_dict)}):")
        if not ioc_dict:
            lines.append("    (None)")
            continue
        for ioc, details in ioc_dict.items():
            lines.append(f"    - {ioc}:")
            if not details:
                lines.append("      No data.")
            elif isinstance(details, dict):
                for k, v in details.items():
                    # Pretty print nested dicts
                    if isinstance(v, dict):
                        lines.append(f"      {k}:")
                        for k2, v2 in v.items():
                            lines.append(f"        {k2}: {v2}")
                    else:
                        lines.append(f"      {k}: {v}")
            else:
                lines.append(f"      {details}")
    return "\n".join(lines)


def format_verdict(verdict, reasons):
    lines = [f"\nFinal Verdict: {verdict}"]
    if reasons:
        lines.append("Reasons:")
        for idx, reason in enumerate(reasons, 1):
            lines.append(f"  {idx}. {reason}")
    else:
        lines.append("No suspicious indicators detected.")
    return "\n".join(lines)


def generate_report(parsed_email, iocs, enriched_data, verdict, reasons, body_preview_length=500):
    """
    Generate a detailed phishing analysis report.

    Args:
        parsed_email (dict): Output from parse_eml (headers, body_plain, body_html)
        iocs (dict): Extracted IOCs from extract_iocs
        enriched_data (dict): Enriched IOC data from enrich_iocs
        verdict (str): Final verdict from analyze_verdict
        reasons (list): List of reasons for the verdict
        body_preview_length (int): Number of characters to preview from plain text body

    Returns:
        str: The full formatted report as a string
    """

    headers = parsed_email.get("headers", {})
    body_plain = parsed_email.get("body_plain", "")

    report_sections = [
        f"PhishScanX Report - Generated on {datetime.datetime.utcnow().isoformat()} UTC",
        "=" * 60,
        format_headers(headers),
        "=" * 60,
        format_body(body_plain, preview_length=body_preview_length),
        "=" * 60,
        format_iocs(iocs),
        "=" * 60,
        format_enriched_data(enriched_data),
        "=" * 60,
        format_verdict(verdict, reasons),
        "=" * 60,
    ]

    return "\n".join(report_sections)


def save_report(report_str, output_path):
    """
    Save the generated report string to a file.

    Args:
        report_str (str): The full report content
        output_path (str or Path): File path to save the report

    Returns:
        bool: True if saved successfully, False otherwise
    """
    try:
        output_path = Path(output_path)
        output_path.write_text(report_str, encoding="utf-8")
        print(f"[+] Report saved to: {output_path.resolve()}")
        return True
    except Exception as e:
        print(f"[!] Failed to save report: {e}")
        return False


# Example usage (can be removed when integrating into main workflow)
if __name__ == "__main__":
    # Mock minimal example to demonstrate report generation
    sample_parsed_email = {
        "headers": {"From": "phisher@example.com", "To": "victim@example.org", "Subject": "Urgent: Update Your Account"},
        "body_plain": "Please click the link to verify your account: http://malicious.example.com"
    }
    sample_iocs = {
        "ips": ["192.168.1.1"],
        "domains": ["malicious.example.com"],
        "urls": ["http://malicious.example.com"],
        "hashes": []
    }
    sample_enriched = {
        "ips": {"192.168.1.1": {"abuseConfidenceScore": 85, "countryCode": "US"}},
        "domains": {"malicious.example.com": {"malicious": 5}},
        "urls": {"http://malicious.example.com": {"virustotal": {"malicious": 4}, "urlscan": {"verdict": "malicious"}}},
        "hashes": {}
    }
    sample_verdict = "Malicious"
    sample_reasons = ["SPF failed", "URL http://malicious.example.com flagged by VirusTotal"]

    report_text = generate_report(sample_parsed_email, sample_iocs, sample_enriched, sample_verdict, sample_reasons)
    print(report_text)

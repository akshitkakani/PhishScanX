import argparse
import sys
from modules.report_generator import generate_report, save_report
from modules.verdict_engine import analyze_verdict
from modules.ioc_enricher import enrich_iocs
from modules.ioc_extractor import extract_iocs
from modules.email_parser import parse_eml
from colorama import Fore, Style
import pprint

def print_nested_dict(d, indent=4):
    """Helper to recursively print nested dicts nicely with indentation."""
    space = " " * indent
    if not d:
        print(space + "(No data)")
        return
    for key, value in d.items():
        if isinstance(value, dict):
            print(f"{space}{key}:")
            print_nested_dict(value, indent + 4)
        else:
            print(f"{space}{key}: {value}")

def summarize_verdict(verdict, reasons):
    print(Fore.MAGENTA + f"\n--- FINAL VERDICT: {verdict} ---" + Style.RESET_ALL)
    if reasons:
        print("Reasons:")
        for idx, reason in enumerate(reasons, start=1):
            print(f"  {idx}. {reason}")
    else:
        print("No suspicious indicators detected.")

def main():
    parser = argparse.ArgumentParser(description="Phishing EML Scanner")
    parser.add_argument("eml_path", help="Path to the .eml file to scan")
    parser.add_argument("--body-preview-length", type=int, default=500,
                        help="Number of characters of plain text body to preview (default: 500)")
    args = parser.parse_args()

    try:
        print(Fore.RED + "\nParsing EML file..." + Style.RESET_ALL)
        result = parse_eml(args.eml_path)
    except FileNotFoundError:
        print(Fore.RED + f"Error: File not found: {args.eml_path}" + Style.RESET_ALL)
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"Error parsing EML: {e}" + Style.RESET_ALL)
        sys.exit(1)

    headers = result.get("headers", {})
    body_plain = result.get("body_plain", "")
    body_html = result.get("body_html", "")

    print(Fore.RED + "\nHeaders:" + Style.RESET_ALL)
    pprint.pprint(headers)

    print(Fore.RED + "\nBody (plain text preview):" + Style.RESET_ALL)
    preview = body_plain[:args.body_preview_length]
    print(preview + ("..." if len(body_plain) > args.body_preview_length else ""))

    print(Fore.RED + "\nExtracting IOCs..." + Style.RESET_ALL)
    iocs = extract_iocs(headers, body_plain, body_html)
    pprint.pprint(iocs)

    print(Fore.RED + "\nEnriching IOCs via APIs (this may take some time)..." + Style.RESET_ALL)
    enriched_data = enrich_iocs(iocs)

    # Nicely display enrichment results grouped by IOC type
    for ioc_type in ["ips", "domains", "urls", "hashes"]:
        ioc_results = enriched_data.get(ioc_type, {})
        print(Fore.CYAN + f"\n--- {ioc_type.upper()} RESULTS ---" + Style.RESET_ALL)

        if not ioc_results:
            print("No data available.")
            continue

        for ioc, data in ioc_results.items():
            print(Fore.YELLOW + f"\n▶ {ioc}:" + Style.RESET_ALL)
            if isinstance(data, dict):
                if ioc_type == "urls":
                    for service, details in data.items():
                        print(f"  [{service}] Scan results for URL: {ioc}")
                        if isinstance(details, dict):
                            print_nested_dict(details, indent=6)
                        else:
                            print(f"    {details}")
                else:
                    print_nested_dict(data, indent=4)
            else:
                print(f"   {data}")

    print(Fore.RED + "\nAnalyzing verdict based on enrichment and email content..." + Style.RESET_ALL)
    verdict, reasons = analyze_verdict(headers, body_plain, enriched_data)

    summarize_verdict(verdict, reasons)

    # ... after verdict is determined
    report_str = generate_report(result, iocs, enriched_data, verdict, reasons)
    print(report_str)  # print on console

    # Optionally save to a file
    save_report(report_str, "output/reports/phishscan_report.txt")

if __name__ == "__main__":
    main()

import re
import tldextract

def extract_iocs(headers, body_plain, body_html):
    iocs = {
        "ips": set(),
        "domains": set(),
        "urls": set(),
        "hashes": set()
    }

    # Combine all searchable text
    combined_text = "\n".join([
        str(headers.get("Return-Path", "")),
        str(headers.get("Reply-To", "")),
        str(headers.get("Authentication-Results", "")),
        str(headers.get("Received-SPF", "")),
        body_plain,
        body_html
    ])

    # Normalize obfuscated indicators (e.g., hxxp[:], [.] => http://, .)
    def deobfuscate(text):
        # Replace hxxp:// or hxxps:// (with or without [:]) with http:// or https://
        text = re.sub(r'hxxps?\[:\]//', 'http://', text, flags=re.IGNORECASE)
        text = re.sub(r'hxxp[:]?s?://', 'http://', text, flags=re.IGNORECASE)
        # Common replacements for obfuscation
        text = text.replace("[.]", ".").replace("(.)", ".")
        text = text.replace("[://]", "://").replace("[:]", ":")
        return text

    combined_text = deobfuscate(combined_text)

    # Extract IPs
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    iocs["ips"].update(re.findall(ip_pattern, combined_text))

    # Extract emails and get their domains
    email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
    emails = re.findall(email_pattern, combined_text)
    email_domains = set()
    for item in emails:
        ext = tldextract.extract(item)
        if ext.domain and ext.suffix:
            domain = f"{ext.domain}.{ext.suffix}"
            iocs["domains"].add(domain)
            email_domains.add(domain)  # keep email domains to exclude later

    # Extract URLs (http/https)
    url_pattern = re.compile(r'https?://[^\s"\'<>]+')
    urls = re.findall(url_pattern, combined_text)
    iocs["urls"].update(urls)

    # Extract domains from URLs
    for url in urls:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            domain = f"{ext.domain}.{ext.suffix}"
            iocs["domains"].add(domain)

    # Extract bare domains (without scheme)
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}\b')
    bare_domains = set(re.findall(domain_pattern, combined_text))

    # Add bare domains only if not part of email domains or already in URLs/domains
    for domain in bare_domains:
        ext = tldextract.extract(domain)
        if ext.domain and ext.suffix:
            full_domain = f"{ext.domain}.{ext.suffix}"
            if full_domain not in email_domains and full_domain not in iocs["domains"]:
                iocs["domains"].add(full_domain)
                # Add as http URL for scanning later
                iocs["urls"].add(f"http://{full_domain}")

    # Extract hashes (MD5, SHA1, SHA256)
    md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
    sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
    sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')

    iocs["hashes"].update(re.findall(md5_pattern, combined_text))
    iocs["hashes"].update(re.findall(sha1_pattern, combined_text))
    iocs["hashes"].update(re.findall(sha256_pattern, combined_text))

    return {key: list(val) for key, val in iocs.items()}

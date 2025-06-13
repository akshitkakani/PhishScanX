import requests
import json
import base64
import time
from pathlib import Path

# Load API keys
CONFIG_PATH = Path(__file__).parent.parent / "config" / "api_keys.json"
with open(CONFIG_PATH) as f:
    api_keys = json.load(f)

VT_API_KEY = api_keys.get("virustotal")
ABUSE_API_KEY = api_keys.get("abuseipdb")
URLSCAN_API_KEY = api_keys.get("urlscan")


def expand_url(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        return response.url
    except Exception:
        return url  # fallback to original if error


def enrich_ip(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        resp = requests.get(url, headers=headers, params=params)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "countryCode": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "lastReportedAt": data.get("lastReportedAt")
            }
    except Exception as e:
        print(f"[!] Error enriching IP: {ip} - {e}")
    return {}


def virustotal_url_id(url):
    url_bytes = url.encode('utf-8')
    b64_url = base64.urlsafe_b64encode(url_bytes).rstrip(b'=').decode('utf-8')
    return b64_url


def enrich_virustotal_url(url):
    url_id = virustotal_url_id(url)
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(vt_url, headers=headers)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})
            return {
                "malicious": last_analysis.get("malicious", 0),
                "suspicious": last_analysis.get("suspicious", 0),
                "harmless": last_analysis.get("harmless", 0),
                "last_analysis_date": attrs.get("last_analysis_date")
            }
    except Exception as e:
        print(f"[!] Error enriching VT URL {url}: {e}")
    return {}


def enrich_virustotal(ioc):
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            results = resp.json().get("data", [])
            if results:
                attrs = results[0].get("attributes", {})
                last_analysis = attrs.get("last_analysis_stats", {})
                return {
                    "malicious": last_analysis.get("malicious", 0),
                    "suspicious": last_analysis.get("suspicious", 0),
                    "harmless": last_analysis.get("harmless", 0),
                    "last_analysis_date": attrs.get("last_analysis_date")
                }
    except Exception as e:
        print(f"[!] Error enriching IOC: {ioc} - {e}")
    return {}


def enrich_urlscan(url):
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {"url": url, "visibility": "public"}

    try:
        # Step 1: Submit scan
        submission = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=payload)

        if submission.status_code == 200:
            response_data = submission.json()
            uuid = response_data.get("uuid")

            if not uuid:
                print("[!] No UUID returned in response.")
                return {}

            # Step 2: Construct URLs
            screenshot_url = f"https://urlscan.io/screenshots/{uuid}.png"
            result_url = f"https://urlscan.io/result/{uuid}/"
            result_api_url = f"https://urlscan.io/api/v1/result/{uuid}/"

            # Step 3: Optional wait for scan to complete
            time.sleep(5)

            # Step 4: Fetch result and infer verdict
            verdict = "unknown"
            result_resp = requests.get(result_api_url, headers=headers)
            if result_resp.status_code == 200:
                result_json = result_resp.json()
                stats = result_json.get("stats", {})
                if stats.get("malicious", 0) > 0:
                    verdict = "malicious"
                elif stats.get("suspicious", 0) > 0:
                    verdict = "suspicious"
                else:
                    verdict = "harmless"

            # Step 5: Save screenshot locally
            screenshot_folder = Path("output/screenshots")
            screenshot_folder.mkdir(parents=True, exist_ok=True)
            local_path = screenshot_folder / f"{uuid}.png"
            try:
                img_data = requests.get(screenshot_url).content
                with open(local_path, "wb") as f:
                    f.write(img_data)
            except Exception as e:
                print(f"[!] Could not save screenshot locally: {e}")
                local_path = ""

            return {
                "screenshot": screenshot_url,
                "screenshot_local": str(local_path),
                "result": result_url,
                "verdict": verdict
            }

        else:
            print(f"[!] Scan submission failed: {submission.status_code}")
            return {}

    except Exception as e:
        print(f"[!] Error during URLScan enrichment: {e}")
        return {}


def enrich_iocs(iocs):
    enriched = {
        "ips": {},
        "domains": {},
        "urls": {},
        "hashes": {}
    }

    for ip in iocs.get("ips", []):
        enriched["ips"][ip] = enrich_ip(ip)

    for domain in iocs.get("domains", []):
        enriched["domains"][domain] = enrich_virustotal(domain)

    seen_urls = set()

    for raw_url in iocs.get("urls", []):
        if not raw_url.startswith("http"):
            url = f"http://{raw_url}"
        else:
            url = raw_url

        # Normalize & deduplicate
        url = expand_url(url)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        enriched["urls"][url] = {
            "virustotal": enrich_virustotal_url(url),
            "urlscan": enrich_urlscan(url)
        }

    for h in iocs.get("hashes", []):
        enriched["hashes"][h] = enrich_virustotal(h)

    return enriched

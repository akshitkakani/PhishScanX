import streamlit as st
from modules import email_parser, ioc_extractor, ioc_enricher, verdict_engine, report_generator
import os
from datetime import datetime
from pathlib import Path
import pandas as pd

st.set_page_config(page_title="PhishScanX", layout="wide")
st.title("📧 PhishScanX")
st.caption("Analyze suspicious emails and generate reports with IOC enrichment and threat verdicts.")

uploaded_file = st.file_uploader("📤 Upload a `.eml` file", type=["eml"])

if uploaded_file:
    st.success("✅ File uploaded successfully. Beginning analysis...")

    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    email_path = f"temp_{timestamp}.eml"

    with open(email_path, "wb") as f:
        f.write(uploaded_file.read())

    try:
        # Step 1: Parse
        parsed = email_parser.parse_eml(email_path)
        headers = parsed.get("headers", {})
        body_plain = parsed.get("body_plain", "")
        body_html = parsed.get("body_html", "")

        # Step 2: Extract IOCs
        iocs = ioc_extractor.extract_iocs(headers, body_plain, body_html)

        # Step 3: Enrich IOCs
        with st.spinner("🔎 Enriching IOCs using APIs..."):
            enriched = ioc_enricher.enrich_iocs(iocs)

        # Step 4: Verdict
        verdict, reasons = verdict_engine.analyze_verdict(headers, body_plain, enriched)

        # Tabs for navigation
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["📬 Email Info", "🧬 IOCs", "🌐 Enrichment", "🧠 Verdict", "📄 Reports"])

        with tab1:
            st.header("📬 Parsed Email Headers")
            for key, val in headers.items():
                st.markdown(f"**{key}**: `{val}`")

            st.markdown("### 📄 Email Body (Preview)")
            st.code(body_plain, language="text")

        with tab2:
            st.header("🧬 Extracted Indicators of Compromise")
            for key, values in iocs.items():
                if values:
                    st.markdown(f"**{key.upper()}**")
                    st.dataframe(pd.DataFrame(values, columns=[f"{key}"]))
                else:
                    st.markdown(f"❌ No {key} found.")

        with tab3:
            st.header("🌐 IOC Enrichment Results")

            if enriched.get("ips"):
                st.subheader("📍 IP Addresses")
                ip_rows = []
                for ip, data in enriched["ips"].items():
                    ip_rows.append({
                        "IP": ip,
                        "Abuse Score": data.get("abuseConfidenceScore", "N/A"),
                        "Country": data.get("countryCode", "N/A"),
                        "ISP": data.get("isp", "N/A"),
                        "Last Reported": data.get("lastReportedAt", "N/A")
                    })
                st.dataframe(pd.DataFrame(ip_rows))

            if enriched.get("domains"):
                st.subheader("🌐 Domains")
                domain_rows = []
                for dom, vt in enriched["domains"].items():
                    domain_rows.append({
                        "Domain": dom,
                        "Malicious": vt.get("malicious", 0),
                        "Suspicious": vt.get("suspicious", 0),
                        "Last Scan": vt.get("last_analysis_date", "N/A")
                    })
                st.dataframe(pd.DataFrame(domain_rows))

            if enriched.get("urls"):
                st.subheader("🔗 URLs")
                for url, info in enriched["urls"].items():
                    vt = info.get("virustotal", {})
                    urlscan = info.get("urlscan", {})

                    st.markdown(f"**🔗 URL:** `{url}`")

                    col1, col2 = st.columns([1, 2])

                    with col1:
                        screenshot_path = urlscan.get("screenshot_local", "")
                        if screenshot_path and os.path.exists(screenshot_path):
                            # Click to zoom using Streamlit built-in feature
                            st.image(screenshot_path, caption="🖼️ URLScan Screenshot (click to zoom)", width=280)
                        else:
                            st.warning("⚠️ Screenshot not available or could not be fetched.")

                    with col2:
                        st.markdown(f"**📊 VT Malicious:** {vt.get('malicious', 0)}")
                        st.markdown(f"**📊 VT Suspicious:** {vt.get('suspicious', 0)}")
                        st.markdown(f"**🧪 URLScan Verdict:** `{urlscan.get('verdict', 'N/A')}`")
                        report_link = urlscan.get("result", "")
                        if report_link:
                            st.markdown(f"[🔍 Open Full URLScan Report]({report_link})")
                        else:
                            st.markdown("_No URLScan report link available._")

            if enriched.get("hashes"):
                st.subheader("🧬 Hashes")
                rows = []
                for h, vt in enriched["hashes"].items():
                    rows.append({
                        "Hash": h,
                        "Malicious": vt.get("malicious", 0),
                        "Suspicious": vt.get("suspicious", 0),
                        "Last Scan": vt.get("last_analysis_date", "N/A")
                    })
                st.dataframe(pd.DataFrame(rows))

        with tab4:
            st.header("🧠 Verdict Summary")
            if verdict == "Malicious":
                st.error(f"🛑 Verdict: {verdict}")
            elif verdict == "Suspicious":
                st.warning(f"⚠️ Verdict: {verdict}")
            else:
                st.success(f"✅ Verdict: {verdict}")

            if reasons:
                st.markdown("### 📋 Reasons")
                for idx, r in enumerate(reasons, start=1):
                    st.markdown(f"{idx}. {r}")
            else:
                st.markdown("_No suspicious indicators found._")

        with tab5:
            st.header("📄 Downloadable Reports")
            report_generator.create_output_folders()
            prefix = f"phishing_{timestamp}"
            json_path = report_generator.generate_json_report(headers, iocs, enriched, verdict, reasons, prefix)
            csv_path = report_generator.generate_csv_report(enriched, prefix)
            md_path = report_generator.generate_markdown_report(headers, iocs, verdict, reasons, prefix)

            st.download_button("⬇️ Download JSON", open(json_path, "rb"), file_name=os.path.basename(json_path))
            st.download_button("⬇️ Download CSV", open(csv_path, "rb"), file_name=os.path.basename(csv_path))
            st.download_button("⬇️ Download Markdown", open(md_path, "rb"), file_name=os.path.basename(md_path))

    finally:
        if os.path.exists(email_path):
            os.remove(email_path)

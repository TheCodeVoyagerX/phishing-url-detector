"""
Phishing URL Detector - Streamlit Frontend Dashboard
Author: Senior Python Developer & Cybersecurity Engineer
Theme: Modern Dark Cybersecurity Interface
"""

import os
import pandas as pd
import streamlit as st
from detector import analyze_url

# Page configuration
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Cyber Dark CSS
st.markdown("""
<style>
    /* Dark cybersecurity color palette */
    .stApp {
        background-color: #0d1117;
        color: #e6edf3;
        font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Main title headers */
    .main-title {
        font-size: 2.3rem;
        font-weight: 800;
        background: linear-gradient(90deg, #38bdf8, #818cf8, #34d399);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        color: #94a3b8;
        font-size: 1.05rem;
        font-weight: 400;
        margin-bottom: 1.25rem;
    }
    
    /* Cyber Card Container */
    .cyber-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 1.25rem;
        margin-bottom: 1.2rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    
    .card-title-tag {
        color: #94a3b8;
        font-size: 0.78rem;
        text-transform: uppercase;
        font-weight: 700;
        letter-spacing: 0.05em;
        white-space: nowrap;
        display: block;
        margin-bottom: 0.4rem;
    }
    
    /* Risk Badges */
    .risk-badge {
        display: inline-block;
        padding: 0.45rem 1rem;
        border-radius: 8px;
        font-weight: 700;
        font-size: 1.15rem;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        margin-bottom: 0.6rem;
    }
    .badge-low {
        background-color: rgba(34, 197, 94, 0.15);
        color: #4ade80;
        border: 1px solid #22c55e;
    }
    .badge-medium {
        background-color: rgba(245, 158, 11, 0.15);
        color: #fbbf24;
        border: 1px solid #f59e0b;
    }
    .badge-high {
        background-color: rgba(239, 68, 68, 0.15);
        color: #f87171;
        border: 1px solid #ef4444;
    }
    
    /* Metric Score Box */
    .score-container {
        display: flex;
        align-items: baseline;
        gap: 0.4rem;
        margin: 0.3rem 0;
    }
    .score-number {
        font-size: 2.8rem;
        font-weight: 900;
        line-height: 1;
    }
    .score-total {
        font-size: 1.25rem;
        color: #64748b;
    }
    
    /* Rule breakdown pill */
    .rule-pill-pass {
        background: rgba(34, 197, 94, 0.08);
        color: #4ade80;
        border-left: 4px solid #22c55e;
        padding: 0.75rem 1rem;
        border-radius: 6px;
        margin-bottom: 0.6rem;
    }
    .rule-pill-fail {
        background: rgba(239, 68, 68, 0.10);
        color: #fca5a5;
        border-left: 4px solid #ef4444;
        padding: 0.75rem 1rem;
        border-radius: 6px;
        margin-bottom: 0.6rem;
    }
    
    /* Disclaimer alert */
    .disclaimer-box {
        background: #0f172a;
        border: 1px dashed #475569;
        border-radius: 8px;
        padding: 0.85rem;
        color: #94a3b8;
        font-size: 0.85rem;
        margin-top: 1rem;
    }
    
    /* Button styling */
    .stButton>button {
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s ease-in-out;
    }
</style>
""", unsafe_allow_html=True)


def load_sample_dataset():
    """Loads sample_urls.csv if available."""
    sample_file = "sample_urls.csv"
    if os.path.exists(sample_file):
        try:
            return pd.read_csv(sample_file)
        except Exception:
            return None
    return None


def set_preset_url(url_value: str):
    """Callback to update the text input state when preset button is clicked."""
    st.session_state["url_text_input"] = url_value
    st.session_state["auto_analyze"] = True


def main():
    # Initialize session state variables
    if "url_text_input" not in st.session_state:
        st.session_state["url_text_input"] = ""
    if "auto_analyze" not in st.session_state:
        st.session_state["auto_analyze"] = False

    # Sidebar: Project Info & Rule Explanations
    with st.sidebar:
        st.markdown("### 🛡️ About This Project")
        st.markdown(
            """
            **Phishing URL Detector** is an offline cybersecurity analyzer designed 
            to identify malicious, deceptive, and credential-harvesting links.
            
            **Core Concept:**
            Attackers manipulate URL syntax, conceal host identities, and inject urgent keywords 
            to lure victims into fraudulent portals. This application inspects 8 deterministic 
            structural features without making unsafe web connections.
            """
        )
        st.markdown("---")
        st.markdown("### 📋 8 Core Heuristic Rules")
        st.markdown(
            """
            1. **URL Length** (> 54 / 75 chars)
            2. **HTTPS Protocol** (Enforce SSL)
            3. **IP-Based Hostname** (Raw IP check)
            4. **Suspicious Keywords** (Login, Verify...)
            5. **URL Shorteners** (bit.ly, tinyurl...)
            6. **Excessive Subdomains** (>= 2 levels)
            7. **Special Characters** (@, -, // in path)
            8. **Suspicious Domain Patterns** (Abuse TLDs, Punycode)
            """
        )
        st.markdown("---")
        st.markdown("### 🎯 Scoring Thresholds")
        st.markdown(
            """
            - 🟢 **LOW RISK**: 0 – 29 pts  
            - 🟡 **MEDIUM RISK**: 30 – 64 pts  
            - 🔴 **HIGH RISK**: 65 – 100 pts
            """
        )
        st.caption("Developed with Python & Streamlit | 100% Offline Analysis")

    # Header section
    st.markdown('<div class="main-title">🛡️ Phishing URL Detector</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Protect Yourself from Malicious Websites & Phishing Attacks</div>', unsafe_allow_html=True)

    # Tabs for Single URL Scan vs Batch / Samples
    tab_scan, tab_samples, tab_about = st.tabs(["🔍 Analyze URL", "📂 Sample Test URLs", "📖 Detection Methodology"])

    with tab_scan:
        st.markdown("#### Enter URL to Inspect")

        # Quick preset buttons with proper Streamlit callbacks
        st.caption("Quick Test Presets (Click to load and inspect):")
        preset_cols = st.columns(4)
        with preset_cols[0]:
            st.button("🟢 Safe Example", on_click=set_preset_url, args=("https://www.wikipedia.org/wiki/Computer_science",), use_container_width=True)
        with preset_cols[1]:
            st.button("🟡 Medium Risk", on_click=set_preset_url, args=("http://bit.ly/verify-account-update-2026",), use_container_width=True)
        with preset_cols[2]:
            st.button("🔴 High Risk Phish", on_click=set_preset_url, args=("http://paypal.verification-account-security-update.xyz/login.php",), use_container_width=True)
        with preset_cols[3]:
            st.button("🔴 IP Address Host", on_click=set_preset_url, args=("http://192.168.1.100/banking/login.php",), use_container_width=True)

        # URL Input field bound to session_state key
        url_input = st.text_input(
            "Target Web Address (URL):",
            key="url_text_input",
            placeholder="e.g., https://secure.bank.com/login or http://192.168.1.1/verify",
            help="Paste the full link you want to inspect. The app performs offline parsing only."
        )

        analyze_button = st.button("🚀 Analyze URL", use_container_width=False, type="primary")

        # Check if analyze should run
        should_run = analyze_button or st.session_state.get("auto_analyze", False)
        # Reset auto_analyze flag
        st.session_state["auto_analyze"] = False

        if should_run:
            current_val = url_input.strip()
            if not current_val:
                st.error("⚠️ Input Error: Please enter a URL before clicking 'Analyze URL'.")
            else:
                result = analyze_url(current_val)

                if not result["is_valid"]:
                    st.error(f"❌ {result['error_message']}")
                else:
                    # Risk score styling
                    risk_level = result["risk_level"]
                    risk_score = result["risk_score"]
                    risk_color = result["risk_color"]
                    badge_class = "badge-low" if risk_score < 30 else "badge-medium" if risk_score < 65 else "badge-high"

                    st.markdown("---")
                    st.markdown("### 📊 Detection Results")

                    # Top Metrics Row
                    col1, col2, col3 = st.columns([1.1, 1, 1.9])

                    with col1:
                        st.markdown(f"""
                        <div class="cyber-card">
                            <span class="card-title-tag">Overall Threat Status</span>
                            <div class="risk-badge {badge_class}">
                                {result['badge_emoji']} {risk_level}
                            </div>
                            <div class="score-container">
                                <span class="score-number" style="color: {risk_color};">{risk_score}</span>
                                <span class="score-total">/ 100</span>
                            </div>
                            <span style="color: #64748b; font-size: 0.82rem;">Calculated Risk Score</span>
                        </div>
                        """, unsafe_allow_html=True)

                    with col2:
                        st.markdown(f"""
                        <div class="cyber-card">
                            <span class="card-title-tag">Triggered Indicators</span>
                            <div style="font-size: 2.8rem; font-weight: 900; color: #38bdf8; margin: 0.3rem 0; line-height: 1;">
                                {result['triggered_count']} <span style="font-size: 1.25rem; color: #64748b;">/ {result['total_rules']}</span>
                            </div>
                            <span style="color: #64748b; font-size: 0.82rem;">Heuristic rules triggered</span>
                        </div>
                        """, unsafe_allow_html=True)

                    with col3:
                        st.markdown(f"""
                        <div class="cyber-card">
                            <span class="card-title-tag">Analysis Summary</span>
                            <p style="font-size: 0.92rem; line-height: 1.5; color: #e2e8f0; margin-top: 0.3rem;">
                                {result['analysis_summary']}
                            </p>
                        </div>
                        """, unsafe_allow_html=True)

                    # Visual Risk Meter Bar
                    st.markdown("##### Threat Score Gauge")
                    st.progress(risk_score / 100.0)

                    # URL Structural Inspection breakdown
                    with st.expander("🔎 View URL Structural Components", expanded=False):
                        comp_col1, comp_col2 = st.columns(2)
                        with comp_col1:
                            st.write(f"**Target URL:** `{result['raw_url']}`")
                            st.write(f"**Extracted Hostname:** `{result['hostname']}`")
                        with comp_col2:
                            st.write(f"**URL Path:** `{result['path'] if result['path'] else '/'}`")
                            st.write(f"**Query Parameters:** `{result['query'] if result['query'] else 'None'}`")

                    # Detailed Rules Breakdown
                    st.markdown("### 🔍 Rule-by-Rule Detection Breakdown")
                    st.caption("Each rule evaluates a distinct attack vector. Points are added when suspicious patterns are observed.")

                    for ind in result["indicators"]:
                        is_trig = ind["triggered"]
                        status_icon = "⚠️ ALERT" if is_trig else "✅ PASSED"
                        css_class = "rule-pill-fail" if is_trig else "rule-pill-pass"
                        score_text = f"+{ind['score']} pts" if is_trig else "0 pts"

                        st.markdown(f"""
                        <div class="{css_class}">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <strong>Rule {ind['rule_id']}: {ind['name']}</strong>
                                <span style="font-weight: 700;">{status_icon} ({score_text} / max {ind['max_score']})</span>
                            </div>
                            <div style="font-size: 0.88rem; margin-top: 0.3rem;">
                                {ind['details']}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                    # Mandatory educational disclaimer
                    st.markdown(f"""
                    <div class="disclaimer-box">
                        <strong>🛡️ Security Notice:</strong> {result['disclaimer']}
                    </div>
                    """, unsafe_allow_html=True)

    with tab_samples:
        st.markdown("#### 📂 Pre-Loaded Test Cases & Evaluation Suite")
        st.markdown(
            "Use this dataset to test and demonstrate how the rule-based detection engine differentiates "
            "between legitimate portals, suspicious sites, and critical phishing attacks."
        )

        df_samples = load_sample_dataset()
        if df_samples is not None:
            if st.button("⚡ Run Batch Analysis on All Samples", type="primary"):
                with st.spinner("Analyzing all sample URLs offline..."):
                    results_list = []
                    for idx, row in df_samples.iterrows():
                        res = analyze_url(str(row["url"]))
                        results_list.append({
                            "URL": row["url"],
                            "Expected Risk": row["expected_risk_category"],
                            "Detected Risk": res["risk_level"],
                            "Score (/100)": res["risk_score"],
                            "Triggered Rules": f"{res['triggered_count']}/{res['total_rules']}",
                            "Description": row["description"]
                        })
                    results_df = pd.DataFrame(results_list)
                    st.success("Batch analysis complete!")
                    st.dataframe(results_df, use_container_width=True)
            else:
                st.dataframe(df_samples, use_container_width=True)
                st.info("Click 'Run Batch Analysis on All Samples' above to evaluate all URLs at once.")
        else:
            st.warning("sample_urls.csv was not found in the project root directory.")

    with tab_about:
        st.markdown("#### 📖 How the Detection System Works")
        st.markdown("""
        ### Why Rule-Based Detection?
        In cybersecurity, rule-based heuristic detection provides **immediate, explainable, and deterministic** 
        analysis. Unlike black-box algorithms, every single point added to the risk score has a clear, 
        transparent reason that can be audited.

        ---

        ### The 8 Attack Vectors Explained:
        1. **URL Length Detection**:
           - Real URLs are typically concise (averaging under 50 characters).
           - Phishers use long URLs to embed fake authentication tokens, obfuscated hex strings, or lengthy deceptive subdomains.
        
        2. **HTTPS Protocol Detection**:
           - Legitimate e-commerce, banking, and modern social platforms enforce TLS/SSL (HTTPS).
           - Unencrypted HTTP URLs expose credentials in plaintext to man-in-the-middle (MITM) attacks.

        3. **IP Address-Based Hostnames**:
           - Domain names cost money and require DNS registration where attackers can be reported and blacklisted.
           - To evade domain registration checks, attackers often host phishing portals on raw IP addresses (e.g., `http://192.168.1.1/login`).

        4. **Suspicious Keyword Detection**:
           - Phishing campaigns rely on urgency and credential theft. Keywords such as `login`, `verify`, `banking`, `password`, `wallet`, and `recovery` in the path or subdomain trigger high scrutiny.

        5. **URL Shortening Service Detection**:
           - Services like `bit.ly` or `tinyurl.com` mask the actual destination host. Attackers frequently utilize shorteners in SMS (smishing) or phishing emails to bypass user inspection.

        6. **Excessive Subdomain Detection**:
           - Legitimate domains typically use 0 to 1 subdomain level (`mail.google.com`).
           - Attackers chain 3 or more subdomains (e.g., `paypal.com.account-update.verify.xyz`) to trick users on mobile screens where only the start of the URL is visible.

        7. **Special Character Detection (@, -, //)**:
           - The `@` character in a URL tells browsers to treat preceding characters as username/password and connect exclusively to the server *after* the `@`.
           - Multiple hyphens (`-`) are used to create typosquatted domains (e.g. `apple-security-check.com`).
           - Double slashes (`//`) within the URL path indicate redirection techniques.

        8. **Suspicious Domain Patterns**:
           - High-abuse TLDs (`.xyz`, `.top`, `.click`, `.buzz`) have low barrier-to-entry costs and frequent abuse records.
           - Punycode (`xn--`) is used in IDN homograph attacks where Cyrillic letters (e.g., 'а') spoof Latin letters ('a').
        """)


if __name__ == "__main__":
    main()

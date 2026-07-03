"""Main Streamlit application — SOC Anti-Phishing Simulation Platform."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.antivirus_engine import MiniAntivirus
from app.core.kill_chain import get_all_stages_info, map_findings_to_kill_chain
from app.core.mitre_attack import (
    compare_techniques,
    fetch_mitre_data,
    get_phishing_related_techniques,
    get_tactic_summary,
    parse_techniques,
    search_techniques,
)
from app.core.malware_scanner import scan_file_content, scan_hash
from app.core.phishing_scanner import analyze_email_headers, analyze_url
from app.core.recon import RECON_PLATFORMS, aggregate_recon_findings, run_full_recon
from app.core.soc_analyzer import build_soc_dashboard, severity_color
from app.ui.components import SOC_THEME_CSS, render_header, render_metric, severity_badge, verdict_class
from components.chatbot import render_soc_chatbot

st.set_page_config(
    page_title="Anti-Phishing SOC Simulator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(SOC_THEME_CSS, unsafe_allow_html=True)


def sidebar():
    st.sidebar.markdown('<div class="sidebar-brand">🔐 SOC Command Center</div>', unsafe_allow_html=True)
    page = st.sidebar.radio(
        "Navigation",
        [
            "🏠 SOC Dashboard",
            "🎣 Anti-Phishing Scanner",
            "🦠 Malware & Virus Scanner",
            "🛡️ Mini Antivirus",
            "🔍 Recon Platforms",
            "⛓️ Cyber Kill Chain",
            "🎯 MITRE ATT&CK",
            "🤖 AI Assistant & Prompts",
        ],
        label_visibility="collapsed",
    )
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🔑 CREDENTIALS")
    api_key_env = os.environ.get("GEMINI_API_KEY", "")
    api_key_input = st.sidebar.text_input(
        "Gemini API Key",
        value=api_key_env if api_key_env else st.session_state.get("gemini_key", ""),
        type="password",
        help="Provide your Gemini API key to enable AI-powered SOC chatbots."
    )
    st.session_state.gemini_key = api_key_input
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Analyst:** Blue Team SOC")
    st.sidebar.markdown("**Classification:** Internal Use")
    av_status = MiniAntivirus.get_engine_status()
    st.sidebar.success(f"AV Engine: {av_status['status'].upper()}")
    st.sidebar.caption(f"Signatures: {av_status['signatures_loaded']} | Heuristic: ON")
    return page


def page_dashboard():
    render_header()

    # Initialize dashboard states
    if "dash_phish_score" not in st.session_state:
        st.session_state.dash_phish_score = 45
    if "dash_mal_score" not in st.session_state:
        st.session_state.dash_mal_score = 20
    if "dash_recon_flags" not in st.session_state:
        st.session_state.dash_recon_flags = 2
    if "dash_kc_risk" not in st.session_state:
        st.session_state.dash_kc_risk = 35
    if "dash_phish_blocked" not in st.session_state:
        st.session_state.dash_phish_blocked = 127
    if "dash_mal_quarantined" not in st.session_state:
        st.session_state.dash_mal_quarantined = 18

    # Build dynamic dashboard model
    dashboard = build_soc_dashboard(
        phishing_score=st.session_state.dash_phish_score,
        malware_score=st.session_state.dash_mal_score,
        recon_flags=st.session_state.dash_recon_flags,
        kill_chain_risk=st.session_state.dash_kc_risk,
    )

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        render_metric("Open Alerts", str(dashboard.metrics["open_alerts"]), "#ff4757")
    with col2:
        render_metric("Phishing Blocked", str(st.session_state.dash_phish_blocked), "#00ff88")
    with col3:
        render_metric("Malware Quarantined", str(st.session_state.dash_mal_quarantined), "#00d4ff")
    with col4:
        render_metric("Avg Triage Time", "12m", "#a55eea")

    st.markdown('<div class="section-title">Live SOC Overview</div>', unsafe_allow_html=True)

    c1, c2 = st.columns([2, 1])
    with c1:
        alert_rows = [
            {
                "ID": a.id,
                "Title": a.title,
                "Severity": a.severity.upper(),
                "Source": a.source,
                "MITRE": ", ".join(a.mitre_ids),
            }
            for a in dashboard.alerts
        ]
        if alert_rows:
            st.dataframe(pd.DataFrame(alert_rows), use_container_width=True, hide_index=True)
        else:
            st.info("No active alerts — environment nominal.")

    with c2:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=dashboard.overall_risk,
            title={"text": "Overall Risk Score"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#00d4ff"},
                "steps": [
                    {"range": [0, 30], "color": "#1a2332"},
                    {"range": [30, 60], "color": "rgba(255, 165, 2, 0.2)"},
                    {"range": [60, 100], "color": "rgba(255, 71, 87, 0.2)"},
                ],
            },
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font={"color": "#e2e8f0"},
            height=280,
        )
        st.plotly_chart(fig, use_container_width=True)

    # Simulation and Action controls
    st.markdown('<div class="section-title">Simulation & Triage Actions</div>', unsafe_allow_html=True)
    ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4, ctrl_col5 = st.columns(5)

    with ctrl_col1:
        if st.button("🎣 Simulate Phish", use_container_width=True, help="Simulate a spearphishing email attempt"):
            st.session_state.dash_phish_score = 85
            st.session_state.dash_kc_risk = 60
            st.session_state.dash_phish_blocked += 1
            st.toast("Simulated Phishing Incident!", icon="🎣")
            st.rerun()

    with ctrl_col2:
        if st.button("🦠 Simulate Malware", use_container_width=True, help="Simulate a malware signature execution attempt"):
            st.session_state.dash_mal_score = 95
            st.session_state.dash_kc_risk = 75
            st.session_state.dash_mal_quarantined += 1
            st.toast("Simulated Malware signature trigger!", icon="🦠")
            st.rerun()

    with ctrl_col3:
        if st.button("📡 Simulate Recon", use_container_width=True, help="Simulate external reconnaissance scans"):
            st.session_state.dash_recon_flags = 4
            st.toast("Simulated External Recon scan detected!", icon="📡")
            st.rerun()

    with ctrl_col4:
        if st.button("🛡️ Host Isolation", use_container_width=True, type="primary", help="Isolate compromise nodes and block hashes"):
            st.session_state.dash_phish_score = min(st.session_state.dash_phish_score, 25)
            st.session_state.dash_mal_score = min(st.session_state.dash_mal_score, 20)
            st.session_state.dash_recon_flags = max(0, st.session_state.dash_recon_flags - 3)
            st.session_state.dash_kc_risk = min(st.session_state.dash_kc_risk, 15)
            st.toast("Defense policies pushed. Network endpoints isolated.", icon="🛡️")
            st.rerun()

    with ctrl_col5:
        if st.button("🧹 Clear Logs", use_container_width=True, help="Clear active queue and reset simulator telemetry"):
            st.session_state.dash_phish_score = 0
            st.session_state.dash_mal_score = 0
            st.session_state.dash_recon_flags = 0
            st.session_state.dash_kc_risk = 0
            st.toast("Security console alerts cleared.", icon="🧹")
            st.rerun()

    st.write("")
    st.markdown('<div class="section-title">Blue Team Action Items</div>', unsafe_allow_html=True)
    for i, action in enumerate(dashboard.blue_team_actions, 1):
        st.markdown(f"{i}. {action}")


def page_phishing():
    render_header()
    tab_url, tab_email = st.tabs(["URL Analysis", "Email Header Analysis"])

    with tab_url:
        url = st.text_input("Enter URL to analyze", placeholder="https://suspicious-site.example/login")
        if st.button("Scan URL", type="primary") and url:
            with st.spinner("Running anti-phishing heuristics..."):
                report = analyze_url(url)
            st.markdown(f'**Verdict:** <span class="{verdict_class(report.verdict)}">{report.verdict.upper()}</span> — Score: **{report.score}/100**', unsafe_allow_html=True)
            if report.indicators:
                st.warning("Indicators: " + " | ".join(report.indicators))
            st.json({"metadata": report.metadata, "mitre": report.mitre_techniques, "recommendations": report.recommendations})

    with tab_email:
        headers = st.text_area("Paste raw email headers", height=200)
        if st.button("Analyze Headers") and headers:
            report = analyze_email_headers(headers)
            st.markdown(f'**Verdict:** <span class="{verdict_class(report.verdict)}">{report.verdict.upper()}</span> — Score: **{report.score}/100**', unsafe_allow_html=True)
            for rec in report.recommendations:
                st.info(rec)


def page_malware():
    render_header()
    tab_file, tab_hash = st.tabs(["File Upload", "Hash Lookup"])

    with tab_file:
        uploaded = st.file_uploader("Upload file for malware analysis", type=None)
        if uploaded and st.button("Scan File", type="primary"):
            content = uploaded.read()
            with st.spinner("Scanning with signature + heuristic engine..."):
                report = scan_file_content(content, uploaded.name)
            st.markdown(f'**Verdict:** <span class="{verdict_class(report.verdict)}">{report.verdict.upper()}</span> — Score: **{report.score}/100**', unsafe_allow_html=True)
            st.write("**Hashes:**")
            st.code(json.dumps(report.hashes, indent=2))
            if report.signatures_matched:
                st.error("Matched signatures:\n" + "\n".join(f"- {s}" for s in report.signatures_matched))
            st.write("**MITRE Techniques:**", ", ".join(report.mitre_techniques))

    with tab_hash:
        h = st.text_input("MD5 or SHA256 hash")
        if st.button("Lookup Hash") and h:
            report = scan_hash(h)
            st.markdown(f'**Verdict:** {report.verdict.upper()} — {report.signatures_matched[0]}')


def page_antivirus():
    render_header()
    st.markdown("**BlueShield AV Engine** — signature-based mini antivirus for SOC triage")

    col1, col2 = st.columns(2)
    with col1:
        uploaded = st.file_uploader("Quick AV scan", key="av_upload")
        if uploaded and st.button("Run AV Scan", type="primary"):
            result = MiniAntivirus.scan_bytes(uploaded.read(), uploaded.name)
            st.metric("Threats Found", result.threats_found)
            st.metric("Scan Time (ms)", result.scan_duration_ms)
            if result.quarantine_recommended:
                st.error("⚠️ QUARANTINE RECOMMENDED")
            st.json({"detections": result.detections})

    with col2:
        scan_dir = st.text_input("Directory path to scan", value=".")
        if st.button("Scan Directory"):
            result = MiniAntivirus.scan_directory(scan_dir, max_files=30)
            st.metric("Files Scanned", result.scanned_items)
            st.metric("Threats", result.threats_found)
            if result.detections:
                st.dataframe(pd.DataFrame(result.detections), use_container_width=True)


def page_recon():
    render_header()
    target = st.text_input("Target domain or URL", placeholder="example.com")
    platforms = st.multiselect(
        "Recon platforms",
        list(RECON_PLATFORMS.keys()),
        default=["dns", "whois", "ssl", "ports"],
    )

    if st.button("Launch Recon", type="primary") and target:
        with st.spinner("Running multi-platform reconnaissance..."):
            results = run_full_recon(target, platforms)
            aggregated = aggregate_recon_findings(results)

        st.metric("Risk Flags", aggregated["total_risk_flags"])
        for r in results:
            with st.expander(f"📡 {r.platform} — {r.target}"):
                if r.risk_flags:
                    for f in r.risk_flags:
                        st.warning(f)
                st.json(r.findings)


def page_kill_chain():
    render_header()
    st.markdown("Map your scan findings to the **Lockheed Martin Cyber Kill Chain**")

    for stage in get_all_stages_info():
        st.markdown(f"""
        <div class="kill-chain-stage">
            <strong>{stage['stage']}</strong><br>
            <small>{stage['description']}</small><br>
            <em>MITRE: {stage['mitre_tactics']}</em>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("Kill Chain Assessment")
    phish = st.slider("Phishing score", 0, 100, 40)
    malware = st.slider("Malware score", 0, 100, 30)
    c2 = st.checkbox("C2 indicators detected")

    findings = {
        "phishing_score": phish,
        "malware_score": malware,
        "malware_detected": malware > 60,
        "c2_indicators": c2,
        "open_ports": True,
    }
    assessment = map_findings_to_kill_chain(findings)

    st.metric("Risk Score", f"{assessment.risk_score}/100")
    st.write(assessment.narrative)
    if assessment.current_stage:
        st.error(f"Current Stage: **{assessment.current_stage.value}**")
    st.subheader("SOC Playbook")
    for step in assessment.soc_playbook:
        st.markdown(f"- {step}")


def page_mitre():
    render_header()

    tab_search, tab_compare, tab_phish, tab_stats = st.tabs(
        ["Search Techniques", "Compare Techniques", "Phishing TTPs", "Tactic Statistics"]
    )

    with st.spinner("Loading MITRE ATT&CK data..."):
        try:
            techniques = parse_techniques()
            st.session_state["mitre_techniques"] = techniques
        except Exception as exc:
            st.error(f"Failed to fetch MITRE data: {exc}")
            techniques = []

    with tab_search:
        q = st.text_input("Search MITRE ATT&CK", placeholder="T1566 phishing")
        if q:
            results = search_techniques(q, techniques)
            rows = [{"ID": t.technique_id, "Name": t.name, "Tactics": ", ".join(t.tactics)} for t in results[:25]]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with tab_compare:
        c1, c2 = st.columns(2)
        with c1:
            id_a = st.text_input("Technique A", value="T1566")
        with c2:
            id_b = st.text_input("Technique B", value="T1566.001")
        if st.button("Compare & Analyze", type="primary"):
            comparison = compare_techniques(id_a, id_b, techniques)
            if comparison:
                st.success(comparison.recommendation)
                st.write(f"**Similarity Score:** {comparison.similarity_score}%")
                st.write(f"**Shared Tactics:** {', '.join(comparison.shared_tactics) or 'None'}")
                st.write(f"**Shared Platforms:** {', '.join(comparison.shared_platforms) or 'None'}")
                col1, col2 = st.columns(2)
                with col1:
                    st.subheader(comparison.technique_a.technique_id)
                    st.write(comparison.technique_a.name)
                    st.caption(comparison.technique_a.description[:300])
                with col2:
                    st.subheader(comparison.technique_b.technique_id)
                    st.write(comparison.technique_b.name)
                    st.caption(comparison.technique_b.description[:300])
            else:
                st.error("One or both technique IDs not found.")

    with tab_phish:
        phish_techs = get_phishing_related_techniques(techniques)
        st.write(f"Found **{len(phish_techs)}** phishing-related techniques")
        rows = [{"ID": t.technique_id, "Name": t.name, "Tactics": ", ".join(t.tactics)} for t in phish_techs[:30]]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with tab_stats:
        summary = get_tactic_summary(techniques)
        df = pd.DataFrame(list(summary.items()), columns=["Tactic", "Count"])
        fig = px.bar(df.head(15), x="Tactic", y="Count", color="Count", color_continuous_scale="Blues")
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={"color": "#e2e8f0"})
        st.plotly_chart(fig, use_container_width=True)


def page_prompts():
    render_header()
    
    tab_chat, tab_ref = st.tabs(["💬 Gemini SOC Assistant", "📄 Reference System Prompts"])
    
    with tab_chat:
        render_soc_chatbot(st.session_state.get("gemini_key", ""))
        
    with tab_ref:
        st.markdown("Load balanced JSON prompts for **Gemini** and **Claude** to extend this platform.")
        prompts_dir = ROOT / "prompts"
        for name in ["master_prompt.json", "gemini_prompt.json", "claude_prompt.json"]:
            path = prompts_dir / name
            if path.exists():
                with st.expander(f"📄 {name}"):
                    content = path.read_text(encoding="utf-8")
                    st.code(content, language="json")
                    st.download_button(f"Download {name}", content, file_name=name, mime="application/json")


PAGES = {
    "🏠 SOC Dashboard": page_dashboard,
    "🎣 Anti-Phishing Scanner": page_phishing,
    "🦠 Malware & Virus Scanner": page_malware,
    "🛡️ Mini Antivirus": page_antivirus,
    "🔍 Recon Platforms": page_recon,
    "⛓️ Cyber Kill Chain": page_kill_chain,
    "🎯 MITRE ATT&CK": page_mitre,
    "🤖 AI Assistant & Prompts": page_prompts,
}


def main():
    page = sidebar()
    PAGES[page]()


if __name__ == "__main__":
    main()

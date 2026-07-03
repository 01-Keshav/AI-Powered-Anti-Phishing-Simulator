import json
import streamlit as st
import os

# Helper to load MITRE data
def load_mitre_data() -> dict:
    """Loads local MITRE ATT&CK techniques database."""
    filepath = os.path.join("data", "mitre_techniques.json")
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            st.error(f"Error loading MITRE data: {e}")
            return {}
    return {}

# Map MITRE techniques to Cyber Kill Chain phases
KILL_CHAIN_MAPPING = {
    "Reconnaissance": ["T1595", "T1592", "T1589", "T1590", "T1591"],
    "Weaponization": ["T1204", "T1027", "T1204.002", "T1587", "T1588"],
    "Delivery": ["T1566", "T1566.001", "T1566.002", "T1566.003", "T1189"],
    "Exploitation": ["T1203", "T1059", "T1059.001", "T1059.003", "T1211"],
    "Installation": ["T1547", "T1547.001", "T1053.005", "T1543", "T1569"],
    "Command & Control": ["T1071", "T1071.001", "T1105", "T1090", "T1043"],
    "Actions on Objectives": ["T1048", "T1486", "T1490", "T1114", "T1020"]
}

def render_mitre_explorer(is_dark: bool):
    """Renders the MITRE ATT&CK & Cyber Kill Chain Explorer interface."""
    mitre_db = load_mitre_data()
    
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <h3 style="margin: 0; font-size: 1.25rem;">MITRE ATT&CK & Cyber Kill Chain Intelligence</h3>
        <p style="margin: 0; font-size: 0.8rem; color: var(--text-dim);">Map threat behaviors, search tactics, and compare security controls side-by-side.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Tabs for MITRE sections
    sub_tabs = st.tabs(["🔍 Technique Search", "⚖️ Compare Techniques", "🔗 Cyber Kill Chain Mapping"])
    
    # Tab 1: Technique Search
    with sub_tabs[0]:
        st.markdown("<p style='font-size: 0.85rem; margin-bottom: 1rem;'>Search local enterprise techniques database or fetch definitions.</p>", unsafe_allow_html=True)
        search_query = st.text_input("Search techniques (by ID, Name, or Tactic)", "", placeholder="e.g. Phishing, T1059, Defense Evasion")
        
        filtered_techniques = {}
        for tid, tinfo in mitre_db.items():
            query = search_query.lower()
            if (query in tid.lower() or 
                query in tinfo["name"].lower() or 
                query in tinfo["tactic"].lower() or 
                query in tinfo["description"].lower()):
                filtered_techniques[tid] = tinfo
                
        if not filtered_techniques:
            st.warning("No techniques match your search query.")
        else:
            # Display matching techniques as expanders
            for tid, tinfo in filtered_techniques.items():
                with st.expander(f"**{tid}** - {tinfo['name']} ({tinfo['tactic']})"):
                    st.markdown(f"**Kill Chain Phase:** `{tinfo.get('kill_chain_phase', 'N/A')}`")
                    st.markdown(f"**Description:**\n{tinfo['description']}")
                    
                    # Layout detection and mitigations
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown(f"""
                        <div style="background: rgba(37,99,235,0.05); border: 1px solid var(--border); padding: 0.85rem; border-radius: var(--radius); height: 100%;">
                            <span class="badge badge-blue">🔍 Detection Controls</span>
                            <p style="font-size: 0.8rem; margin-top: 0.5rem; line-height: 1.4;">{tinfo['detection']}</p>
                        </div>
                        """, unsafe_allow_html=True)
                    with c2:
                        st.markdown(f"""
                        <div style="background: rgba(34,197,94,0.05); border: 1px solid var(--border); padding: 0.85rem; border-radius: var(--radius); height: 100%;">
                            <span class="badge badge-green">🛡️ Mitigation Strategies</span>
                            <p style="font-size: 0.8rem; margin-top: 0.5rem; line-height: 1.4;">{tinfo['mitigation']}</p>
                        </div>
                        """, unsafe_allow_html=True)

    # Tab 2: Compare Techniques
    with sub_tabs[1]:
        st.markdown("<p style='font-size: 0.85rem; margin-bottom: 1rem;'>Select two techniques to compare security mitigations and detection strategies.</p>", unsafe_allow_html=True)
        
        list_tids = list(mitre_db.keys())
        if len(list_tids) >= 2:
            col_sel1, col_sel2 = st.columns(2)
            with col_sel1:
                t1_id = st.selectbox("Select Technique A", list_tids, index=0)
            with col_sel2:
                t2_id = st.selectbox("Select Technique B", list_tids, index=1)
                
            t1 = mitre_db[t1_id]
            t2 = mitre_db[t2_id]
            
            # Side-by-side comparison table / cards
            comp_col1, comp_col2 = st.columns(2)
            with comp_col1:
                st.markdown(f"""
                <div class="chart-wrap" style="height: 100%;">
                    <div style="border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-bottom: 0.75rem;">
                        <span class="badge badge-blue">{t1_id}</span>
                        <div class="chart-title" style="font-size: 1.05rem; margin-top: 0.25rem;">{t1['name']}</div>
                        <div class="chart-subtitle" style="margin:0;">Tactic: {t1['tactic']} | Phase: {t1.get('kill_chain_phase', 'N/A')}</div>
                    </div>
                    <p style="font-size: 0.8rem; line-height: 1.4; margin-bottom: 1rem;"><strong>Description:</strong> {t1['description']}</p>
                    <div style="margin-bottom: 0.85rem;">
                        <div style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.2rem;">DETECTION RULES:</div>
                        <div style="font-size: 0.8rem; background: var(--bg-subtle); padding: 0.5rem; border-radius: 6px; border: 1px dashed var(--border);">{t1['detection']}</div>
                    </div>
                    <div>
                        <div style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.2rem;">BEST MITIGATIONS:</div>
                        <div style="font-size: 0.8rem; background: var(--bg-subtle); padding: 0.5rem; border-radius: 6px; border: 1px dashed var(--border);">{t1['mitigation']}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
            with comp_col2:
                st.markdown(f"""
                <div class="chart-wrap" style="height: 100%;">
                    <div style="border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-bottom: 0.75rem;">
                        <span class="badge badge-blue">{t2_id}</span>
                        <div class="chart-title" style="font-size: 1.05rem; margin-top: 0.25rem;">{t2['name']}</div>
                        <div class="chart-subtitle" style="margin:0;">Tactic: {t2['tactic']} | Phase: {t2.get('kill_chain_phase', 'N/A')}</div>
                    </div>
                    <p style="font-size: 0.8rem; line-height: 1.4; margin-bottom: 1rem;"><strong>Description:</strong> {t2['description']}</p>
                    <div style="margin-bottom: 0.85rem;">
                        <div style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.2rem;">DETECTION RULES:</div>
                        <div style="font-size: 0.8rem; background: var(--bg-subtle); padding: 0.5rem; border-radius: 6px; border: 1px dashed var(--border);">{t2['detection']}</div>
                    </div>
                    <div>
                        <div style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.2rem;">BEST MITIGATIONS:</div>
                        <div style="font-size: 0.8rem; background: var(--bg-subtle); padding: 0.5rem; border-radius: 6px; border: 1px dashed var(--border);">{t2['mitigation']}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("Insufficient techniques in database to perform comparison.")

    # Tab 3: Cyber Kill Chain Mapping
    with sub_tabs[2]:
        st.markdown("""
        <p style='font-size: 0.85rem; margin-bottom: 1.5rem;'>
            Visual mapping of MITRE ATT&CK Techniques against the Lockheed Martin Cyber Kill Chain phases. 
            Click on any phase to view associated techniques and threat descriptions.
        </p>
        """, unsafe_allow_html=True)
        
        # We can construct a beautiful horizontal flowchart / vertical cards layout representing the 7 steps
        for idx, (phase, t_list) in enumerate(KILL_CHAIN_MAPPING.items(), 1):
            phase_num_badge = f"""
            <span style="background: var(--accent); color: white; border-radius: 50%; width: 1.25rem; height: 1.25rem; display: inline-flex; align-items: center; justify-content: center; font-size: 0.75rem; font-weight: bold; margin-right: 0.5rem;">
                {idx}
            </span>
            """
            with st.expander(f"{idx}. {phase}"):
                st.markdown(f"**Cyber Kill Chain Stage {idx}: {phase}**")
                
                # Render matched techniques in local db
                available_matches = []
                for tid in t_list:
                    # check if direct tid is in db, or search by subtechnique
                    if tid in mitre_db:
                        available_matches.append((tid, mitre_db[tid]))
                    else:
                        # check if there's any related subtechnique
                        for local_tid, local_tinfo in mitre_db.items():
                            if local_tid.startswith(tid + "."):
                                available_matches.append((local_tid, local_tinfo))
                
                if available_matches:
                    rows = ""
                    for tid, tinfo in available_matches:
                        rows += f"""
                        <tr>
                            <td style="font-weight:600; width: 15%;">{tid}</td>
                            <td style="font-weight:500; width: 25%; color: var(--accent);">{tinfo['name']}</td>
                            <td style="font-size: 0.78rem;">{tinfo['description'][:140]}...</td>
                        </tr>
                        """
                    st.markdown(f"""
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Technique ID</th>
                                <th>Name</th>
                                <th>Threat Overview</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows}
                        </tbody>
                    </table>
                    """, unsafe_allow_html=True)
                else:
                    # General phase description fallback
                    descriptions = {
                        "Reconnaissance": "Harvesting email addresses, identifying target systems, domain footprinting, and technology profiling.",
                        "Weaponization": "Coupling exploit with backdoor payload into deliverable payload (e.g. PDF/macro documents, custom executables).",
                        "Delivery": "Transmitting weaponized payload to target via email attachments, malicious web links, or USB drives.",
                        "Exploitation": "Triggering malicious code execution targeting application vulnerabilities or operating system flaws.",
                        "Installation": "Installing backdoor payload or registry persistence on victim endpoint to maintain control.",
                        "Command & Control": "Opening interactive C2 communication channel over HTTP/HTTPS/DNS to external command servers.",
                        "Actions on Objectives": "Executing objective goals like data exfiltration, lateral movement, or system encryption (ransomware)."
                    }
                    st.info(f"No specific techniques linked. Phase focus: {descriptions.get(phase, '')}")

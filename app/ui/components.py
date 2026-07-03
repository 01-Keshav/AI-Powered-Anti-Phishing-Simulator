"""Custom CSS and UI helpers for the SOC dashboard."""

SOC_THEME_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');

:root {
    --bg-primary: #0a0e17;
    --bg-secondary: #111827;
    --bg-card: #1a2332;
    --accent-cyan: #00d4ff;
    --accent-green: #00ff88;
    --accent-red: #ff4757;
    --accent-orange: #ffa502;
    --accent-purple: #a855f7;
    --text-primary: #e2e8f0;
    --text-muted: #94a3b8;
    --border: #2d3748;
}

.stApp {
    background: linear-gradient(135deg, #0a0e17 0%, #111827 50%, #0f172a 100%);
    font-family: 'Inter', sans-serif;
    color: var(--text-primary);
}

.main-header {
    background: linear-gradient(90deg, #00d4ff22, #a855f722);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 2rem 2.5rem;
    margin-bottom: 2rem;
    backdrop-filter: blur(10px);
}

.main-header h1 {
    font-size: 2.2rem;
    font-weight: 700;
    background: linear-gradient(90deg, #00d4ff, #00ff88);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0.5rem;
}

.main-header p {
    color: var(--text-muted);
    font-size: 1.05rem;
    margin: 0;
}

.metric-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem;
    text-align: center;
    transition: transform 0.2s, box-shadow 0.2s;
}

.metric-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0, 212, 255, 0.15);
}

.metric-value {
    font-size: 2rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
}

.metric-label {
    color: var(--text-muted);
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.verdict-malicious { color: var(--accent-red); }
.verdict-suspicious { color: var(--accent-orange); }
.verdict-clean { color: var(--accent-green); }

.soc-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.badge-critical { background: #ff475733; color: #ff4757; border: 1px solid #ff4757; }
.badge-high { background: #ff6b3533; color: #ff6b35; border: 1px solid #ff6b35; }
.badge-medium { background: #ffa50233; color: #ffa502; border: 1px solid #ffa502; }
.badge-low { background: #2ed57333; color: #2ed573; border: 1px solid #2ed573; }

.kill-chain-stage {
    background: var(--bg-card);
    border-left: 4px solid var(--accent-cyan);
    padding: 1rem 1.25rem;
    margin: 0.5rem 0;
    border-radius: 0 8px 8px 0;
}

.section-title {
    font-size: 1.3rem;
    font-weight: 600;
    color: var(--accent-cyan);
    margin: 1.5rem 0 1rem 0;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
}

.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background: var(--bg-secondary);
    border-radius: 12px;
    padding: 4px;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 8px;
    font-weight: 500;
}

div[data-testid="stSidebar"] {
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
}

.sidebar-brand {
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--accent-cyan);
    padding: 1rem 0;
}
</style>
"""


def render_header():
    import streamlit as st
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ AI-Powered Anti-Phishing Simulator</h1>
        <p>SOC Analyst Platform · Blue Team Operations · MITRE ATT&CK · Cyber Kill Chain</p>
    </div>
    """, unsafe_allow_html=True)


def render_metric(label: str, value: str | int, color: str = "#00d4ff"):
    import streamlit as st
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value" style="color:{color}">{value}</div>
        <div class="metric-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)


def verdict_class(verdict: str) -> str:
    return {
        "malicious": "verdict-malicious",
        "suspicious": "verdict-suspicious",
        "clean": "verdict-clean",
    }.get(verdict, "")


def severity_badge(severity: str) -> str:
    return f'<span class="soc-badge badge-{severity}">{severity.upper()}</span>'

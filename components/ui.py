import streamlit as st

def inject_custom_css(is_dark: bool):
    """Injects custom CSS to style the Streamlit app beautifully according to the design system."""
    bg = "#09090b" if is_dark else "#ffffff"
    bg_subtle = "#0c0c0f" if is_dark else "#f9fafb"
    card = "#0c0c0f" if is_dark else "#ffffff"
    card_hover = "#131316" if is_dark else "#f4f4f5"
    border = "#1e1e24" if is_dark else "#e4e4e7"
    border_subtle = "#16161a" if is_dark else "#f0f0f2"
    text = "#fafafa" if is_dark else "#09090b"
    text_dim = "#52525b" if is_dark else "#a1a1aa"
    shadow = "none" if is_dark else "0 1px 3px rgba(0,0,0,0.04), 0 1px 2px rgba(0,0,0,0.03)"
    
    css = f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,100..1000;1,9..40,100..1000&family=JetBrains+Mono:ital,wght@0,100..800;1,100..800&display=swap');
    
    :root {{
        --bg: {bg};
        --bg-subtle: {bg_subtle};
        --card: {card};
        --card-hover: {card_hover};
        --border: {border};
        --border-subtle: {border_subtle};
        --text: {text};
        --text-muted: #71717a;
        --text-dim: {text_dim};
        --accent: #2563eb;
        --accent-muted: #1d4ed8;
        --green: {"#22c55e" if is_dark else "#16a34a"};
        --green-muted: {"rgba(34,197,94,0.12)" if is_dark else "rgba(22,163,74,0.08)"};
        --red: {"#ef4444" if is_dark else "#dc2626"};
        --red-muted: {"rgba(239,68,68,0.12)" if is_dark else "rgba(220,38,38,0.08)"};
        --amber: {"#f59e0b" if is_dark else "#d97706"};
        --amber-muted: {"rgba(245,158,11,0.12)" if is_dark else "rgba(217,119,6,0.08)"};
        --shadow: {shadow};
        --radius: 10px;
    }}
    
    /* Hide Streamlit default components */
    header[data-testid="stHeader"], #MainMenu, footer, [data-testid="stToolbar"],
    [data-testid="stDecoration"], [data-testid="stStatusWidget"], .stDeployButton,
    div[data-testid="stSidebarCollapsedControl"] {{
        display: none !important;
    }}
    
    /* Global Background and Typography */
    html, body, [data-testid="stAppViewContainer"], [data-testid="stApp"], .main, .block-container, section[data-testid="stMain"] {{
        background-color: var(--bg) !important;
        color: var(--text) !important;
        font-family: 'DM Sans', -apple-system, sans-serif !important;
    }}
    
    .block-container {{
        padding: 1.5rem 2.5rem 2rem !important;
        max-width: 1360px !important;
    }}
    
    /* Tab System Overrides (Pill style) */
    button[data-baseweb="tab"] {{
        background: transparent !important;
        color: var(--text-muted) !important;
        font-size: 0.85rem !important;
        font-weight: 500 !important;
        padding: 0.55rem 1.1rem !important;
        border: 1px solid transparent !important;
        border-radius: 7px !important;
        transition: all 0.2s ease !important;
        margin-right: 4px !important;
    }}
    button[data-baseweb="tab"]:hover {{
        color: var(--text) !important;
        background: var(--card-hover) !important;
    }}
    button[data-baseweb="tab"][aria-selected="true"] {{
        color: var(--text) !important;
        background: var(--card) !important;
        border-color: var(--border) !important;
        box-shadow: var(--shadow) !important;
    }}
    [data-baseweb="tab-highlight"], [data-baseweb="tab-border"] {{
        display: none !important;
    }}
    [data-baseweb="tab-list"] {{
        gap: 4px !important;
        background: var(--bg-subtle) !important;
        border: 1px solid var(--border) !important;
        border-radius: 10px !important;
        padding: 4px !important;
        margin-bottom: 1.5rem !important;
    }}
    
    /* Horizontal columns gap */
    [data-testid="stHorizontalBlock"] {{
        gap: 1.25rem !important;
    }}
    [data-testid="stVerticalBlock"] > div:has(> [data-testid="stHorizontalBlock"]) {{
        margin-bottom: 0.5rem !important;
    }}
    
    /* Metric Card Styling */
    .metric-card {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        padding: 1.25rem 1.4rem;
        box-shadow: var(--shadow);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }}
    .metric-card:hover {{
        transform: translateY(-2px);
        border-color: var(--accent);
    }}
    .metric-label {{
        font-size: 0.78rem;
        color: var(--text-muted);
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }}
    .metric-value {{
        font-size: 1.85rem;
        font-weight: 700;
        color: var(--text);
        letter-spacing: -0.03em;
        margin-top: 0.2rem;
    }}
    .metric-delta {{
        font-size: 0.75rem;
        font-weight: 500;
        margin-top: 0.4rem;
        padding: 2px 8px;
        border-radius: 6px;
        display: inline-flex;
        align-items: center;
        gap: 3px;
    }}
    .delta-up {{ color: var(--green); background: var(--green-muted); }}
    .delta-down {{ color: var(--red); background: var(--red-muted); }}
    .delta-warn {{ color: var(--amber); background: var(--amber-muted); }}
    
    /* Chart and Panel Containers */
    .chart-wrap {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        padding: 1.2rem;
        box-shadow: var(--shadow);
        margin-bottom: 1rem;
    }}
    .chart-title {{
        font-size: 0.9rem;
        font-weight: 600;
        color: var(--text);
    }}
    .chart-subtitle {{
        font-size: 0.75rem;
        color: var(--text-dim);
        margin-bottom: 1rem;
    }}
    
    /* Data Tables Custom Styling */
    .data-table {{
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        font-size: 0.8rem;
        margin-top: 0.5rem;
    }}
    .data-table th {{
        text-align: left;
        padding: 0.75rem 0.8rem;
        color: var(--text-muted);
        font-weight: 600;
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        border-bottom: 1px solid var(--border);
    }}
    .data-table td {{
        padding: 0.75rem 0.8rem;
        color: var(--text);
        border-bottom: 1px solid var(--border-subtle);
        vertical-align: middle;
    }}
    .data-table tr:last-child td {{
        border-bottom: none;
    }}
    .data-table tr:hover td {{
        background-color: var(--card-hover);
    }}
    
    /* Badges */
    .badge {{
        display: inline-block;
        padding: 2px 9px;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.02em;
    }}
    .badge-green {{ color: var(--green); background: var(--green-muted); }}
    .badge-red {{ color: var(--red); background: var(--red-muted); }}
    .badge-amber {{ color: var(--amber); background: var(--amber-muted); }}
    .badge-blue {{ color: var(--accent); background: rgba(37,99,235,0.1); }}
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {{
        background-color: var(--bg-subtle) !important;
        border-right: 1px solid var(--border) !important;
    }}
    section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {{
        font-size: 0.85rem !important;
    }}
    
    /* Codeblock custom styling */
    code {{
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.82rem !important;
    }}
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)

def metric_card(label: str, value: str, delta: str = None, delta_type: str = "up"):
    """Renders a beautiful styled KPI card."""
    cls = f"delta-{delta_type}"
    arrow = "↑" if delta_type == "up" else ("↓" if delta_type == "down" else "→")
    delta_html = f'<div class="metric-delta {cls}">{arrow} {delta}</div>' if delta else ""
    
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        {delta_html}
    </div>
    """, unsafe_allow_html=True)

def brand_header(title: str, is_dark: bool, toggle_callback):
    """Renders the top branding header with logo, title, and theme toggler."""
    h_col1, h_col2 = st.columns([8, 2])
    with h_col1:
        st.markdown(f"""
        <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1.5rem;">
            <div style="background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); width: 2.2rem; height: 2.2rem; border-radius: 8px; display: flex; align-items: center; justify-content: center; color: white; font-weight: 800; font-size: 1.2rem; box-shadow: 0 4px 12px rgba(37,99,235,0.25);">
                🛡️
            </div>
            <div>
                <h1 style="margin: 0; font-size: 1.6rem; font-weight: 800; letter-spacing: -0.02em;">{title}</h1>
                <p style="margin: 0; font-size: 0.75rem; color: #71717a;">AI-Driven Threat Simulation & Blue Teaming Console</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
    with h_col2:
        theme_label = "☀️ Light Console" if is_dark else "🌙 Dark Console"
        st.button(theme_label, on_click=toggle_callback, key="global_theme_toggle_btn", use_container_width=True)

def get_plotly_layout(is_dark: bool):
    """Returns a pre-configured Plotly chart layout compatible with the UI theme."""
    grid_color = "rgba(255,255,255,0.05)" if is_dark else "rgba(0,0,0,0.05)"
    text_color = "#a1a1aa" if is_dark else "#71717a"
    return dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="DM Sans, sans-serif", color=text_color, size=11),
        margin=dict(l=40, r=20, t=20, b=40),
        xaxis=dict(
            gridcolor=grid_color,
            zerolinecolor=grid_color,
            tickfont=dict(size=10, color=text_color),
        ),
        yaxis=dict(
            gridcolor=grid_color,
            zerolinecolor=grid_color,
            tickfont=dict(size=10, color=text_color),
        ),
        legend=dict(
            font=dict(size=10, color=text_color),
            bgcolor="rgba(0,0,0,0)"
        )
    )

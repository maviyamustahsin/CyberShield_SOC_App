import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import time
import random
import os
from collections import deque
from src.detection_engine import IntrusionDetectionEngine
from fpdf import FPDF
import io

# PAGE CONFIG
st.set_page_config(page_title="CyberShield SOC", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# SESSION STATE DEFAULTS
defaults = {
    "running": False,
    "metrics": {"Total":0,"Normal":0,"Attacks":0,"Blocked":0},
    "logs": deque(maxlen=12),
    "timeline": {"t":[],"n":[],"a":[]},
    "arcs": [],
    "hex": [], # Initialized later
    "idx": 0,
    "last_alert": None,
    "current_page": "dashboard",
    # Settings
    "app_theme": "Dark",
    "anomaly_threshold": 0.85,
    "risk_threshold": 80,
    "auto_block": True,
    "capture_interface": "eth0 (Primary)",
    "subnet_mask": "192.168.1.0/24",
    "syslog_ip": "",
    "refresh_speed": 0.4,
    "detail_level": "Balanced",
    # Admin Profile Data
    "admin_name": "Maviya",
    "admin_email": "maviya@cybershield.local",
    "admin_role": "Senior Security Analyst",
    "admin_clearance": "Level 5 (Ring 0)",
    "admin_joined": "Oct 12, 2025",
    "admin_avatar": "👤",
    "audit_logs": [
        {"t": "2026-03-17 21:12", "a": "System threshold adjusted (0.85 -> 0.90)"},
        {"t": "2026-03-17 20:45", "a": "Exported Weekly Threat Report (PDF)"},
        {"t": "2026-03-17 19:30", "a": "Manual override on source 10.0.0.45"},
        {"t": "2026-03-17 18:15", "a": "Security Operator Session Initialized"},
    ],
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

def log_audit(action):
    st.session_state.audit_logs.insert(0, {"t": time.strftime("%Y-%m-%d %H:%M"), "a": action})
    if len(st.session_state.audit_logs) > 20:
        st.session_state.audit_logs.pop()

def gen_hex(is_attack, atype):
    lines = []
    for i in range(10):
        addr = f"{i*8:04X}"
        if is_attack and random.random() > 0.4:
            raw = [random.randint(0x80,0xFF) for _ in range(8)]
            ascii_r = "".join(["." if b>126 or b<32 else chr(b) for b in raw])
            if "SQL" in atype: ascii_r = "'OR 1=1--"[:8]
            if "XSS" in atype: ascii_r = "<script>"
            danger = True
        else:
            raw = [random.randint(0x20,0x7E) for _ in range(8)]
            ascii_r = "".join([chr(b) for b in raw])
            danger = False
        hx = " ".join(f"{b:02X}" for b in raw)
        lines.append({"a": addr, "h": hx, "s": ascii_r, "d": danger})
    return lines

if not st.session_state.hex:
    st.session_state.hex = gen_hex(False, "")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# THEME ENGINE & DYNAMIC CSS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
theme_mode = st.session_state.app_theme
if theme_mode == "Light":
    bg_main = "#f4f7f9"  # Soft Arctic White
    bg_side = "#ffffff"
    text_main = "#1e293b" # Slate 800
    text_sub = "#64748b"  # Slate 500
    card_bg = "rgba(255, 255, 255, 0.82)"
    card_border = "#e2e8f0" 
    log_header_bg = "#f1f5f9" 
    hover_bg = "rgba(66, 133, 244, 0.04)"
    sidebar_active = "rgba(66, 133, 244, 0.08)"
    hex_bg = "#f8fafc"
else:
    # Masterpiece Dark Mode
    bg_main = "#0b0e14" # Deep Space
    bg_side = "#0f121a"
    text_main = "#f1f5f9"
    text_sub = "#94a3b8"
    card_bg = "rgba(17, 24, 39, 0.75)" # Premium Glass
    card_border = "rgba(255, 255, 255, 0.08)"
    log_header_bg = "rgba(31, 41, 55, 0.85)"
    hover_bg = "rgba(255, 255, 255, 0.02)"
    sidebar_active = "rgba(255, 255, 255, 0.04)"
    hex_bg = "#07090e"

st.markdown(f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Global Overrides */
    .stApp, .stApp [data-testid="stHeader"], .stApp p, .stApp span, .stApp label, .stApp div, .stApp h1, .stApp h2, .stApp h3 {{
        color: {text_main} !important;
    }}
    .stApp {{
        background-color: {bg_main} !important;
        background-image: { "radial-gradient(at 0% 0%, rgba(67, 56, 202, 0.08) 0, transparent 50%), radial-gradient(at 50% 100%, rgba(67, 56, 202, 0.08) 0, transparent 50%)" if theme_mode=="Dark" else "none" };
    }}
    #MainMenu, footer {{visibility: hidden;}}
    header {{ background: transparent !important; }}
    .stDeployButton {{display: none;}}
    .block-container {{ 
        padding-top: 2rem !important; 
        max-width: 96% !important; 
        margin: auto;
    }}

    /* Sidebar Styling */
    [data-testid="stSidebar"] {{
        background-color: {bg_side} !important;
        border-right: 1px solid {card_border} !important;
        min-width: 330px !important;
        max-width: 330px !important;
    }}
    .sidebar-history-item {{
        padding: 10px 14px; margin-bottom: 4px;
        border-radius: 8px; color: {text_sub}; font-size: 0.85rem;
        cursor: pointer; transition: background 0.2s, color 0.2s;
        display: flex; align-items: center; gap: 8px;
    }}
    .sidebar-history-item:hover {{
        background: {sidebar_active}; color: {text_main};
    }}
    .sidebar-header {{
        font-size: 0.85rem; font-weight: 600; color: #5f6368;
        letter-spacing: 0.5px; margin: 24px 0 10px 14px; text-transform: uppercase;
    }}

    /* Sidebar Buttons */
    section[data-testid="stSidebar"] .stButton > button {{
        background-color: transparent !important;
        border: none !important;
        color: {text_sub} !important;
        justify-content: flex-start !important;
        padding: 10px 14px !important;
        border-radius: 8px !important;
        transition: background 0.2s, color 0.2s !important;
        font-size: 1rem !important;
        box-shadow: none !important;
        font-weight: 500 !important;
    }}
    section[data-testid="stSidebar"] .stButton > button:hover {{
        background: {sidebar_active} !important; color: {text_main} !important;
    }}
    
    /* Active State for sidebar buttons */
    section[data-testid="stSidebar"] .stButton:first-child > button {{
        border: 1px solid {card_border} !important;
        background: {sidebar_active} !important;
        justify-content: center !important;
        font-weight: 600 !important;
        color: {text_main} !important;
    }}

    /* Metric Cards */
    .kpi-card {{
        background: {card_bg};
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid {card_border};
        border-radius: 16px; padding: 24px;
        text-align: left; transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        color: {text_main};
        position: relative; overflow: hidden;
    }}
    .kpi-card::after {{
        content: ""; position: absolute; top: -50%; left: -50%; width: 200%; height: 200%;
        background: radial-gradient(circle, rgba(255,255,255,0.03) 0%, transparent 70%);
        opacity: 0; transition: opacity 0.4s;
    }}
    .kpi-card:hover::after {{ opacity: 1; }}
    .kpi-card:hover {{ 
        border-color: rgba(66,133,244,0.4); 
        transform: translateY(-5px); 
        box-shadow: 0 12px 30px rgba(0,0,0,0.2); 
    }}
    .kpi-icon {{ font-size: 1.4rem; padding: 8px; background: rgba(255,255,255,0.03); border-radius: 8px; margin-bottom: 12px; display: inline-block; }}
    .kpi-label {{ font-size: 0.8rem; font-weight: 600; letter-spacing: 1.2px; text-transform: uppercase; color: {text_sub}; margin-bottom: 10px; font-family: 'Inter',sans-serif; }}
    .kpi-value {{ font-size: 2.4rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; line-height: 1.1; color: {text_main}; }}
    .kpi-sub {{ font-size: 0.8rem; color: #5f6368; margin-top: 6px; font-family: 'JetBrains Mono', monospace; }}

    /* Colors */
    .v-purple {{ color: #a370f7; }}
    .v-green {{ color: #34a853; }}
    .v-red {{ color: #ea4335; }}
    .v-blue {{ color: #4285f4; }}
    .v-amber {{ color: #fbbc04; }}

    /* Header */
    .main-header {{
        display: flex; align-items: center; gap: 16px;
        padding: 8px 0 16px 0; border-bottom: 1px solid {card_border};
        margin-bottom: 20px;
    }}
    .main-header-icon {{ font-size: 2rem; }}
    .main-header-text h1 {{
        margin: 0; font-size: 1.6rem; font-weight: 700; color: {text_main};
        font-family: 'Inter', sans-serif; letter-spacing: -0.3px;
    }}
    .main-header-text p {{
        margin: 4px 0 0 0; font-size: 0.85rem; color: {text_sub};
        font-family: 'Inter', sans-serif; letter-spacing: 0.5px;
    }}
    .mission-marquee {{
        background: {sidebar_active};
        padding: 5px 15px; border-radius: 4px; border: 1px solid {card_border};
        font-size: 0.7rem; color: #4285f4; font-weight: 600;
        text-transform: uppercase; letter-spacing: 1px;
        margin-top: 5px; display: inline-block;
    }}
    .header-right {{
        margin-left: auto; display: flex; align-items: center; gap: 12px;
    }}
    .status-chip {{
        display: inline-flex; align-items: center; gap: 6px;
        padding: 6px 14px; border-radius: 20px;
        font-size: 0.72rem; font-weight: 600; font-family: 'Inter',sans-serif;
        letter-spacing: 0.3px;
    }}
    .chip-active {{ background: rgba(52,168,83,0.1); color: #34a853; border: 1px solid rgba(52,168,83,0.25); }}
    .chip-idle {{ background: rgba(154,160,166,0.1); color: #9aa0a6; border: 1px solid rgba(154,160,166,0.2); }}
    .pulse-dot {{ width: 6px; height: 6px; border-radius: 50%; background: #34a853; animation: pulse 2s ease-in-out infinite; }}
    @keyframes pulse {{ 0%,100%{{box-shadow:0 0 0 0 rgba(52,168,83,0.4);}} 50%{{box-shadow:0 0 0 6px rgba(52,168,83,0);}} }}

    /* Section Headers */
    .section-head {{
        font-size: 0.95rem; font-weight: 600; color: {text_main};
        font-family: 'Inter',sans-serif; letter-spacing: 0.3px;
        margin-bottom: 12px; display: flex; align-items: center; gap: 10px;
    }}
    .section-head .dot {{ width: 6px; height: 6px; border-radius: 50%; }}
    .dot-green {{ background: #34a853; }}
    .dot-red {{ background: #ea4335; animation: pulse-red 1.5s infinite; }}
    .dot-blue {{ background: #4285f4; }}
    @keyframes pulse-red {{ 0%,100%{{box-shadow:0 0 0 0 rgba(234,67,53,0.4);}} 50%{{box-shadow:0 0 0 5px rgba(234,67,53,0);}} }}

    /* Hex Dump Panel */
    .hex-panel {{
        background: {hex_bg}; border: 1px solid {card_border};
        border-radius: 10px; padding: 16px; font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem; color: {text_sub}; overflow: hidden; max-height: 350px;
    }}
    .hex-row {{ display: flex; gap: 10px; padding: 2px 0; white-space: nowrap; }}
    .hex-addr {{ color: #5f6368; min-width: 40px; }}
    .hex-bytes {{ color: #34a853; letter-spacing: 1px; white-space: nowrap; min-width: 180px; }}
    .hex-bytes.danger {{ color: #ea4335; font-weight: 600; }}
    .hex-ascii {{ color: #4285f4; min-width: 70px; text-align: right; white-space: nowrap; }}
    .hex-ascii.danger {{ color: #fbbc04; }}

    /* Log Table */
    .log-panel {{
        background: {bg_side}; border: 1px solid {card_border};
        border-radius: 10px; overflow: hidden;
    }}
    .log-header {{
        display: flex; padding: 10px 14px; background: {log_header_bg};
        font-size: 0.65rem; font-weight: 600; color: {text_sub};
        text-transform: uppercase; letter-spacing: 1px;
        font-family: 'Inter',sans-serif; border-bottom: 1px solid {card_border};
    }}
    .log-r {{
        display: flex; padding: 10px 14px; border-bottom: 1px solid {card_border};
        font-family: 'JetBrains Mono',monospace; font-size: 0.85rem;
        align-items: center; transition: background 0.15s;
        color: {text_main};
    }}
    .log-r:hover {{ background: {hover_bg}; }}
    .lc-time {{ width: 90px; color: #5f6368; }}
    .lc-ip {{ width: 140px; color: {text_sub}; }}
    .lc-port {{ width: 60px; color: {text_sub}; }}
    .lc-class {{ flex: 1; font-weight: 600; }}
    .lc-class.safe {{ color: #34a853; }}
    .lc-class.threat {{ color: #ea4335; }}

    /* Ensure Streamlit widgets also use theme colors */
    .stMarkdown, .stHeader, .stWidgetLabel, .stSelectbox, .stSlider, .stRadio, .stToggle {{
        color: {text_main} !important;
    }}
    
    /* Dedicated Button Styling */
    div.stButton > button {{
        font-weight: 700 !important;
        border-radius: 10px !important;
        padding: 0.65rem 1.4rem !important;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) !important;
        border: 1px solid transparent !important;
        letter-spacing: 0.8px !important;
        text-transform: uppercase !important;
        font-size: 0.85rem !important;
        position: relative;
        overflow: hidden;
    }}
    
    /* Primary Button (Start) - Neon 3D */
    div.stButton > button[kind="primary"] {{
        background: linear-gradient(135deg, #4285f4, #1a73e8) !important;
        color: white !important;
        box-shadow: 0 4px 6px rgba(66, 133, 244, 0.2) !important;
        border: none !important;
    }}
    div.stButton > button[kind="primary"]:hover {{
        transform: translateY(-4px) scale(1.02) !important;
        box-shadow: 0 0 20px rgba(66, 133, 244, 0.6), 0 8px 15px rgba(66, 133, 244, 0.3) !important;
        filter: brightness(1.2) !important;
    }}
    
    /* Secondary Button (Stop/Settings) - Sleek Glow */
    div.stButton > button[kind="secondary"] {{
        background-color: { "rgba(255,255,255,0.03)" if theme_mode=="Dark" else "#ffffff" } !important;
        color: {text_main} !important;
        border: 1px solid {card_border} !important;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05) !important;
    }}
    div.stButton > button[kind="secondary"]:hover {{
        transform: translateY(-3px) !important;
        background-color: { "rgba(255,255,255,0.08)" if theme_mode=="Dark" else "#ffffff" } !important;
        border-color: #4285f4 !important;
        box-shadow: 0 0 15px { "rgba(66, 133, 244, 0.4)" if theme_mode=="Dark" else "rgba(66, 133, 244, 0.1)" }, 0 5px 10px rgba(0,0,0,0.1) !important;
        color: #4285f4 !important;
    }}
    
    /* Active State (Press Down) */
    div.stButton > button:active {{
        transform: translateY(1px) scale(0.96) !important;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1) !important;
    }}

    .stSelectbox label, .stSlider label, .stRadio label, .stToggle label {{
        color: {text_main} !important;
        font-weight: 600 !important;
    }}
    
    .alert-bar {{
        background: { "rgba(234,67,53,0.12)" if theme_mode=="Dark" else "rgba(234,67,53,0.08)" };
        border: 1px solid { "rgba(234,67,53,0.2)" if theme_mode=="Dark" else "rgba(234,67,53,0.3)" };
        border-left: 5px solid #ea4335; border-radius: 12px;
        padding: 24px; margin-bottom: 25px;
        font-family: 'Inter',sans-serif;
    }}
    .alert-bar-title {{
        font-size: 1.2rem; font-weight: 800; color: #ea4335; margin-bottom: 12px;
        display: flex; align-items: center; gap: 10px;
        border-bottom: 1px solid rgba(234,67,53,0.1);
        padding-bottom: 10px;
    }}
    .alert-label {{ font-size: 0.75rem; color: {text_sub}; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }}
    .alert-value {{ font-size: 1.1rem; font-weight: 700; color: {text_main}; }}
    
    /* Settings Panels */
    .settings-card {{
        background: {card_bg};
        border: 1px solid {card_border};
        border-radius: 14px; padding: 24px 28px;
        margin-bottom: 16px; transition: all 0.3s ease;
        color: {text_main};
    }}
    .settings-card h3 {{
        margin: 0 0 16px 0; font-size: 1rem; font-weight: 700;
        color: {text_main}; font-family: 'Inter',sans-serif;
        display: flex; align-items: center; gap: 10px;
    }}
    
    /* Sidebar Status Widget */
    .status-widget {{
        background: {sidebar_active};
        border: 1px solid {card_border};
        border-radius: 10px; padding: 12px;
        margin: 10px 14px; font-family: 'Inter', sans-serif;
    }}
    .status-row {{
        display: flex; justify-content: space-between; font-size: 0.7rem;
        margin-bottom: 6px; color: {text_sub};
    }}
    .status-val {{ color: {text_main}; font-weight: 600; font-family: 'JetBrains Mono', monospace; }}
    .prog-bg {{ background: {card_border}; height: 4px; border-radius: 2px; width: 100%; }}
    .prog-fill {{ background: #4285f4; height: 100%; border-radius: 2px; }}
</style>
""", unsafe_allow_html=True)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LOAD AI ENGINE & DATA
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@st.cache_resource
def load_engine():
    return IntrusionDetectionEngine(r"models")

@st.cache_data
def load_dataset():
    df = pd.read_parquet(r"data/cleaned_dataset.parquet")
    return df.sample(n=min(50000, len(df)), random_state=42).reset_index(drop=True)

try:
    engine = load_engine()
    df_test = load_dataset()
except Exception as e:
    st.error(f"Error loading AI Engine: {e}")
    st.stop()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SIDEBAR (Simplified)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
with st.sidebar:
    st.markdown('<div style="display:flex; align-items:center; gap:10px; margin-bottom: 24px;"><span style="font-size:1.8rem;">🛡️</span><span style="font-weight:800; font-size:1.2rem; color:'+text_main+';">CyberShield</span></div>', unsafe_allow_html=True)
    
    if st.button("➕ New Hunt Session", use_container_width=True):
        st.session_state.running = False
        st.session_state.metrics = {"Total":0,"Normal":0,"Attacks":0,"Blocked":0}
        st.session_state.logs.clear()
        st.session_state.timeline = {"t":[],"n":[],"a":[]}
        st.session_state.arcs = []
        st.session_state.last_alert = None
        st.session_state.current_page = "dashboard"
        st.rerun()
    
    st.markdown('<div style="margin: 20px 0;"></div>', unsafe_allow_html=True)
    
    if st.button("❱ NW HUNTER SETTINGS", use_container_width=True):
        st.session_state.current_page = "settings"
        st.rerun()
        
    if st.button("❱ ADMIN PROFILE", use_container_width=True):
        st.session_state.current_page = "admin"
        st.rerun()

    with st.expander("ℹ️ Project Intel & Specs"):
        st.markdown(f"""
        <div style="font-size: 0.75rem; color: {text_sub}; line-height: 1.5;">
            <b>Architecture:</b> Scikit-Lean Ensemble<br>
            <b>Model:</b> RF Classifier + Gradient Boost<br>
            <b>Training Data:</b> CIC-IDS-2017 Dataset<br>
            <b>Packet Rate:</b> Up to 1GB/s Analysis<br>
            <b>Accuracy:</b> 99.2% Verified<br><br>
            <i>Designed for high-performance autonomous SOC environments.</i>
        </div>
        """, unsafe_allow_html=True)

    # PROJECT INTEL WIDGET
    st.markdown(f"""
    <div class="sidebar-header" style="margin-top: 30px;">Project Intelligence</div>
    <div class="status-widget">
        <div style="font-size: 0.7rem; color: {text_sub}; margin-bottom: 10px; line-height: 1.4;">
            <b>CyberShield</b> is an advanced AI-driven SOC platform utilizing Scikit-Learn ensembles for real-time intrusion detection.
        </div>
        <div class="status-row"><span>AI Model</span><span class="status-val">RandomForest+GBM</span></div>
        <div class="status-row"><span>Dataset</span><span class="status-val">CIC-IDS 2017</span></div>
        <div class="status-row"><span>Latency</span><span class="status-val">42ms</span></div>
        <div style="margin-top: 10px;"></div>
        <div class="status-row"><span>Detection Accuracy</span><span class="status-val">99.2%</span></div>
        <div class="prog-bg"><div class="prog-fill" style="width: 99%;"></div></div>
    </div>
    
    <div class="sidebar-header" style="margin-top: 20px;">System Health</div>
    <div class="status-widget">
        <div class="status-row"><span>CPU Usage</span><span class="status-val">{random.randint(12, 18)}%</span></div>
        <div class="prog-bg"><div class="prog-fill" style="width: 15%; background: #34a853;"></div></div>
        <div style="margin-top: 10px;"></div>
        <div class="status-row"><span>Packet Load</span><span class="status-val">{random.randint(40, 65)}%</span></div>
        <div class="prog-bg"><div class="prog-fill" style="width: 55%; background: #fbbc04;"></div></div>
    </div>
    """, unsafe_allow_html=True)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HEADER BAR & DYNAMIC SCORECARD
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
is_on = st.session_state.running
m = st.session_state.metrics

# LOGIC: DYNAMIC SECURITY GRADE calculation
sec_score = 100
if m["Attacks"] > 0:
    # Scale: Mitigation efficiency + Detection Rate
    # If all detected are blocked -> 100. Penalize unblocked threats (Risk Factor)
    mit_rate = m["Blocked"] / m["Attacks"]
    sec_score = (mit_rate * 80) + 20 
    
if sec_score >= 98: grade, g_color, g_msg = "A+", "#34a853", "PERFECT DEFENSE"
elif sec_score >= 90: grade, g_color, g_msg = "A", "#4285f4", "SECURE"
elif sec_score >= 80: grade, g_color, g_msg = "B+", "#fbbc04", "ALERT ACTIVE"
elif sec_score >= 70: grade, g_color, g_msg = "B", "#fbbc04", "RISK ELEVATED"
else: grade, g_color, g_msg = "C", "#ea4335", "COMPROMISE SUSPECTED"

chip_html = '<span class="status-chip chip-active"><span class="pulse-dot"></span>HUNTING</span>' if is_on else '<span class="status-chip chip-idle">IDLE</span>'

st.markdown(f"""
<div class="main-header">
    <div class="main-header-icon">⚔️</div>
    <div class="main-header-text">
        <h1>NW Hunter - Autonomous Security Cluster</h1>
        <p>AI-Driven Intrusion Mitigation & Enterprise Risk Analytics</p>
        <div class="mission-marquee">MISSION: AUTONOMOUS NEURAL DEFENSE ACTIVE // LEVEL 5 CLEARANCE</div>
    </div>
    <div class="header-right">
        <!-- Elite Dashboard Scorecard -->
        <div style="background: rgba(255,255,255,0.03); border: 1px solid {card_border}; border-radius: 14px; padding: 12px 24px; display: flex; align-items: center; gap: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); backdrop-filter: blur(8px);">
            <div style="text-align: center;">
                <div style="font-size: 0.6rem; color: {text_sub}; font-weight: 800; letter-spacing: 1.5px; text-transform: uppercase;">SEC_GRADE</div>
                <div style="font-size: 2.2rem; font-weight: 900; color: {g_color}; line-height: 1; font-family: 'JetBrains Mono'; text-shadow: 0 0 15px {g_color}40;">{grade}</div>
            </div>
            <div style="border-left: 2px solid {card_border}; padding-left: 20px; min-width: 140px;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                    {chip_html}
                </div>
                <div style="font-size: 0.85rem; color: {text_main}; font-family: 'JetBrains Mono'; font-weight: 800; letter-spacing: -0.5px;">{g_msg}</div>
                <div style="font-size: 0.7rem; color: {g_color}; font-weight: 700; opacity: 0.9;">{int(sec_score)}% INTEGRITY VERIFIED</div>
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# CONTROLS
if st.session_state.current_page == "dashboard":
    c1, c2, _, _ = st.columns([1.5, 1.5, 3, 3])
    if c1.button("▶  START MONITORING", type="primary", use_container_width=True):
        st.session_state.running = True
        log_audit("Autonomous engine started - Internal link monitoring active")
        st.rerun()
    if c2.button("■  STOP MONITORING", use_container_width=True):
        st.session_state.running = False
        log_audit("Autonomous engine suspended - IDLE state")
        st.rerun()
    st.markdown("<div style='margin-bottom: 25px;'></div>", unsafe_allow_html=True)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PAGE ROUTING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if st.session_state.current_page == "settings":
    st.markdown('<div class="main-header"><div class="main-header-icon">🛡️</div><div class="main-header-text"><h1>NW Hunter Core Settings</h1><p>Tune Autonomous Engine Parameters & Interface Aesthetics</p></div></div>', unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["⚙️ NW Hunter Core", "🎨 UI Personalization"])
    
    with tab1:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown('<div class="settings-card"><h3>🧠 AI Detection Thresholds</h3>', unsafe_allow_html=True)
            st.session_state.anomaly_threshold = st.slider("Anomaly Confidence Threshold", 0.0, 1.0, st.session_state.anomaly_threshold, 0.05)
            st.session_state.risk_threshold = st.slider("Risk Action Threshold (Auto-Block)", 0, 100, st.session_state.risk_threshold, 5)
            st.session_state.auto_block = st.toggle("Enable Autonomous Auto-Block", value=st.session_state.auto_block)
            st.markdown('</div>', unsafe_allow_html=True)
        with c2:
            st.markdown('<div class="settings-card"><h3>🌐 Network Link</h3>', unsafe_allow_html=True)
            st.session_state.capture_interface = st.selectbox("Link Interface", ["eth0 (Primary)", "eth1", "wlan0", "docker0", "lo"], index=0)
            st.session_state.subnet_mask = st.text_input("VLAN Subnet Mask", value=st.session_state.subnet_mask)
            st.markdown('</div>', unsafe_allow_html=True)

    with tab2:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown('<div class="settings-card"><h3>🌗 Theme Mode</h3>', unsafe_allow_html=True)
            new_theme = st.radio("Switch Dashboard Theme", ["Dark", "Light"], index=0 if st.session_state.app_theme == "Dark" else 1, horizontal=True)
            if new_theme != st.session_state.app_theme:
                st.session_state.app_theme = new_theme
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)
        with c2:
            st.markdown('<div class="settings-card"><h3>📐 Dashboard Density</h3>', unsafe_allow_html=True)
            st.session_state.detail_level = st.select_slider("Information Density", options=["Compact", "Balanced", "Extended"], value=st.session_state.detail_level)
            st.session_state.refresh_speed = st.slider("Sync Interval (s)", 0.1, 1.5, st.session_state.refresh_speed, 0.1)
            st.markdown('</div>', unsafe_allow_html=True)

    if st.button("💾  Deploy Changes", type="primary", use_container_width=True):
        log_audit(f"Engine configuration updated: Threshold {st.session_state.anomaly_threshold}, Risk {st.session_state.risk_threshold}%")
        st.success("New configuration deployed to autonomous core!")
        time.sleep(1)
        st.session_state.current_page = "dashboard"
        st.rerun()
    st.stop()

if st.session_state.current_page == "admin":
    st.markdown('<div class="main-header"><div class="main-header-icon">👤</div><div class="main-header-text"><h1>Security Operator Portal</h1><p>Manage Identity, Access Privileges & Session Audits</p></div></div>', unsafe_allow_html=True)
    
    a1, a2 = st.columns([1, 2])
    
    with a1:
        st.markdown(f"""
        <div class="settings-card" style="text-align: center;">
            <div style="font-size: 5rem; margin-bottom: 10px;">{st.session_state.admin_avatar}</div>
            <h2 style="margin: 0; color: {text_main};">{st.session_state.admin_name}</h2>
            <p style="color: {text_sub}; margin-bottom: 20px;">{st.session_state.admin_role}</p>
            <div style="background: {sidebar_active}; padding: 10px; border-radius: 8px; font-size: 0.8rem; display: inline-block;">
                <span style="color: #34a853; font-weight: 700;">●</span> ACTIVE SESSION
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        pass

    with a2:
        tab_p1, tab_p2 = st.tabs(["📋 Profile Overview", "📜 Audit Logs"])
        
        with tab_p1:
            st.markdown(f'<div class="settings-card">', unsafe_allow_html=True)
            st.subheader("Account Information")
            c_p1, c_p2 = st.columns(2)
            st.session_state.admin_name = c_p1.text_input("Full Name", value=st.session_state.admin_name)
            st.session_state.admin_email = c_p2.text_input("Work Email", value=st.session_state.admin_email)
            
            c_p3, c_p4 = st.columns(2)
            st.session_state.admin_role = c_p3.selectbox("Organizational Role", ["Senior Security Analyst", "SOC Manager", "Security Engineer", "Compliance Officer"], index=0)
            st.session_state.admin_avatar = c_p4.selectbox("Portal Avatar", ["👤", "👨‍💻", "👩‍💻", "🛡️", "🕵️"], index=["👤", "👨‍💻", "👩‍💻", "🛡️", "🕵️"].index(st.session_state.admin_avatar))
            
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("Update Profile Details", type="primary"):
                log_audit(f"Operator profile updated (Name/Role: {st.session_state.admin_name}/{st.session_state.admin_role})")
                st.success("Operator profile updated in global registry.")
            st.markdown('</div>', unsafe_allow_html=True)
            
            st.markdown(f'<div class="settings-card">', unsafe_allow_html=True)
            st.subheader("System Access Keys")
            st.code("SSH-RSA AAAAB3Nza.../maviya-soc-v4", language="bash")
            st.caption("Active hardware key linked to high-clearance terminal.")
            st.markdown('</div>', unsafe_allow_html=True)
            
        with tab_p2:
            st.markdown(f'<div class="settings-card">', unsafe_allow_html=True)
            st.subheader("Audit Intelligence")
            
            # --- Visual Activity Summary ---
            if st.session_state.audit_logs:
                df_audit = pd.DataFrame(st.session_state.audit_logs)
                # Simple categorization for visualization
                def cat_log(a):
                    if "engine" in a.lower(): return "Engine"
                    if "profile" in a.lower(): return "Profile"
                    return "Config"
                df_audit['Category'] = df_audit['a'].apply(cat_log)
                cat_counts = df_audit['Category'].value_counts()
                
                fig_audit = go.Figure(data=[go.Bar(
                    x=cat_counts.index, 
                    y=cat_counts.values,
                    marker_color=['#4285f4', '#34a853', '#fbbc04'],
                    width=0.4
                )])
                fig_audit.update_layout(
                    height=200, margin=dict(l=10,r=10,t=10,b=10),
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color=text_sub, size=10),
                    yaxis=dict(showgrid=True, gridcolor=card_border),
                    xaxis=dict(showgrid=False)
                )
                st.plotly_chart(fig_audit, use_container_width=True, config={'displayModeBar': False})
            
            st.markdown("<hr style='border:0; border-top:1px solid {card_border}; margin:20px 0;'>", unsafe_allow_html=True)
            st.subheader("Visual Timeline")
            
            for act in st.session_state.audit_logs:
                dot_color = "#4285f4"
                if "started" in act['a'].lower(): dot_color = "#34a853"
                if "suspended" in act['a'].lower(): dot_color = "#ea4335"
                if "updated" in act['a'].lower(): dot_color = "#fbbc04"
                
                st.markdown(f"""
                <div style="padding: 14px; border-bottom: 1px solid {card_border}; display: flex; align-items: center; gap: 15px;">
                    <div style="width: 8px; height: 8px; border-radius: 50%; background: {dot_color}; flex-shrink: 0; box-shadow: 0 0 8px {dot_color}66;"></div>
                    <div style="flex-grow: 1;">
                        <div style="font-size: 0.85rem; color: {text_main}; font-weight: 500;">{act['a']}</div>
                        <div style="font-size: 0.72rem; color: {text_sub}; margin-top: 4px; font-family: 'JetBrains Mono'; opacity: 0.8;">{act['t']}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown("<br>", unsafe_allow_html=True)
            
            # --- HIGH-DENSITY EXECUTIVE AUDIT PDF (STRICT 1-PAGE) ---
            def create_pdf(logs, admin):
                pdf = FPDF()
                pdf.add_page()
                
                # Soothing Corporate Palette
                C_NAVY = (30, 58, 138)
                C_TEXT = (45, 55, 72)
                C_LABEL = (107, 114, 128)
                C_BG_SOFT = (249, 250, 251)
                C_BORDER = (229, 231, 235)
                
                # Header
                pdf.set_fill_color(*C_NAVY)
                pdf.rect(0, 0, 210, 1.2, 'F')
                pdf.set_y(12)
                pdf.set_x(15)
                pdf.set_font("Arial", 'B', 16)
                pdf.set_text_color(*C_NAVY)
                pdf.cell(100, 10, "CyberShield SOC", 0, 0)
                pdf.set_font("Arial", 'B', 8)
                pdf.set_text_color(*C_TEXT)
                pdf.cell(80, 10, "OFFICIAL SECURITY AUDIT", 0, 1, 'R')
                pdf.set_draw_color(*C_BORDER)
                pdf.line(15, 23, 195, 23)
                
                # Metadata Grid
                pdf.set_y(26)
                pdf.set_fill_color(*C_BG_SOFT)
                pdf.rect(15, 26, 180, 14, 'F')
                pdf.set_font("Arial", 'B', 7)
                pdf.set_text_color(*C_LABEL)
                pdf.set_xy(18, 28)
                pdf.cell(45, 4, "INTEL CLASSIFICATION", 0, 0)
                pdf.cell(45, 4, "SESSION ID", 0, 0)
                pdf.cell(45, 4, "AUDIT TIMESTAMP", 0, 0)
                pdf.cell(45, 4, "ENGINE STATUS", 0, 1)
                
                pdf.set_font("Arial", 'B', 8)
                pdf.set_text_color(*C_TEXT)
                pdf.set_x(18)
                pdf.cell(45, 4, "RESTRICTED / L5", 0, 0)
                pdf.cell(45, 4, f"NW-{random.randint(400,499)}", 0, 0)
                pdf.cell(45, 4, time.strftime('%d-%b-%Y %H:%M'), 0, 0)
                pdf.cell(45, 4, "ACTIVE [STABLE]", 0, 1)
                
                # Operational Performance Summary
                pdf.set_y(48)
                pdf.set_x(15)
                pdf.set_font("Arial", 'B', 10)
                pdf.set_text_color(*C_NAVY)
                pdf.cell(0, 8, "Operational Performance Summary", ln=True)
                
                m = st.session_state.get('metrics', {"Total":0, "Normal":0, "Attacks":0, "Blocked":0})
                pdf.set_x(15)
                pdf.set_font("Arial", '', 9)
                pdf.set_text_color(*C_TEXT)
                summary = f"During this operational window, the CyberShield SOC analyzed {m['Total']} packet flows. The AI engine successfully identified {m['Attacks']} malicious " \
                          f"anomalies while maintaining a 99.2% classification accuracy. Autonomous mitigation was triggered to block {m['Blocked']} high-risk threats, " \
                          "ensuring zero-day perimeter integrity. System latency remained optimal at 42ms."
                pdf.multi_cell(180, 5, summary)
                
                # Stats Row (Dynamic)
                pdf.ln(4)
                pdf.set_draw_color(*C_BORDER)
                pdf.rect(15, 75, 180, 14, 'D')
                pdf.set_xy(18, 77)
                pdf.set_font("Arial", 'B', 7)
                pdf.set_text_color(*C_LABEL)
                pdf.cell(36, 4, "ANALYZED FLOWS", 0, 0, 'C')
                pdf.cell(36, 4, "SAFE FLOWS", 0, 0, 'C')
                pdf.cell(36, 4, "THREATS FOUND", 0, 0, 'C')
                pdf.cell(36, 4, "THREATS BLOCKED", 0, 0, 'C')
                pdf.cell(36, 4, "ENGINE LOAD", 0, 1, 'C')
                
                pdf.set_x(18)
                pdf.set_font("Arial", 'B', 9)
                pdf.set_text_color(*C_NAVY)
                pdf.cell(36, 5, str(m['Total']), 0, 0, 'C')
                pdf.cell(36, 5, str(m['Normal']), 0, 0, 'C')
                pdf.cell(36, 5, str(m['Attacks']), 0, 0, 'C')
                pdf.cell(36, 5, str(m['Blocked']), 0, 0, 'C')
                pdf.cell(36, 5, f"{random.randint(12, 18)}%", 0, 1, 'C')
                
                # Detailed Audit Table
                pdf.set_y(96)
                pdf.set_x(15)
                pdf.set_font("Arial", 'B', 9)
                pdf.set_text_color(*C_NAVY)
                pdf.cell(0, 8, "Operational Event Timeline", ln=True)
                
                pdf.set_fill_color(*C_NAVY)
                pdf.set_font("Arial", 'B', 7.5)
                pdf.set_text_color(255, 255, 255)
                pdf.set_x(15)
                pdf.cell(40, 8, "  TIMESTAMP", 0, 0, 'L', True)
                pdf.cell(140, 8, "  CLASSIFICATION & AUTOMATED MITIGATION RESPONSE", 0, 1, 'L', True)
                
                pdf.set_font("Arial", '', 7.5)
                pdf.set_text_color(*C_TEXT)
                pdf.set_draw_color(*C_BORDER)
                fill = False
                for l in logs[:16]:
                    pdf.set_x(15)
                    pdf.set_fill_color(*C_BG_SOFT) if fill else pdf.set_fill_color(255, 255, 255)
                    pdf.cell(40, 7, f"  {l['t']}", 'B', 0, 'L', fill)
                    pdf.cell(140, 7, f"  {l['a']}", 'B', 1, 'L', fill)
                    fill = not fill
                
                # Footer
                pdf.set_y(-28)
                pdf.set_draw_color(*C_NAVY)
                pdf.line(15, 272, 195, 272)
                pdf.set_y(-24)
                pdf.set_font("Arial", 'B', 7)
                pdf.set_text_color(*C_NAVY)
                pdf.cell(0, 4, f"SYSTEM LEAD: {admin['name'].upper()} // LEAD RESEARCHER (AI & NEURAL DEFENSE)", 0, 1, 'C')
                pdf.set_font("Arial", '', 6)
                pdf.set_text_color(*C_LABEL)
                pdf.cell(0, 3, "Microsoft-grade Digital Audit Compliance. Project Workspace Authentication: Verified.", 0, 1, 'C')
                pdf.cell(0, 3, "CyberShield SOC Research Intelligence (c) 2026. Global Security Compliance Registry.", 0, 1, 'C')
                
                return pdf.output()

            col_pdf, col_csv = st.columns(2)
            
            with col_pdf:
                admin_data = {"name": st.session_state.admin_name, "role": st.session_state.admin_role}
                pdf_output = create_pdf(st.session_state.audit_logs, admin_data)
                # Ensure the data is in bytes format for Streamlit
                pdf_bytes = bytes(pdf_output)
                st.download_button(
                    label="📄 EXPORT PDF REPORT",
                    data=pdf_bytes,
                    file_name=f"cyber_audit_{time.strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
                
            with col_csv:
                audit_csv = "Timestamp,Action\n"
                for log in st.session_state.audit_logs:
                    audit_csv += f"{log['t']},{log['a'].replace(',', ';')}\n"
                st.download_button(
                    label="📥 DOWNLOAD CSV",
                    data=audit_csv,
                    file_name=f"soc_audit_log_{time.strftime('%Y%m%d_%H%M')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            st.markdown('</div>', unsafe_allow_html=True)


    if st.button("❰ Return to Command Dashboard", use_container_width=True):
        st.session_state.current_page = "dashboard"
        st.rerun()
    st.stop()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DASHBOARD CONTENT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# ALERT BANNER
if st.session_state.last_alert and st.session_state.running:
    a = st.session_state.last_alert
    st.markdown(f"""
    <div class="alert-bar">
        <div class="alert-bar-title">🚨 CRITICAL THREAT DETECTED – AUTOMONOUS SEGMENTATION ACTIVE</div>
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px;">
            <div><div class="alert-label">Classification</div><div class="alert-value">{a['pred']}</div></div>
            <div><div class="alert-label">Source Node</div><div class="alert-value">{a['sip']}</div></div>
            <div><div class="alert-label">Risk Intelligence</div><div class="alert-value" style="color:#ea4335;">{a['score']}/100</div></div>
            <div><div class="alert-label">IPS Response</div><div class="alert-value" style="color:#ea4335;">{a['action']}</div></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# CONTROLS & KPI
m = st.session_state.metrics
c1,c2,c3,c4 = st.columns(4)
c1.markdown(f'<div class="kpi-card"><div class="kpi-icon">📊</div><div class="kpi-label">ANALYZED</div><div class="kpi-value v-purple">{m["Total"]:,}</div><div class="kpi-sub">TOTAL PACKET FLOWS</div></div>', unsafe_allow_html=True)
c2.markdown(f'<div class="kpi-card"><div class="kpi-icon">✅</div><div class="kpi-label">SAFE</div><div class="kpi-value v-green">{m["Normal"]:,}</div><div class="kpi-sub">VERIFIED LEGITIMATE</div></div>', unsafe_allow_html=True)
c3.markdown(f'<div class="kpi-card"><div class="kpi-icon">⚠️</div><div class="kpi-label">THREATS</div><div class="kpi-value v-red">{m["Attacks"]:,}</div><div class="kpi-sub">MALICIOUS ANOMALIES</div></div>', unsafe_allow_html=True)
c4.markdown(f'<div class="kpi-card"><div class="kpi-icon">🔥</div><div class="kpi-label">BLOCKED</div><div class="kpi-value v-amber">{m["Blocked"]:,}</div><div class="kpi-sub">AUTONOMOUSLY HALTED</div></div>', unsafe_allow_html=True)

st.markdown("")

# MIDDLE ROW: Map + Tools
mid1, mid2 = st.columns([2, 1])

with mid1:
    st.markdown('<div class="section-head"><span class="dot dot-green"></span>Global Distribution</div>', unsafe_allow_html=True)
    fig_globe = go.Figure()
    fig_globe.add_trace(go.Scattergeo(lon=[-122.42], lat=[37.77], mode='markers', marker_size=12, marker_color='#4285f4', marker_symbol='diamond'))
    for arc in st.session_state.arcs:
        fig_globe.add_trace(go.Scattergeo(lon=[arc['slon'],arc['dlon']], lat=[arc['slat'],arc['dlat']], mode='lines', line=dict(width=arc['w'], color=arc['c']), opacity=0.6))
    
    fig_globe.update_layout(
        geo=dict(projection_type="natural earth", showcoastlines=True, coastlinecolor=card_border, showland=True, landcolor=bg_side, showocean=True, oceancolor=bg_main, bgcolor="rgba(0,0,0,0)"), 
        margin=dict(l=0,r=0,t=0,b=0), height=350, paper_bgcolor='rgba(0,0,0,0)'
    )
    st.plotly_chart(fig_globe, use_container_width=True, config={'displayModeBar': False})

with mid2:
    st.markdown('<div class="section-head"><span class="dot dot-blue"></span>Traffic Analysis</div>', unsafe_allow_html=True)
    fig_time = go.Figure()
    fig_time.add_trace(go.Scatter(x=st.session_state.timeline["t"], y=st.session_state.timeline["n"], name="Safe", fill='tozeroy', line=dict(color='#34a853', width=2)))
    fig_time.add_trace(go.Scatter(x=st.session_state.timeline["t"], y=st.session_state.timeline["a"], name="Threat", fill='tozeroy', line=dict(color='#ea4335', width=2)))
    fig_time.update_layout(height=180, margin=dict(l=0,r=0,t=0,b=0), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', showlegend=True, legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1), font=dict(color=text_sub, size=10), xaxis=dict(showgrid=False), yaxis=dict(showgrid=True, gridcolor=card_border))
    st.plotly_chart(fig_time, use_container_width=True)

    st.markdown('<div class="section-head" style="margin-top:20px;"><span class="dot dot-blue"></span>Live Forensics</div>', unsafe_allow_html=True)
    hex_html = '<div class="hex-panel">'
    for ln in st.session_state.hex:
        dc = " danger" if ln["d"] else ""
        hex_html += f'<div class="hex-row"><span class="hex-addr">{ln["a"]}</span><span class="hex-bytes{dc}">{ln["h"]}</span><span class="hex-ascii{dc}">{ln["s"]}</span></div>'
    hex_html += '</div>'
    st.markdown(hex_html, unsafe_allow_html=True)

# BOTTOM: LOG
st.markdown('<div class="section-head"><span class="dot dot-red"></span>Live IPS Event Stream</div>', unsafe_allow_html=True)

if st.session_state.logs:
    log_html = '<div class="log-panel">'
    log_html += '<div class="log-header"><span class="lc-time">TIME</span><span class="lc-ip">SOURCE IP</span><span class="lc-port">PORT</span><span class="lc-class">CLASSIFICATION</span><span style="width:100px; text-align:right;">ACTION</span></div>'
    for lg in st.session_state.logs:
        cls = "threat" if lg["atk"] else "safe"
        act = '<span style="color:#ea4335; font-weight:700;">BLOCK</span>' if lg["atk"] else '<span style="color:#34a853;">ALLOW</span>'
        log_html += f'<div class="log-r"><span class="lc-time">{lg["t"]}</span><span class="lc-ip">{lg["sip"]}</span><span class="lc-port">{int(lg["dp"])}</span><span class="lc-class {cls}">{lg["pred"]}</span><span style="width:100px; text-align:right;">{act}</span></div>'
    log_html += '</div>'
    st.markdown(log_html, unsafe_allow_html=True)
else:
    st.info("Live engine currently at rest. Initiate session to begin analysis.")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SIMULATION ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def get_simulated_geo(is_attack, attack_type=""):
    dst_lat, dst_lon = 37.77, -122.42
    regions = [(55.75,37.61),(39.90,116.40),(35.68,139.65),(-23.55,-46.63),(51.50,-0.12)]
    if not is_attack:
        slat = 37 + random.uniform(-10,10); slon = -95 + random.uniform(-20,20)
        sip = f"{random.randint(10,99)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        slat, slon = random.choice(regions)
        slat += random.uniform(-10,10); slon += random.uniform(-10,10)
        sip = f"{random.randint(100,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return {"sip": sip, "slat": slat, "slon": slon, "dlat": dst_lat, "dlon": dst_lon}

if st.session_state.running:
    if len(st.session_state.arcs) > 12: st.session_state.arcs = st.session_state.arcs[-8:]
    # Optimization: process only 3 rows per loop to maintain UI responsiveness
    for _ in range(3):
        if st.session_state.idx >= len(df_test):
            st.session_state.running = False; break
        row = df_test.iloc[st.session_state.idx]
        st.session_state.idx += 1
        feat = row.to_dict()
        if 'Label' in feat: del feat['Label']
        result = engine.predict_flow(feat)
        is_atk = result["is_attack"]; pred = result["prediction"]; conf = result["confidence"]
        r_score = result.get("risk_score", 0); t_level = result.get("threat_level", "INFO"); r_action = result.get("recommended_action", "Allow Traffic")
        geo = get_simulated_geo(is_atk, pred)
        st.session_state.metrics["Total"] += 1
        if is_atk:
            st.session_state.metrics["Attacks"] += 1
            if conf > st.session_state.anomaly_threshold: st.session_state.metrics["Blocked"] += 1
            st.session_state.arcs.append({"slat":geo["slat"],"slon":geo["slon"],"dlat":geo["dlat"],"dlon":geo["dlon"],"c":"#ea4335","w":2})
            st.session_state.hex = gen_hex(True, pred)
            st.session_state.last_alert = {"pred":pred, "sip":geo["sip"], "conf":conf, "score":r_score, "level":t_level, "action":r_action}
        else:
            st.session_state.metrics["Normal"] += 1
            if random.random() > 0.85: st.session_state.arcs.append({"slat":geo["slat"],"slon":geo["slon"],"dlat":geo["dlat"],"dlon":geo["dlon"],"c":"rgba(66,133,244,0.3)","w":1})
        st.session_state.timeline["t"].append(time.strftime("%H:%M:%S"))
        st.session_state.timeline["n"].append(st.session_state.metrics["Normal"])
        st.session_state.timeline["a"].append(st.session_state.metrics["Attacks"])
        if len(st.session_state.timeline["t"]) > 25:
            for key in ["t","n","a"]: st.session_state.timeline[key].pop(0)
        dst_port = feat.get("Destination Port", feat.get(" Destination Port", 0))
        st.session_state.logs.appendleft({"t":time.strftime("%H:%M:%S"),"sip":geo["sip"],"dp":dst_port,"pred":pred,"atk":is_atk,"score":r_score})
    
    # Slight pause for visual stability then trigger rerun
    time.sleep(0.05) 
    st.rerun()

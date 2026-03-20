"""
app.py - The Senterator UI
===========================
Main Streamlit application that brings everything together.
This is what your team will demo in the presentation.
"""

import streamlit as st
import plotly.graph_objects as go
import json
from integrator import run_local_analysis, run_threat_intel, run_verdict

# =============================================================
#PAGE CONFIG - Must be the first Streamlit command
#==============================================================
st.set_page_config(
	page_title="Senterator - IoC Generator",
	page_icon="🛡️",
	layout="wide",
)


# ============================================================
# MATRIX RAIN — Falling green characters (canvas animation)
# ============================================================
# We use st.components.v1.html() instead of st.markdown() because
# Streamlit blocks <script> tags in markdown for security.
# components.html() renders in its own iframe where JS is allowed.
import streamlit.components.v1 as components

components.html("""
<canvas id="matrixCanvas"></canvas>
<style>
    body { margin: 0; overflow: hidden; background: transparent; }
    #matrixCanvas {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
    }
</style>
<script>
    const canvas = document.getElementById('matrixCanvas');
    const ctx = canvas.getContext('2d');

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });

    const chars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const fontSize = 14;
    const columns = Math.floor(canvas.width / fontSize);
    const drops = Array(columns).fill(0).map(() => Math.random() * -100);

    function drawMatrix() {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.fillStyle = '#00ff41';
        ctx.font = fontSize + 'px monospace';

        for (let i = 0; i < drops.length; i++) {
            const char = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(char, i * fontSize, drops[i] * fontSize);

            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }

    setInterval(drawMatrix, 50);
</script>
""", height=300)


#============================================================
#CUSTOM CSS - MATRIX-style dark theme with neon green accents
#============================================================
st.markdown("""
<style>
    /* Main background */
    .stApp {
	background-color: #0a0a0a;
	color: #00ff41;
    }
    
    /* Header styling */
    h1, h2, h3 {
	color: #00ff41 !important;
	font-family: 'Courier New' , monospace !important;
    }

    /* Metric Cards */
    [data-testid="stMetric"] {
	background-color: #1a1a2e;
	border: 1px solid #00ff41;
	border-radius: 8px;
	padding: 15px;
    }

    [data-testid="stMetricValue"] {
	color: #00ff41 !important;
    }

    /* Tab syling */
    .stTabs [data-baseweb="tab-list"] {
	gap: 8px;
    }

    .stTabs [data-baseweb="tab"] {
	background-color: #1a1a2e;
	border: 1px solid #00ff41;
	border-radius: 4px;
	color: #00ff41;
	padding: 10px 20px;
    }

    .stTabs [aria-selected="true"] {
	background-color: #00ff41 !important;
	color: #0a0a0a !important;
    }
    
    /* Expander styling */
    .streamlit-expanderHeader {
	background-color: #1a1a2e;
	color: #00ff41 !important;
    }
    /* Table styling */
    .stDataFrame {
	border: 1px solid #00ff41;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
	background-color: #0d0d1a;
	border-right: 1px solid #00ff41;
    }

    /* Make the Matrix rain iframe cover the full background */
    /* Try multiple selectors for different Streamlit versions */
    [data-testid="stCustomComponentV1"],
    [data-testid="stHtml"],
    [data-testid="element-container"]:has(iframe) {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        z-index: 0 !important;
        pointer-events: none !important;
        opacity: 0.15 !important;
    }
    [data-testid="stCustomComponentV1"] iframe,
    [data-testid="stHtml"] iframe {
        width: 100vw !important;
        height: 100vh !important;
    }

    /* Also target by the iframe wrapper class directly */
    .element-container:has(iframe) {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        z-index: 0 !important;
        pointer-events: none !important;
        opacity: 0.15 !important;
    }
    .element-container:has(iframe) iframe {
        width: 100vw !important;
        height: 100vh !important;
    }

    /* Make sure all real content sits on top of the rain */
    .stMainBlockContainer,
    [data-testid="stMainBlockContainer"],
    .main .block-container {
        position: relative !important;
        z-index: 1 !important;
    }
</style>
""", unsafe_allow_html=True)
#=====================================================
#SIDEBAR - File upload and controls
#======================================================
with st.sidebar:
	st.markdown("## 🛡️ SENTERATOR")
	st.markdown("### 🤖 IoC Generator & Threat Analyzer")
	st.markdown("---")

	# File uploader for binary files
	uploaded_file = st.file_uploader(
		"Upload ELF Binary",
		type=None,  # Accept any file type
		help="Drop an ELF binary here for analysis"
	)

	# OR use sample/mock data button
	use_sample = st.button(
		"⚡ Use Sample Data",
		use_container_width=True,
	)

	st.markdown("---")
	st.markdown(
		"<small style='color: #00ff41;'>v1.0 — Team Senterator</small>",
		unsafe_allow_html=True
	)

#==========================================================
# MAIN HEADER
#==========================================================
st.markdown("# 🛡️ SENTERATOR")
st.markdown("### 🤖 IoC Generator & Threat Intelligence Platform")
st.markdown("---")
#==========================================================
# LOAD DATA - Only when user clicks "Use Sample Data" or uploads
#==========================================================
#st.session_state is like a "memory" for Streamlit
# without it, data disappears every time the page refreshes.
# We store our results here so they stick around.

if use_sample:
        st.session_state["analysis"] = run_local_analysis()
        st.session_state["threat"] = run_threat_intel()
        st.session_state["verdict"] = run_verdict()

# Check if we have data to display
if "analysis" in st.session_state:
    # Grab the date from memory
    analysis = st.session_state["analysis"]
    threat = st.session_state["threat"]
    verdict = st.session_state["verdict"]

    #==========================================================
    # THE 4 TABS -- Each one shows a different piece of the puzzle
    #==========================================================
    tab1, tab2, tab3, tab4 = st.tabs([
            "🔍 Local Analysis",
            "🌐 Threat Intel",
            "⚖️ Verdict",
            "📄 Full Report"
    ]) 	
    # ==========================================================
    # TAB 1: LOCAL ANALYSIS — Hashes & Suspicious Imports
    # ==========================================================
    with tab1:
        st.markdown("## 🔍 Local Binary Analysis")

        # --- Hash Table ---
        st.markdown("### 🔑 File Hashes")
        hashes = analysis["hashes"]
        for algo, value in hashes.items():
            st.code(f"{algo}: {value}", language="text")

        # --- Suspicious Imports ---
        st.markdown("### ⚠️ Suspicious Imports")
        imports = analysis["suspicious_imports"]

        # Show the summary metrics in columns
        col1, col2 = st.columns(2)
        col1.metric("Total Hits", imports["total_hits"])
        col2.metric("Categories Flagged", imports["categories_flagged"])

        # Show each category in an expandable section
        for category, matches in imports["matches"].items():
            with st.expander(f"🔸 {category} ({len(matches)} matches)"):
                for match in matches:
                    st.markdown(f"- `{match}`")
        # ==========================================================
    # TAB 2: THREAT INTELLIGENCE — VirusTotal / MalwareBazaar
    # ==========================================================
    with tab2:
        st.markdown("## 🌐 Threat Intelligence Report")

        # --- Detection Score & Malware Family ---
        col1, col2, col3 = st.columns(3)
        col1.metric("Detection Score", threat["detection_score"])
        col2.metric("Malware Family", threat["malware_family"])
        col3.metric("Source", threat["source"])

        # --- Tags ---
        st.markdown("### 🏷️ Tags")
        tag_text = " • ".join(
            [f"`{tag}`" for tag in threat["tags"]]
        )
        st.markdown(tag_text)

        # --- First Seen ---
        st.markdown(f"**First Seen:** {threat['first_seen']}")

        # --- Detection Engines Table ---
        st.markdown("### 🛡️ Detection Engines")
        st.markdown("Which antivirus engines flagged this file:")
        import pandas as pd
        engines_df = pd.DataFrame(threat["detection_engines"])
        st.dataframe(
            engines_df,
            use_container_width=True,
            hide_index=True,
        )

    # ==========================================================
    # TAB 3: VERDICT — Threat Score Gauge & Risk Factors
    # ==========================================================
    with tab3:
        st.markdown("## ⚖️ Final Verdict")

        # --- Color based on verdict ---
        if verdict["verdict"] == "Malicious":
            verdict_color = "#ff0040"
            verdict_emoji = "🔴"
        elif verdict["verdict"] == "Suspicious":
            verdict_color = "#ffaa00"
            verdict_emoji = "🟡"
        else:
            verdict_color = "#00ff41"
            verdict_emoji = "🟢"

        # --- Big verdict display ---
        st.markdown(
            f"<h2 style='color: {verdict_color}; text-align: center;'>"
            f"{verdict_emoji} {verdict['verdict'].upper()} "
            f"— {verdict['confidence']}% Confidence</h2>",
            unsafe_allow_html=True
        )

        # --- Plotly Gauge Chart ---
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=verdict["confidence"],
            title={"text": "Threat Score", "font": {"color": "#00ff41"}},
            number={"suffix": "%", "font": {"color": "#00ff41"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#00ff41"},
                "bar": {"color": verdict_color},
                "bgcolor": "#1a1a2e",
                "steps": [
                    {"range": [0, 33], "color": "#0a2a0a"},
                    {"range": [33, 66], "color": "#2a2a0a"},
                    {"range": [66, 100], "color": "#2a0a0a"},
                ],
            }
        ))
        fig.update_layout(
            paper_bgcolor="#0a0a0a",
            plot_bgcolor="#0a0a0a",
            font={"color": "#00ff41"},
            height=300,
        )
        st.plotly_chart(fig, use_container_width=True)

        # --- Risk Factors Breakdown ---
        st.markdown("### 📊 Risk Factor Breakdown")
        for rf in verdict["risk_factors"]:
            with st.expander(
                f"⚡ {rf['factor']} (Weight: {rf['weight']})"
            ):
                st.markdown(f"**Detail:** {rf['detail']}")

        # --- Recommendation ---
        st.markdown("### 📋 Recommendation")
        st.warning(verdict["recommendation"])
    # ==========================================================
    # TAB 4: FULL REPORT — Combined JSON + Download
    # ==========================================================
    with tab4:
        st.markdown("## 📄 Full Analysis Report")

        # Combine all data into one report
        full_report = {
            "tool": "Senterator IoC Generator",
            "local_analysis": analysis,
            "threat_intelligence": threat,
            "verdict": verdict,
        }

        # Display as formatted JSON
        st.markdown("### 📋 Combined Report Data")
        st.json(full_report)

        # Download button
        report_json = json.dumps(full_report, indent=4)
        st.download_button(
            label="⬇️ Download Full Report (JSON)",
            data=report_json,
            file_name="senterator_report.json",
            mime="application/json",
            use_container_width=True,
        )

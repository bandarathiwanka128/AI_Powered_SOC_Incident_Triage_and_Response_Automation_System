"""
AI-Powered SOC Analyst Assistant Dashboard
EC6301 Mini Project
Team: Herath H.M.T.B | Hettiarachchi H.A.K.G | Fernando N.D.H | [Member 4]
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

from modules.preprocessor import load_sample_data, extract_features
from modules.expert_system import ExpertSystem
from modules.severity_engine import SeverityEngine
from modules.playbook_engine import PlaybookEngine
from modules.gemini_integration import GeminiAnalyst
from modules.ml_predictor import MLPredictor
from modules.auth import register_user, login_user, regenerate_api_key, DB_CONNECTED
from config import SEVERITY_LEVELS, MITRE_MAPPING

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SOC Analyst Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .stMetric { background: #1e2130; border-radius: 8px; padding: 10px; }
    .severity-critical { background: #dc354533; border-left: 4px solid #dc3545; padding: 8px 12px; border-radius: 4px; margin: 4px 0; }
    .severity-high { background: #fd7e1433; border-left: 4px solid #fd7e14; padding: 8px 12px; border-radius: 4px; margin: 4px 0; }
    .severity-medium { background: #ffc10733; border-left: 4px solid #ffc107; padding: 8px 12px; border-radius: 4px; margin: 4px 0; }
    .severity-low { background: #28a74533; border-left: 4px solid #28a745; padding: 8px 12px; border-radius: 4px; margin: 4px 0; }
    .playbook-box { background: #1e2130; border-radius: 8px; padding: 16px; margin-top: 12px; }
    .mitre-badge { background: #3d1a78; color: #c792ea; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
    .api-key-box { background: #1e2130; border: 1px solid #3d4663; border-radius: 8px; padding: 16px; font-family: monospace; font-size: 1.1em; color: #c792ea; word-break: break-all; }
    .doc-box { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin: 8px 0; }
</style>
""", unsafe_allow_html=True)

# ── Session State ─────────────────────────────────────────────────────────────
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.nav = "Dashboard"

# ═══════════════════════════════════════════════════════════════════════════════
# AUTH PAGES
# ═══════════════════════════════════════════════════════════════════════════════
def show_auth():
    if "auth_mode" not in st.session_state:
        st.session_state.auth_mode = "Login"

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("## 🛡️ SOC Analyst Assistant")
        st.markdown("AI-Powered Threat Detection Platform")
        st.markdown("---")

        c1, c2 = st.columns(2)
        if c1.button("Login",    use_container_width=True,
                     type="primary" if st.session_state.auth_mode == "Login" else "secondary"):
            st.session_state.auth_mode = "Login"
            st.rerun()
        if c2.button("Register", use_container_width=True,
                     type="primary" if st.session_state.auth_mode == "Register" else "secondary"):
            st.session_state.auth_mode = "Register"
            st.rerun()

        st.markdown("---")

        if st.session_state.auth_mode == "Login":
            st.subheader("Sign In")
            with st.form("login_form"):
                email    = st.text_input("Email")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Sign In", use_container_width=True)

            if submitted:
                if not email or not password:
                    st.error("Please fill all fields")
                else:
                    ok, msg, user = login_user(email, password)
                    if ok:
                        st.session_state.logged_in = True
                        st.session_state.user = user
                        st.rerun()
                    else:
                        st.error(msg)

        else:
            st.subheader("Create Account")
            with st.form("register_form"):
                username   = st.text_input("Username")
                email_r    = st.text_input("Email")
                password_r = st.text_input("Password",         type="password")
                confirm    = st.text_input("Confirm Password", type="password")
                submitted  = st.form_submit_button("Create Account", use_container_width=True)

            if submitted:
                if not username or not email_r or not password_r or not confirm:
                    st.error("Please fill all fields")
                elif password_r != confirm:
                    st.error("Passwords do not match")
                elif len(password_r) < 6:
                    st.error("Password must be at least 6 characters")
                else:
                    ok, result = register_user(username, email_r, password_r)
                    if ok:
                        st.success("Account created! Please login.")
                        st.info(f"Your API Key: `{result}`")
                    else:
                        st.error(result)

        if not DB_CONNECTED:
            st.warning("Database offline — auth unavailable")


if not st.session_state.logged_in:
    show_auth()
    st.stop()

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGED IN — SIDEBAR NAVIGATION
# ═══════════════════════════════════════════════════════════════════════════════
user = st.session_state.user

with st.sidebar:
    st.markdown(f"**👤 {user['username']}**")
    st.caption(user["email"])
    st.markdown("---")

    st.session_state.nav = st.radio(
        "Navigate",
        ["Dashboard", "API Keys", "Documentation"],
        label_visibility="collapsed",
    )

    st.markdown("---")

    if st.button("Logout", use_container_width=True):
        st.session_state.logged_in = False
        st.session_state.user = None
        st.rerun()

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: API KEYS
# ═══════════════════════════════════════════════════════════════════════════════
if st.session_state.nav == "API Keys":
    st.title("🔑 API Key Management")
    st.markdown("---")

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Your API Key")
        st.markdown(f'<div class="api-key-box">{user["api_key"]}</div>', unsafe_allow_html=True)
        st.caption("Keep this secret. Use it in your application's .env file.")

        st.markdown("---")
        st.markdown(f"**Total API Requests Made:** `{user.get('requests', 0)}`")

    with col2:
        st.subheader("Actions")
        if st.button("Regenerate API Key", type="secondary", use_container_width=True):
            new_key = regenerate_api_key(user["email"])
            st.session_state.user["api_key"] = new_key
            st.success("New API key generated!")
            st.rerun()

    st.markdown("---")
    st.subheader("API Endpoint")
    st.code("http://localhost:8000/api/detect", language="bash")
    st.caption("Start the API server with: uvicorn api_server:app --reload --port 8000")
    st.stop()

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: DOCUMENTATION
# ═══════════════════════════════════════════════════════════════════════════════
if st.session_state.nav == "Documentation":
    st.title("📖 Integration Documentation")
    st.caption("How to use the SOC Analyst API in your application")
    st.markdown("---")

    api_key = user["api_key"]

    # ── Step 1 — Start API Server
    st.subheader("Step 1 — Start the API Server")
    st.code("uvicorn api_server:app --reload --port 8000", language="bash")
    st.caption("Run this in your SOC project terminal. Keep it running.")

    st.markdown("---")

    # ── Step 2 — Setup by OS
    st.subheader("Step 2 — Setup in Your Application")

    tab_win, tab_mac, tab_linux, tab_ssh, tab_curl = st.tabs([
        "Windows", "macOS", "Linux", "SSH", "cURL / API"
    ])

    # WINDOWS
    with tab_win:
        st.markdown("#### Install dependencies")
        st.code("pip install requests python-dotenv", language="bash")

        st.markdown("#### Create `.env` file in your project folder")
        st.code(f"""SOC_API_KEY={api_key}
SOC_ENDPOINT=http://localhost:8000/api/detect""", language="bash")

        st.markdown("#### Create `detect.py` in your project")
        st.code(f"""import os, requests
from dotenv import load_dotenv

load_dotenv()

API_KEY  = os.getenv("SOC_API_KEY")
ENDPOINT = os.getenv("SOC_ENDPOINT")

with open("your_logs.csv", "rb") as f:
    response = requests.post(
        ENDPOINT,
        files={{"file": f}},
        headers={{"X-API-Key": API_KEY}}
    )

result = response.json()
print(f"Total rows:    {{result['total_rows']}}")
print(f"Threats found: {{result['threats_found']}}")
for r in result["results"]:
    if r["attack_type"] != "Benign":
        print(f"[{{r['severity']}}] {{r['attack_type']}} — {{r['src_ip']}} → {{r['dst_ip']}}")
""", language="python")

        st.markdown("#### Run via CMD")
        st.code("python detect.py", language="bash")

    # macOS
    with tab_mac:
        st.markdown("#### Install dependencies")
        st.code("pip3 install requests python-dotenv", language="bash")

        st.markdown("#### Set environment variables (Terminal)")
        st.code(f"""export SOC_API_KEY={api_key}
export SOC_ENDPOINT=http://localhost:8000/api/detect""", language="bash")

        st.markdown("#### Or create `.env` file")
        st.code(f"""SOC_API_KEY={api_key}
SOC_ENDPOINT=http://localhost:8000/api/detect""", language="bash")

        st.markdown("#### Run detection")
        st.code("python3 detect.py", language="bash")

        st.markdown("#### Expected output")
        st.code("""Total rows:    500
Threats found: 23
[CRITICAL] Brute Force — 45.33.32.156 → 192.168.1.10
[HIGH]     Port Scan   — 91.241.19.100 → 192.168.1.100""", language="bash")

    # Linux
    with tab_linux:
        st.markdown("#### Install dependencies")
        st.code("pip3 install requests python-dotenv", language="bash")

        st.markdown("#### Add to `~/.bashrc` or `~/.zshrc` (permanent)")
        st.code(f"""echo 'export SOC_API_KEY={api_key}' >> ~/.bashrc
echo 'export SOC_ENDPOINT=http://localhost:8000/api/detect' >> ~/.bashrc
source ~/.bashrc""", language="bash")

        st.markdown("#### Or use `.env` file (recommended)")
        st.code(f"""SOC_API_KEY={api_key}
SOC_ENDPOINT=http://localhost:8000/api/detect""", language="bash")

        st.markdown("#### Run detection")
        st.code("python3 detect.py", language="bash")

        st.markdown("#### Automate with cron (run every hour)")
        st.code("0 * * * * cd /your/project && python3 detect.py >> /var/log/soc.log 2>&1", language="bash")

    # SSH
    with tab_ssh:
        st.markdown("#### Connect to your server")
        st.code("ssh username@your-server-ip", language="bash")

        st.markdown("#### Set API key on server")
        st.code(f"""export SOC_API_KEY={api_key}
export SOC_ENDPOINT=http://localhost:8000/api/detect""", language="bash")

        st.markdown("#### Send logs directly from server via cURL")
        st.code(f"""curl -X POST http://localhost:8000/api/detect \\
  -H "X-API-Key: {api_key}" \\
  -F "file=@/var/log/network_logs.csv" \\
  | python3 -m json.tool""", language="bash")

        st.markdown("#### Check API health remotely")
        st.code("curl http://localhost:8000/api/health", language="bash")

    # cURL / API
    with tab_curl:
        st.markdown("#### Health check")
        st.code("curl http://localhost:8000/api/health", language="bash")

        st.markdown("#### Detect threats from CSV file")
        st.code(f"""curl -X POST http://localhost:8000/api/detect \\
  -H "X-API-Key: {api_key}" \\
  -F "file=@network_logs.csv" """, language="bash")

        st.markdown("#### Detect single row (JSON)")
        st.code(f"""curl -X POST http://localhost:8000/api/detect/single \\
  -H "X-API-Key: {api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{{"Destination Port": 22, "Total Fwd Packets": 67, "Flow Duration": 5200}}'""", language="bash")

        st.markdown("#### Example JSON response")
        st.code("""{
  "total_rows": 500,
  "threats_found": 23,
  "clean_rows": 477,
  "results": [
    {
      "src_ip": "45.33.32.156",
      "dst_ip": "192.168.1.10",
      "attack_type": "Brute Force",
      "severity": "Critical",
      "score": 95,
      "confidence": 0.9821,
      "mitre_id": "T1110",
      "mitre_name": "Brute Force"
    }
  ]
}""", language="json")

    st.markdown("---")
    st.subheader("API Reference")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**GET** `/api/health`")
        st.caption("Check if API is running")
    with col2:
        st.markdown("**POST** `/api/detect`")
        st.caption("Upload CSV → get all threats")
    with col3:
        st.markdown("**POST** `/api/detect/single`")
        st.caption("Send JSON row → get classification")

    st.stop()

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

# ── Initialize AI modules ─────────────────────────────────────────────────────
@st.cache_resource
def load_modules():
    return ExpertSystem(), SeverityEngine(), PlaybookEngine(), GeminiAnalyst(), MLPredictor()

expert_sys, severity_eng, playbook_eng, gemini, ml_predictor = load_modules()

# ── Dashboard Sidebar ─────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("---")
    st.subheader("Your Analyst Role")
    analyst_role = st.selectbox(
        "Select your level:",
        ["L1", "L2", "L3"],
        format_func=lambda x: {
            "L1": "L1 — Junior Analyst",
            "L2": "L2 — Senior Analyst",
            "L3": "L3 — Threat Hunter / IR",
        }[x],
    )

    st.markdown("---")
    st.subheader("Alert Filter (Noise Control)")
    filter_level = st.select_slider(
        "Show alerts from severity:",
        options=["Low", "Medium", "High", "Critical"],
        value="Medium",
    )
    st.caption(f"Showing: {filter_level} → Critical only")

    st.markdown("---")
    st.subheader("Data Source")
    data_source = st.radio("Load data from:", ["Sample Dataset", "Upload CSV"])

    df_raw = None
    if data_source == "Sample Dataset":
        df_raw = load_sample_data("data/sample_logs.csv")
        st.success(f"Loaded {len(df_raw)} log records")
    else:
        uploaded = st.file_uploader("Upload network log CSV", type=["csv"])
        if uploaded:
            df_raw = pd.read_csv(uploaded)
            st.success(f"Loaded {len(df_raw)} records")

    st.markdown("---")
    st.caption("EC6301 Mini Project | 2026")

# ── Process logs through AI pipeline ─────────────────────────────────────────
@st.cache_data
def process_logs(df_json: str, filter_lvl: str):
    df = pd.read_json(io.StringIO(df_json))
    results = []
    for _, row in df.iterrows():
        features = extract_features(row)
        ml_result = ml_predictor.predict(row)
        if ml_result["attack_type"] and ml_result["confidence"] > 0.7:
            attack = ml_result["attack_type"]
            classification = {
                "attack_type": attack,
                "confidence": ml_result["confidence"],
                "rule_name": "ANN Model (CICIDS2017)",
                "mitre": MITRE_MAPPING.get(attack, MITRE_MAPPING["Benign"]),
            }
        else:
            classification = expert_sys.classify(features)
        severity = severity_eng.score(
            classification["attack_type"], features, classification["confidence"]
        )
        if severity_eng.should_show(severity["level"], filter_lvl):
            results.append({
                "Timestamp": row.get("Timestamp", "N/A"),
                "Source IP": features["src_ip"],
                "Destination IP": features["dst_ip"],
                "Port": features["dst_port"],
                "Attack Type": classification["attack_type"],
                "MITRE ID": classification["mitre"]["id"],
                "Confidence": f"{classification['confidence']:.0%}",
                "Severity": severity["level"],
                "Score": severity["score"],
                "_features": features,
                "_classification": classification,
                "_severity": severity,
            })
    return results

import io

# ── Main Dashboard ────────────────────────────────────────────────────────────
st.title("🛡️ AI-Powered SOC Analyst Assistant")
st.caption(f"Role: **{analyst_role}** | Filter: **{filter_level}+** | {datetime.now().strftime('%Y-%m-%d %H:%M')}")

if df_raw is None:
    st.info("Load a dataset from the sidebar to begin analysis.")
    st.stop()

with st.spinner("Running AI classification pipeline..."):
    incidents = process_logs(df_raw.to_json(), filter_level)

# ── KPI Metrics ───────────────────────────────────────────────────────────────
total           = len(df_raw)
shown           = len(incidents)
noise_filtered  = total - shown
critical_count  = sum(1 for i in incidents if i["Severity"] == "Critical")
high_count      = sum(1 for i in incidents if i["Severity"] == "High")

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Log Events", total)
col2.metric("Alerts After Filter", shown, delta=f"-{noise_filtered} noise removed", delta_color="normal")
col3.metric("Critical", critical_count, delta="Immediate action" if critical_count > 0 else None, delta_color="inverse")
col4.metric("High", high_count)
col5.metric("Noise Filtered", f"{noise_filtered/total*100:.0f}%", help="Percentage of low-priority logs filtered out")

st.markdown("---")

if not incidents:
    st.success("No alerts above the selected severity threshold. Network looks clean!")
    st.stop()

# ── Charts ────────────────────────────────────────────────────────────────────
col_left, col_right = st.columns(2)

with col_left:
    attack_counts = pd.DataFrame(incidents)["Attack Type"].value_counts().reset_index()
    attack_counts.columns = ["Attack Type", "Count"]
    fig = px.bar(
        attack_counts, x="Attack Type", y="Count",
        title="Attack Type Distribution",
        color="Count", color_continuous_scale="Reds",
    )
    fig.update_layout(plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="#ffffff")
    st.plotly_chart(fig, use_container_width=True)

with col_right:
    sev_counts = pd.DataFrame(incidents)["Severity"].value_counts().reindex(
        ["Critical", "High", "Medium", "Low"], fill_value=0
    ).reset_index()
    sev_counts.columns = ["Severity", "Count"]
    colors_map = {"Critical": "#dc3545", "High": "#fd7e14", "Medium": "#ffc107", "Low": "#28a745"}
    fig2 = px.pie(
        sev_counts, names="Severity", values="Count",
        title="Severity Distribution",
        color="Severity",
        color_discrete_map=colors_map,
    )
    fig2.update_layout(plot_bgcolor="#0e1117", paper_bgcolor="#0e1117", font_color="#ffffff")
    st.plotly_chart(fig2, use_container_width=True)

# ── Alert Table ───────────────────────────────────────────────────────────────
st.subheader("Prioritized Alerts")

severity_order   = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
incidents_sorted = sorted(incidents, key=lambda x: severity_order.get(x["Severity"], 9))

display_df = pd.DataFrame([{
    "Severity":       i["Severity"],
    "Attack Type":    i["Attack Type"],
    "Source IP":      i["Source IP"],
    "Destination IP": i["Destination IP"],
    "Port":           i["Port"],
    "MITRE ID":       i["MITRE ID"],
    "Confidence":     i["Confidence"],
    "Score":          i["Score"],
    "Timestamp":      i["Timestamp"],
} for i in incidents_sorted])

st.dataframe(
    display_df,
    use_container_width=True,
    height=300,
    column_config={
        "Score":    st.column_config.ProgressColumn("Score", min_value=0, max_value=100),
        "Severity": st.column_config.TextColumn("Severity"),
    }
)

# ── Incident Detail View ──────────────────────────────────────────────────────
st.markdown("---")
st.subheader("Incident Deep Dive")

incident_labels = [
    f"[{i['Severity']}] {i['Attack Type']} — {i['Source IP']} → {i['Destination IP']}:{i['Port']}"
    for i in incidents_sorted
]

selected_idx = st.selectbox("Select incident to investigate:", range(len(incident_labels)), format_func=lambda x: incident_labels[x])

if selected_idx is not None:
    incident       = incidents_sorted[selected_idx]
    classification = incident["_classification"]
    severity       = incident["_severity"]
    mitre          = classification["mitre"]
    features       = incident["_features"]

    col_a, col_b = st.columns([1, 2])

    with col_a:
        st.markdown(f"### {severity['level']} Severity Alert")
        st.markdown(f"**Attack:** {classification['attack_type']}")
        st.markdown(f"**Source IP:** `{features['src_ip']}`")
        st.markdown(f"**Target:** `{features['dst_ip']}:{features['dst_port']}`")
        st.markdown(f"**Confidence:** {classification['confidence']:.0%}")
        st.progress(severity["score"] / 100)
        st.caption(f"Severity Score: {severity['score']}/100")

        st.markdown("---")
        st.markdown("**MITRE ATT&CK**")
        st.markdown(f"- **ID:** `{mitre['id']}`")
        st.markdown(f"- **Technique:** {mitre['name']}")
        st.markdown(f"- **Tactic:** {mitre['tactic']}")
        st.markdown(f"- **Description:** {mitre['description']}")
        if mitre["url"]:
            st.markdown(f"[View on MITRE ATT&CK]({mitre['url']})")

    with col_b:
        st.markdown("**AI-Generated Incident Summary (Gemini)**")
        incident_data = {
            "attack_type":    classification["attack_type"],
            "severity_level": severity["level"],
            "severity_score": severity["score"],
            "src_ip":         features["src_ip"],
            "dst_ip":         features["dst_ip"],
            "dst_port":       features["dst_port"],
            "mitre_id":       mitre["id"],
            "mitre_name":     mitre["name"],
            "mitre_tactic":   mitre["tactic"],
            "confidence":     classification["confidence"],
        }

        if st.button("Generate AI Summary", key="gen_summary"):
            with st.spinner("Gemini is analyzing the incident..."):
                summary = gemini.generate_summary(incident_data)
            st.markdown(summary)
        else:
            st.info("Click 'Generate AI Summary' to get an AI-powered incident analysis.")

    st.markdown("---")
    st.subheader(f"Role-Based Playbook — {analyst_role} Analyst")
    playbook = playbook_eng.get_playbook(classification["attack_type"], analyst_role)
    st.markdown(f"**{playbook['title']}**")
    st.markdown("**Response Steps:**")
    for i, step in enumerate(playbook["steps"], 1):
        st.markdown(f"{i}. {step}")

    col_p1, col_p2 = st.columns(2)
    with col_p1:
        st.markdown(f"**Escalate if:** {playbook['escalate_if']}")
    with col_p2:
        if playbook["tools"]:
            st.markdown(f"**Tools needed:** {', '.join(playbook['tools'])}")

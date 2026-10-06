import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import json
from datetime import datetime

from main import SIEMPipeline
from simulator.attack_simulator import AttackSimulator

# Page Config
st.set_page_config(
    page_title="SIEM Sentinel - Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Dark SOC Aesthetics)
st.markdown("""
<style>
    /* Force Dark Theme Main Container */
    .stApp, [data-testid="stAppViewContainer"], .main {
        background-color: #0b0f19 !important;
        color: #f8fafc !important;
    }
    
    /* Metric Card Containers */
    [data-testid="stMetric"], .stMetric {
        background-color: #1e293b !important;
        padding: 16px !important;
        border-radius: 12px !important;
        border-left: 5px solid #3b82f6 !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3) !important;
    }

    /* Metric Label Text (e.g. Total Logs Ingested, Total Security Alerts) */
    [data-testid="stMetricLabel"],
    [data-testid="stMetricLabel"] *,
    [data-testid="stMetricLabel"] p,
    [data-testid="stMetricLabel"] label,
    [data-testid="stMetricLabel"] span {
        color: #93c5fd !important;
        font-weight: 600 !important;
        font-size: 1rem !important;
    }

    /* Metric Value Text (Numbers e.g. 168, 84, 48, 0) */
    [data-testid="stMetricValue"],
    [data-testid="stMetricValue"] *,
    [data-testid="stMetricValue"] div,
    [data-testid="stMetricValue"] span,
    [data-testid="stMetricValue"] p {
        color: #ffffff !important;
        font-weight: 800 !important;
        font-size: 2.2rem !important;
        text-shadow: 0 2px 4px rgba(0, 0, 0, 0.4) !important;
    }

    /* Metric Delta (Urgent Badge) */
    [data-testid="stMetricDelta"],
    [data-testid="stMetricDelta"] *,
    [data-testid="stMetricDelta"] div,
    [data-testid="stMetricDelta"] span {
        font-weight: 700 !important;
    }

    /* Severity Badges */
    .stBadge { font-weight: bold; padding: 4px 8px; border-radius: 4px; }
    .critical-badge { background-color: #ef4444; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .high-badge { background-color: #f97316; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .medium-badge { background-color: #eab308; color: black; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .low-badge { background-color: #3b82f6; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def get_pipeline():
    return SIEMPipeline()

pipeline = get_pipeline()

# Sidebar Control Center
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=70)
st.sidebar.title("🛡️ SIEM Sentinel SOC")
st.sidebar.caption("Hybrid Detection Engine v2.0")

st.sidebar.markdown("---")
st.sidebar.subheader("🕹️ Simulation Controls")

if st.sidebar.button("🚀 Run Full Attack Simulation", width="stretch"):
    with st.spinner("Executing simulated attack vectors..."):
        pipeline.run_simulation_batch(40)
        st.sidebar.success("Attack simulation completed!")

st.sidebar.markdown("---")
st.sidebar.subheader("⚙️ System Status")
st.sidebar.markdown("🟢 **Sigma Engine**: ACTIVE (`5 Rules Loaded`)")
st.sidebar.markdown("🟢 **ML Anomaly (Isolation Forest)**: ONLINE")
st.sidebar.markdown("🟢 **Threat Intel Enrichment**: ONLINE")
st.sidebar.markdown("🟢 **SOAR Playbooks**: ACTIVE")

if st.sidebar.button("🗑️ Clear Database Logs", width="stretch"):
    pipeline.db.clear_all()
    if os.path.exists("./soar_mitigation.sh"):
        os.remove("./soar_mitigation.sh")
    if os.path.exists("./soar_mitigation.ps1"):
        os.remove("./soar_mitigation.ps1")
    st.sidebar.warning("Database cleared!")
    st.rerun()

# Header
st.title("🛡️ SIEM Sentinel - Hybrid Security Operations Dashboard")
st.markdown("Production-grade SIEM combining **Sigma YAML Rules**, **Unsupervised ML Anomaly Detection**, **Threat Intel Enrichment**, and **SOAR Playbooks**.")

# Fetch Statistics
stats = pipeline.db.get_stats()
alerts = pipeline.db.get_alerts(limit=200)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Logs Ingested", stats["total_events"])
m2.metric("Total Security Alerts", stats["total_alerts"])
critical_count = stats["severity_counts"].get("CRITICAL", 0)
m3.metric("Critical Threat Alerts", critical_count, delta=f"{critical_count} Urgent" if critical_count > 0 else None, delta_color="inverse")
blocked_count = len(pipeline.soar.blocked_ips)
m4.metric("SOAR Auto-Blocked IPs", blocked_count)

st.markdown("---")

# Navigation Tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🚨 Real-Time Alert Feed",
    "📊 MITRE ATT&CK Matrix Analytics",
    "🤖 ML Anomaly Inspector",
    "🌐 Threat Intel & IP Lookup",
    "⚡ SOAR Active Defense Playbooks"
])

# TAB 1: Real-Time Alert Feed
with tab1:
    st.subheader("📋 Ingested Security Alerts")
    
    col_filter1, col_filter2 = st.columns([2, 2])
    with col_filter1:
        severity_filter = st.multiselect("Filter by Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    with col_filter2:
        detection_filter = st.multiselect("Filter by Engine Type", ["SIGMA", "ML_ANOMALY"], default=["SIGMA", "ML_ANOMALY"])

    filtered_alerts = [
        a for a in alerts 
        if a["severity"] in severity_filter and a["detection_type"] in detection_filter
    ]

    if filtered_alerts:
        df_alerts = pd.DataFrame(filtered_alerts)
        display_df = df_alerts[["id", "timestamp", "severity", "detection_type", "rule_title", "mitre_technique", "source_ip", "user", "abuse_score", "asn_tag", "soar_action_taken"]]
        st.dataframe(display_df, width="stretch", height=350)

        # Selected Alert Deep Dive Inspector
        st.markdown("### 🔍 Alert Deep-Dive Inspector")
        selected_alert_id = st.selectbox("Select Alert ID to Inspect Details:", df_alerts["id"].tolist())
        if selected_alert_id:
            target_alert = next((a for a in alerts if a["id"] == selected_alert_id), None)
            if target_alert:
                i1, i2 = st.columns(2)
                with i1:
                    st.markdown(f"**Rule:** `{target_alert.get('rule_title')}`")
                    st.markdown(f"**Detection Type:** `{target_alert.get('detection_type')}`")
                    st.markdown(f"**Severity:** `{target_alert.get('severity')}`")
                    st.markdown(f"**Attacker IP:** `{target_alert.get('source_ip')}`")
                    st.markdown(f"**Target User:** `{target_alert.get('user')}`")
                with i2:
                    st.markdown(f"**MITRE Technique:** `{target_alert.get('mitre_technique')}`")
                    st.markdown(f"**AbuseIPDB Score:** `{target_alert.get('abuse_score')}/100`")
                    st.markdown(f"**ASN Classification:** `{target_alert.get('asn_tag')}`")
                    st.markdown(f"**SOAR Action Taken:** `{target_alert.get('soar_action_taken')}`")

                st.markdown("**Raw Alert Payload Details:**")
                st.json(target_alert.get("details", {}))
    else:
        st.info("No security alerts matching selected filters. Run the Attack Simulation from the sidebar to generate live test alerts!")

# TAB 2: MITRE ATT&CK Matrix Analytics
with tab2:
    st.subheader("📊 MITRE ATT&CK Framework Coverage & Incident Breakdown")

    if stats["mitre_counts"]:
        df_mitre = pd.DataFrame(list(stats["mitre_counts"].items()), columns=["MITRE Technique", "Alert Count"])
        
        # Friendly Technique Titles
        technique_map = {
            "T1110": "T1110 - Brute Force Authentication",
            "T1110.001": "T1110.001 - Password Guessing",
            "T1190": "T1190 - Exploit Public-Facing Application (SQLi / Traversal)",
            "T1505.003": "T1505.003 - Web Shell Persistence",
            "T1078": "T1078 - Valid Accounts / Anomalous Login",
            "T1000": "T1000 - General Anomaly"
        }
        df_mitre["Technique Name"] = df_mitre["MITRE Technique"].map(lambda x: technique_map.get(x, x))

        fig = px.bar(
            df_mitre, 
            x="Technique Name", 
            y="Alert Count", 
            color="Alert Count",
            color_continuous_scale="Reds",
            title="Detections Mapped to MITRE ATT&CK Techniques",
            text="Alert Count"
        )
        fig.update_layout(template="plotly_dark", height=400)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No MITRE metrics recorded yet.")

# TAB 3: ML Anomaly Inspector
with tab3:
    st.subheader("🤖 Unsupervised Machine Learning Anomaly Detection (Isolation Forest)")
    st.markdown("""
    The ML Anomaly Engine analyzes statistical baselines (request length, byte size, Shannon entropy, request frequency per minute, status codes, and off-hours execution) to flag zero-day threats that bypass static rules.
    """)

    ml_alerts = [a for a in alerts if a["detection_type"] == "ML_ANOMALY"]
    if ml_alerts:
        df_ml = pd.DataFrame(ml_alerts)
        st.markdown(f"**Total ML Statistical Outliers Flagged:** `{len(df_ml)}`")

        # Scatter Plot of Entropy vs Anomaly Score
        scores = []
        entropies = []
        freqs = []
        ips = []
        for a in ml_alerts:
            details = a.get("details", {})
            feat = details.get("extracted_features", {})
            scores.append(details.get("anomaly_score", -0.5))
            entropies.append(feat.get("param_entropy", 0.0))
            freqs.append(feat.get("request_freq_per_min", 1.0))
            ips.append(a.get("source_ip"))

        df_scatter = pd.DataFrame({"Anomaly Score": scores, "Param Entropy": entropies, "Request Freq": freqs, "IP": ips})
        
        fig_ml = px.scatter(
            df_scatter,
            x="Param Entropy",
            y="Anomaly Score",
            size="Request Freq",
            color="Anomaly Score",
            hover_name="IP",
            title="Statistical Outliers: Shannon Entropy vs. Isolation Forest Anomaly Score",
            color_continuous_scale="Viridis"
        )
        fig_ml.update_layout(template="plotly_dark", height=400)
        st.plotly_chart(fig_ml, use_container_width=True)

        st.markdown("#### 🔬 Explainable ML Anomaly Detections")
        for idx, a in enumerate(ml_alerts[:5]):
            with st.expander(f"ML Anomaly Alert #{a['id']} - IP: {a['source_ip']} (Score: {a.get('details', {}).get('anomaly_score')})"):
                st.write("**Extracted Baseline Features:**", a.get("details", {}).get("extracted_features"))
                st.write("**Explainability Reasons:**", a.get("details", {}).get("anomaly_reasons"))
    else:
        st.info("No ML anomalies triggered yet. Click 'Run Full Attack Simulation' on the sidebar!")

# TAB 4: Threat Intel & IP Lookup
with tab4:
    st.subheader("🌐 Automated Threat Intelligence Enrichment Engine")
    
    ip_query = st.text_input("Lookup Any IP Address for Live Threat Intel:", value="185.220.101.5")
    if st.button("🔍 Query Threat Intel"):
        with st.spinner(f"Enriching IP {ip_query}..."):
            info = pipeline.threat_intel.enrich_ip(ip_query)
            
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("AbuseIPDB Confidence Score", f"{info['abuse_score']}%")
            c2.metric("Reverse DNS", info['domain'])
            c3.metric("Country", info['country'])
            c4.metric("ASN Classification", info['asn_tag'])

            st.json(info)

# TAB 5: SOAR Active Defense Playbooks
with tab5:
    st.subheader("⚡ Automated SOAR Playbooks & Active Defense")
    st.markdown("""
    When an alert reaches `CRITICAL` severity or exceeds AbuseIPDB confidence threshold (75%), SOAR playbooks automatically generate active mitigation firewall null-route scripts and dispatch webhooks.
    """)

    st.markdown("#### 🚫 Active Blocked IP List")
    if pipeline.soar.blocked_ips:
        st.write(pipeline.soar.blocked_ips)
    else:
        st.info("No IPs currently blocked. Run simulation to trigger automatic SOAR IP blocking!")

    col_s1, col_s2 = st.columns(2)
    with col_s1:
        st.markdown("#### 📜 Generated Linux Firewall Script (`soar_mitigation.sh`)")
        if os.path.exists("./soar_mitigation.sh"):
            with open("./soar_mitigation.sh", "r") as f:
                st.code(f.read(), language="bash")
        else:
            st.info("Script will be generated automatically when critical alerts occur.")

    with col_s2:
        st.markdown("#### 📜 Generated PowerShell Firewall Script (`soar_mitigation.ps1`)")
        if os.path.exists("./soar_mitigation.ps1"):
            with open("./soar_mitigation.ps1", "r") as f:
                st.code(f.read(), language="powershell")
        else:
            st.info("Script will be generated automatically when critical alerts occur.")

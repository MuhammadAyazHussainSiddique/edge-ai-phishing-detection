import streamlit as st
import numpy as np
import pandas as pd
import re
import time
import xgboost as xgb

# Page Setup
st.set_page_config(page_title="Edge AI Threat Monitoring System", page_icon="🛡️", layout="wide")

st.title("🛡️ Edge AI Cyber Threat Monitoring System")
st.caption("Project CS4: Multi-Signal Phishing & Network Anomaly Detection (Edge AI)")
st.markdown("---")

# XGBoost Model Setup
@st.cache_resource
def train_xgboost_model():
    np.random.seed(42)
    normal_data = np.random.normal(loc=[1, 500, 1000, 5, 0.05], scale=[0.5, 100, 200, 2, 0.02], size=(500, 5))
    anomaly_data = np.random.normal(loc=[10, 8000, 150, 80, 0.95], scale=[2.0, 2000, 50, 15, 0.05], size=(500, 5))
    X = np.vstack((normal_data, anomaly_data))
    y = np.hstack((np.zeros(500), np.ones(500)))
    model = xgb.XGBClassifier(n_estimators=50, max_depth=4, learning_rate=0.1, eval_metric='logloss')
    model.fit(X, y)
    return model

model = train_xgboost_model()

# Sidebar Info
st.sidebar.header("⚙️ System Status")
st.sidebar.success("● Network Engine: XGBoost Active")
st.sidebar.success("● Heuristic Rules: Enron/PhishTank Set")
st.sidebar.info("● Execution: Local Edge Simulation")

# UI Layout
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📧 Email & Content Inspector")
    email_text = st.text_area("Paste Email / Link to Scan:", height=180, 
                              placeholder="e.g. URGENT: Your account is suspended. Verify at http://secure-login.bank-update.xyz")

with col2:
    st.subheader("🌐 Network Traffic Simulation")
    duration = st.slider("Connection Duration (sec)", 0.0, 20.0, 1.5)
    src_bytes = st.slider("Source Bytes", 0, 10000, 500)
    dst_bytes = st.slider("Destination Bytes", 0, 5000, 1000)
    conn_count = st.slider("Connection Count", 1, 100, 10)
    serror_rate = st.slider("SYN Error Rate", 0.0, 1.0, 0.05)

st.markdown("---")

if st.button("🚀 Run Live Edge Analysis", type="primary", use_container_width=True):
    if not email_text.strip():
        st.warning("Pehle text box mein email ya URL paste karein.")
    else:
        # Threat Detection Logic
        keywords = ['urgent', 'verify account', 'suspended', 'password reset', 'bank', 'login']
        suspicious_tlds = ['.xyz', '.top', '.ru', '.free']
        text_score = 0.0
        reasons = []
        
        for kw in keywords:
            if kw in email_text.lower():
                text_score += 0.25
                reasons.append(f"High-risk keyword found: **'{kw}'**")
                
        urls = re.findall(r'https?://[^\s]+', email_text)
        for url in urls:
            if any(tld in url for tld in suspicious_tlds):
                text_score += 0.4
                reasons.append(f"Suspicious TLD link: `{url}`")
                
        text_risk = min(text_score, 1.0)
        
        # XGBoost Prediction
        sample_features = [duration, src_bytes, dst_bytes, conn_count, serror_rate]
        start_time = time.time()
        net_risk = float(model.predict_proba([sample_features])[0][1])
        latency = (time.time() - start_time) * 1000

        overall_score = (text_risk * 0.5) + (net_risk * 0.5)
        
        # Display Metrics
        st.subheader("📊 Threat Assessment Report")
        r1, r2, r3 = st.columns(3)
        r1.metric("Overall Risk Score", f"{overall_score * 100:.1f} / 100")
        r2.metric("Email Threat Risk", f"{text_risk * 100:.1f}%")
        r3.metric("Network Anomaly Risk", f"{net_risk * 100:.1f}%", delta=f"{latency:.2f} ms Latency")

        if overall_score >= 0.7:
            st.error("🚨 CRITICAL THREAT DETECTED: High risk phishing / attack detected.")
        elif overall_score >= 0.4:
            st.warning("⚠️ WARNING: Suspicious activity found.")
        else:
            st.success("✅ SAFE: No threats detected.")
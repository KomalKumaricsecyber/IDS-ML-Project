import streamlit as st
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
import random
import time

# Page config
st.set_page_config(page_title="AI IDS Dashboard", page_icon="🛡️", layout="wide")

# Columns list
columns = (['duration','protocol_type','service','flag','src_bytes','dst_bytes',
            'land','wrong_fragment','urgent','hot','num_failed_logins',
            'logged_in','num_compromised','root_shell','su_attempted','num_root',
            'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
            'is_host_login','is_guest_login','count','srv_count','serror_rate',
            'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
            'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
            'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
            'dst_host_rerror_rate','dst_host_srv_rerror_rate','attack_type','level'])

@st.cache_resource
def load_model():
    return joblib.load('ids_model.pkl')

model = load_model()

# Header Design
st.markdown("<h1 style='text-align: center; color: #1E90FF;'>🛡️ AI-Powered Intrusion Detection System</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>Real-time Machine Learning Network Monitor (Random Forest Engine)</p>", unsafe_allow_html=True)
st.divider()

# UI Layout
col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("Control Panel")
    st.info("Click the button below to intercept a random network packet from the live stream and analyze it for threats.")
    start_scan = st.button("🔍 Intercept & Analyze Packet", use_container_width=True)

with col2:
    if start_scan:
        with st.spinner("Analyzing packet signatures & network protocols..."):
            time.sleep(1.5)  # Adding a realistic processing delay
            
            # Load and pick random data
            df = pd.read_csv('Dataset/KDDTrain+.txt', header=None, names=columns)
            random_index = random.randint(0, len(df)-1)
            sample_data = df.iloc[[random_index]].copy()
            actual_attack = sample_data['attack_type'].values[0]
            
            # Preprocessing
            clean_data = sample_data.drop(['attack_type', 'level'], axis=1)
            categorical_columns = ['protocol_type', 'service', 'flag']
            le = LabelEncoder()
            for col in categorical_columns:
                le.fit(df[col]) 
                clean_data[col] = le.transform(clean_data[col])
                
            # Prediction
            prediction = model.predict(clean_data)[0]
            
            # Show Results in Tabs
            tab1, tab2 = st.tabs(["🚨 Threat Report", "📊 Packet Metadata"])
            
            with tab1:
                if prediction == 1:
                    st.error(f"⚠️ THREAT DETECTED: Malicious Signature matched '{actual_attack}' profile.")
                    st.warning("Action Recommended: Block Source IP immediately.")
                else:
                    st.success("✅ TRAFFIC SAFE: No malicious signatures detected.")
                
                # Show key indicators
                st.write("### Key Threat Indicators:")
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Protocol", sample_data['protocol_type'].values[0].upper())
                m2.metric("Failed Logins", int(sample_data['num_failed_logins'].values[0]))
                m3.metric("Root Shell Access", "Yes" if sample_data['root_shell'].values[0] == 1 else "No")
                m4.metric("Compromised Condition", int(sample_data['num_compromised'].values[0]))
                
            with tab2:
                st.write("Raw Packet Header Data:")
                st.dataframe(sample_data.drop(['attack_type', 'level'], axis=1))
    else:
        st.write("### System Status: 🟢 Online & Monitoring...")
        st.write("Waiting for manual intercept command.")
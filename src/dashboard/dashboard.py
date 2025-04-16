import streamlit as st
import pandas as pd
import altair as alt
import time
import sqlite3
from datetime import datetime, timedelta
import sys
import os

# Add the project root to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import config
from src.utils import get_recent_detections, get_attack_statistics, get_top_attacker_ips
from src.mitigator import get_blocked_ips, block_ip, unblock_ip

# Configure the page
st.set_page_config(
    page_title="Network IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
)


st.markdown("""
<style>
    /* Attack alert - Change from light red to a darker red with white text */
    .attack-alert {
        background-color: #d32f2f;
        border-left: 5px solid #b71c1c;
        padding: 10px;
        margin-bottom: 10px;
        color: white;
        font-weight: 500;
        border-radius: 4px;
    }
    
    /* Normal flow - Change from light green to a more visible green with dark text */
    .normal-flow {
        background-color: #66bb6a;
        border-left: 5px solid #2e7d32;
        padding: 10px;
        margin-bottom: 10px;
        color: #1b1b1b;
        font-weight: 500;
        border-radius: 4px;
    }
    
    /* Improve font readability */
    .attack-alert h4 {
        margin-top: 0;
        color: white;
        font-size: 18px;
    }
    
    .attack-alert p, .normal-flow p {
        margin-bottom: 5px;
        font-size: 14px;
        line-height: 1.4;
    }
    
    /* Keep the other styles */
    .header-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    
    .metric-container {
        background-color: #f0f2f6;
        border-radius: 5px;
        padding: 10px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)


# Initialize session state for data storage
if 'last_refresh' not in st.session_state:
    st.session_state.last_refresh = datetime.now()

# Header
st.markdown("<h1 style='text-align: center;'>Network Intrusion Detection System Dashboard</h1>", unsafe_allow_html=True)

# Create tabs
tab1, tab2, tab3 = st.tabs(["Monitoring", "Statistics", "IP Management"])

# Tab 1: Monitoring
with tab1:
    st.header("Live Network Traffic Monitoring")
    
    # Last 5 detections
    st.subheader("Recent Detections")
    
    # Auto-refresh component
    refresh_interval = st.slider("Refresh interval (seconds)", min_value=1, max_value=60, value=5)
    
    # Get detections directly in the main thread
    detections = get_recent_detections(limit=10)
    
    if not detections:
        st.info("No detections found.")
    else:
        for detection in detections:
            attack_type = detection.get('attack_type', 'Unknown')
            source_ip = detection.get('source_ip', 'Unknown')
            formatted_time = detection.get('formatted_time', 'Unknown time')
            
            # Create a container for the detection
            if attack_type != "Benign":
                markdown = f"""
                <div class='attack-alert'>
                    <h4>🚨 {attack_type.upper()} ATTACK DETECTED</h4>
                    <p><b>Time:</b> {formatted_time} | <b>Source IP:</b> {source_ip}</p>
                    <p><b>Details:</b> Bytes: {detection.get('orig_bytes', 0)}, Packets: {detection.get('orig_pkts', 0)}</p>
                </div>
                """
            else:
                markdown = f"""
                <div class='normal-flow'>
                    <p><b>Time:</b> {formatted_time} | <b>Source IP:</b> {source_ip} | <b>Status:</b> Normal traffic</p>
                </div>
                """
            
            st.markdown(markdown, unsafe_allow_html=True)

# Tab 2: Statistics
with tab2:
    st.header("Attack Statistics")
    
    # Create columns for metrics
    col1, col2, col3 = st.columns(3)
    
    # Get attack statistics
    attack_stats = get_attack_statistics()
    total_attacks = sum(count for attack_type, count in attack_stats.items() if attack_type != "Benign")
    
    # Get top attackers
    top_attackers = get_top_attacker_ips(limit=10)
    unique_attackers = len(top_attackers)
    
    # Calculate detection rate (attacks per minute)
    try:
        conn = sqlite3.connect(config.DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get counts for the last hour
        one_hour_ago = datetime.now() - timedelta(hours=1)
        cursor.execute('''
            SELECT COUNT(*) FROM detections 
            WHERE attack_type != 'Benign' 
            AND detected_at > datetime(?, 'unixepoch')
        ''', (one_hour_ago.timestamp(),))
        
        attacks_last_hour = cursor.fetchone()[0]
        conn.close()
        
        detection_rate = attacks_last_hour / 60.0  # per minute
    except:
        detection_rate = 0
    
    # Update metrics directly
    with col1:
        st.metric(
            "Total Attacks Detected", 
            f"{total_attacks}", 
            help="Total number of attacks detected"
        )
    
    with col2:
        st.metric(
            "Unique Attacker IPs", 
            f"{unique_attackers}", 
            help="Number of unique IP addresses that launched attacks"
        )
    
    with col3:
        st.metric(
            "Detection Rate", 
            f"{detection_rate:.2f}/min", 
            help="Average number of attacks detected per minute in the last hour"
        )
    
    # Create attack types chart
    if attack_stats:
        attack_df = pd.DataFrame({
            'Attack Type': list(attack_stats.keys()),
            'Count': list(attack_stats.values())
        })
        
        st.subheader("Attack Types Distribution")
        chart = alt.Chart(attack_df).mark_bar().encode(
            x=alt.X('Attack Type:N', sort='-y'),
            y='Count:Q',
            color=alt.condition(
                alt.datum['Attack Type'] == 'Benign',
                alt.value('green'),
                alt.value('red')
            )
        ).properties(height=300)
        
        st.altair_chart(chart, use_container_width=True)
    else:
        st.info("No attack data available.")
    
    # Create top attackers chart
    if top_attackers:
        attackers_df = pd.DataFrame(top_attackers, columns=['IP Address', 'Attack Count'])
        
        st.subheader("Top Attacker IP Addresses")
        chart = alt.Chart(attackers_df).mark_bar().encode(
            x='Attack Count:Q',
            y=alt.Y('IP Address:N', sort='-x'),
            color=alt.value('red')
        ).properties(height=300)
        
        st.altair_chart(chart, use_container_width=True)
    else:
        st.info("No attacker data available.")

# Tab 3: IP Management
with tab3:
    st.header("IP Address Management")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Block a New IP Address")
        with st.form("block_ip_form"):
            ip_to_block = st.text_input("IP Address to Block")
            submit_block = st.form_submit_button("Block IP")
            
            if submit_block and ip_to_block:
                if block_ip(ip_to_block):
                    st.success(f"Successfully blocked IP: {ip_to_block}")
                else:
                    st.error(f"Failed to block IP: {ip_to_block}")
    
    with col2:
        st.subheader("Currently Blocked IPs")
        
        # Get blocked IPs directly
        blocked_ips = get_blocked_ips()
        
        if not blocked_ips:
            st.info("No IPs are currently blocked.")
        else:
            # Create a DataFrame for the blocked IPs
            blocked_df = pd.DataFrame(blocked_ips)
            blocked_df['blocked_at'] = pd.to_datetime(blocked_df['blocked_at'])
            blocked_df['formatted_time'] = blocked_df['blocked_at'].dt.strftime('%Y-%m-%d %H:%M:%S')
            
            # Display the blocked IPs in a table
            st.dataframe(
                blocked_df[['ip_address', 'formatted_time']],
                column_config={
                    "ip_address": "IP Address",
                    "formatted_time": "Blocked At"
                },
                hide_index=True
            )
            
            # Add unblock functionality
            selected_ip = st.selectbox(
                "Select IP to unblock", 
                options=[ip['ip_address'] for ip in blocked_ips]
            )
            
            if st.button("Unblock Selected IP"):
                if unblock_ip(selected_ip):
                    st.success(f"Successfully unblocked IP: {selected_ip}")
                else:
                    st.error(f"Failed to unblock IP: {selected_ip}")

# Add auto-refresh using Streamlit's native auto-refresh capability
if refresh_interval:
    current_time = datetime.now()
    if (current_time - st.session_state.last_refresh).total_seconds() >= refresh_interval:
        st.session_state.last_refresh = current_time
        st.rerun()

# Display refresh status
st.write(f"Last refreshed: {st.session_state.last_refresh.strftime('%Y-%m-%d %H:%M:%S')}")
st.write(f"Dashboard will auto-refresh every {refresh_interval} seconds. To stop, close this tab or press Ctrl+C in the terminal.")
import os
import time
import pandas as pd
import streamlit as st
import joblib

# Import local project modules
import database
from detect import detect_threat
from alert_system import trigger_alert, get_recent_logs
import packet_capture
from utils.visualization import (
    plot_severity_donut, 
    plot_attack_bar, 
    plot_threat_trend, 
    plot_confusion_matrix_plotly, 
    plot_feature_importance_plotly
)
from utils.helper import resolve_port, get_local_ip, get_severity_color

# Ensure database is initialized
database.init_db()

# Page configuration
st.set_page_config(
    page_title="AI-Driven Cyber Threat Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject custom CSS stylesheet
CSS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'styles.css')
if os.path.exists(CSS_PATH):
    with open(CSS_PATH, 'r') as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Callback function to handle incoming captured/simulated packets
def packet_processing_callback(pkt_dict):
    """Callback passed to the sniffer thread to process each packet in real-time."""
    # Run prediction using detect module
    res = detect_threat(pkt_dict)
    
    # Update packet dictionary inside the rolling queue buffer by reference
    pkt_dict['is_threat'] = res['is_threat']
    pkt_dict['attack_type'] = res['attack_type']
    pkt_dict['severity'] = res['severity']
    pkt_dict['confidence'] = res['confidence']
    
    # If the packet is classified as malicious, trigger logging & db alert storage
    if res['is_threat']:
        trigger_alert(res, pkt_dict)

# Header Section
st.markdown("""
<div style="background-color: #0c1424; padding: 20px; border-radius: 10px; border-bottom: 2px solid #00F0FF; margin-bottom: 25px;">
    <h1 style="color: #00F0FF; margin: 0; font-weight: 700; letter-spacing: 1px;">🛡️ AI-DRIVEN THREAT DETECTION SYSTEM</h1>
    <p style="color: #94a3b8; margin: 5px 0 0 0; font-size: 14px;">Real-Time Machine Learning Security Operations Center (SOC) Console</p>
</div>
""", unsafe_allow_html=True)

# Sidebar - System Controllers & SOC Configurations
st.sidebar.markdown("""
<div style="text-align: center; padding-bottom: 15px; border-bottom: 1px solid #1e293b;">
    <h2 style="color: #00F0FF; margin: 0; font-size: 20px;">SECURITY ENGINE</h2>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("<br>", unsafe_allow_html=True)

# Display Current Engine State
is_running_now = packet_capture.is_running()
sim_mode = packet_capture.is_simulation_mode()

if is_running_now:
    status_html = f"""
    <div style="background: rgba(15,23,42,0.8); border: 1px solid #1e293b; border-radius: 8px; padding: 12px; margin-bottom: 15px;">
        <span class="status-indicator status-scanning"></span>
        <span style="color: #00F0FF; font-weight: 600;">ENGINE ACTIVE</span>
        <div style="color: #94a3b8; font-size: 12px; margin-top: 5px;">Mode: {"SIMULATION FALLBACK" if sim_mode else "LIVE SNIFFING"}</div>
        <div style="color: #94a3b8; font-size: 12px;">Local IP: {get_local_ip()}</div>
    </div>
    """
else:
    status_html = """
    <div style="background: rgba(15,23,42,0.8); border: 1px solid #1e293b; border-radius: 8px; padding: 12px; margin-bottom: 15px;">
        <span class="status-indicator status-online" style="background-color: #8e8e93; box-shadow: none; animation: none;"></span>
        <span style="color: #e2e8f0; font-weight: 600;">ENGINE STANDBY</span>
        <div style="color: #94a3b8; font-size: 12px; margin-top: 5px;">Sniffer offline. Toggle control below to start.</div>
    </div>
    """
st.sidebar.markdown(status_html, unsafe_allow_html=True)

# Engine Controls
st.sidebar.markdown("### Controls")
rate_slider = st.sidebar.slider("Capture Rate (Packets/Sec)", min_value=0.5, max_value=10.0, value=2.0, step=0.5)
packet_capture.set_packet_rate(rate_slider)

if is_running_now:
    if st.sidebar.button("🔴 STOP CAPTURE", use_container_width=True):
        packet_capture.stop_capture()
        st.toast("Packet sniffer stopped.")
        time.sleep(0.5)
        st.rerun()
else:
    if st.sidebar.button("🟢 START CAPTURE", use_container_width=True):
        # Start background packet capture thread
        packet_capture.start_capture(packet_processing_callback, rate=rate_slider)
        st.toast("Packet sniffer initialized.")
        time.sleep(0.5)
        st.rerun()

st.sidebar.markdown("---")

# Cyber Attack Vector Simulator (Available in simulation mode)
st.sidebar.markdown("### Attack Vector Injector")
st.sidebar.info("Simulate cyber incidents to test classification and analyst workflows:")

col1, col2 = st.sidebar.columns(2)
with col1:
    if st.button("💥 DDoS", use_container_width=True, disabled=not is_running_now):
        packet_capture.inject_attack('DDoS')
        st.toast("Injected DDoS Packet.")
    if st.button("🔍 Port Scan", use_container_width=True, disabled=not is_running_now):
        packet_capture.inject_attack('Port Scan')
        st.toast("Injected Port Scan Packet.")
with col2:
    if st.button("🔑 Brute Force", use_container_width=True, disabled=not is_running_now):
        packet_capture.inject_attack('Brute Force')
        st.toast("Injected Brute Force Packet.")
    if st.button("🔓 Infiltration", use_container_width=True, disabled=not is_running_now):
        packet_capture.inject_attack('Infiltration')
        st.toast("Injected Infiltration Packet.")

st.sidebar.markdown("---")

# Navigation Menu
st.sidebar.markdown("### Console Navigation")
nav_selection = st.sidebar.radio(
    "Select Console View",
    ["📺 Live SOC Monitor", "📊 Threat Analytics", "🧠 ML Model Center", "🗄️ Alert Ticket System"]
)

# Footer options
st.sidebar.markdown("---")
if st.sidebar.button("🗑️ Reset Security Console", type="primary", use_container_width=True):
    packet_capture.clear_packet_buffer()
    database.clear_database()
    # Write a clean start marker to logs/alerts.log
    if os.path.exists(alert_system.LOG_FILE):
        os.remove(alert_system.LOG_FILE)
    st.toast("Console and database cleared.")
    time.sleep(0.5)
    st.rerun()

# ----------------- Navigation view logic -----------------

if nav_selection == "📺 Live SOC Monitor":
    # Autorefresh option in the main area
    refresh_col1, refresh_col2 = st.columns([1, 11])
    with refresh_col1:
        auto_refresh = st.checkbox("Auto-Refresh", value=True, help="Automatically refreshes the page every 2 seconds to fetch new packets.")
    
    # 1. Fetch live metrics
    db_stats = database.get_alert_statistics()
    recent_packets = packet_capture.get_recent_packets(limit=15)
    
    # Compute active threat count (Active and Investigating)
    conn = database.get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM threat_alerts WHERE status != 'Resolved'")
    active_threats_count = c.fetchone()[0]
    conn.close()
    
    # Dynamic threat level status
    c_level = "SECURE"
    c_color = "#34C759"
    c_indicator = "status-online"
    if active_threats_count > 0:
        # Check if there are critical threats active
        all_active_threats = database.get_all_alerts(limit=50, filter_status='Active')
        severities = [t['severity'] for t in all_active_threats]
        if 'CRITICAL' in severities:
            c_level = "CRITICAL RISK"
            c_color = "#FF3B30"
            c_indicator = "status-alert"
        elif 'HIGH' in severities:
            c_level = "HIGH RISK"
            c_color = "#FF9500"
            c_indicator = "status-alert"
        else:
            c_level = "ELEVATED RISK"
            c_color = "#FFCC00"
            c_indicator = "status-alert"
            
    # Metrics Row
    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        st.markdown(f"""
        <div class="metric-card">
            <div style="color: #94a3b8; font-size: 13px; font-weight: 600; text-transform: uppercase;">Total Packets Captured</div>
            <div style="color: #e2e8f0; font-size: 32px; font-weight: 700; margin-top: 5px;">{len(packet_capture.get_recent_packets(50))}</div>
            <div style="color: #34C759; font-size: 12px; margin-top: 5px;">↑ Live Buffer Stream</div>
        </div>
        """, unsafe_allow_html=True)
    with m_col2:
        st.markdown(f"""
        <div class="metric-card">
            <div style="color: #94a3b8; font-size: 13px; font-weight: 600; text-transform: uppercase;">Threat Alerts Logged</div>
            <div style="color: #e2e8f0; font-size: 32px; font-weight: 700; margin-top: 5px;">{db_stats.get('total_alerts', 0)}</div>
            <div style="color: #FF3B30; font-size: 12px; margin-top: 5px;">Persistent DB Records</div>
        </div>
        """, unsafe_allow_html=True)
    with m_col3:
        st.markdown(f"""
        <div class="metric-card">
            <div style="color: #94a3b8; font-size: 13px; font-weight: 600; text-transform: uppercase;">Active Threat Tickets</div>
            <div style="color: #e2e8f0; font-size: 32px; font-weight: 700; margin-top: 5px;">{active_threats_count}</div>
            <div style="color: #FF9500; font-size: 12px; margin-top: 5px;">Unresolved alerts</div>
        </div>
        """, unsafe_allow_html=True)
    with m_col4:
        st.markdown(f"""
        <div class="metric-card">
            <div style="color: #94a3b8; font-size: 13px; font-weight: 600; text-transform: uppercase;">System Threat Level</div>
            <div style="color: {c_color}; font-size: 28px; font-weight: 700; margin-top: 7px; display: flex; align-items: center;">
                <span class="status-indicator {c_indicator}"></span>{c_level}
            </div>
            <div style="color: #94a3b8; font-size: 12px; margin-top: 5px;">Based on active alerts</div>
        </div>
        """, unsafe_allow_html=True)
        
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Split view: Packet table on left, Scrolling CLI logs on right
    col_left, col_right = st.columns([7, 3])
    
    with col_left:
        st.markdown("### Live Network Traffic Feed")
        if not recent_packets:
            st.info("No packets captured yet. Click 'START CAPTURE' in the sidebar to begin network monitoring.")
        else:
            # Build DataFrame for display
            df_packets = pd.DataFrame(recent_packets)
            
            # Reorder and filter columns for analyst-friendly layout
            display_cols = ['timestamp', 'source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol', 'packet_length', 'attack_type', 'severity']
            df_packets = df_packets[display_cols]
            
            # Rename columns
            df_packets.columns = ['Time', 'Source IP', 'Src Port', 'Dest IP', 'Dest Port', 'Protocol', 'Length (Bytes)', 'ML Classification', 'Severity']
            
            # Format ports using helper
            df_packets['Src Service'] = df_packets['Src Port'].apply(resolve_port)
            df_packets['Dest Service'] = df_packets['Dest Port'].apply(resolve_port)
            
            # Re-arrange with resolved service columns
            df_packets = df_packets[['Time', 'Source IP', 'Src Service', 'Dest IP', 'Dest Service', 'Protocol', 'Length (Bytes)', 'ML Classification', 'Severity']]
            
            # Style the threat detections in table
            def highlight_threats(val):
                if val == 'Benign':
                    return 'color: #38bdf8'  # Cyber Blue
                elif val in ['DDoS', 'Port Scan', 'Brute Force', 'Infiltration']:
                    return 'color: #ef4444; font-weight: bold; background-color: rgba(239, 68, 68, 0.1)'
                return ''
                
            def highlight_severity(val):
                if val == 'CRITICAL':
                    return 'color: #ef4444; font-weight: bold;'
                elif val == 'HIGH':
                    return 'color: #f97316; font-weight: bold;'
                elif val == 'MEDIUM':
                    return 'color: #eab308; font-weight: bold;'
                elif val == 'LOW':
                    return 'color: #22c55e;'
                return ''
                
            styled_df = df_packets.style.map(highlight_threats, subset=['ML Classification']).map(highlight_severity, subset=['Severity'])
            
            # Render using Streamlit
            st.dataframe(styled_df, use_container_width=True, hide_index=True)
            
    with col_right:
        st.markdown("### SIEM Incident Stream (`alerts.log`)")
        logs = get_recent_logs(num_lines=15)
        
        # Display as a scrolling computer terminal
        logs_html = "".join([f"<div>{line}</div>" for line in logs])
        st.markdown(f"""
        <div class="cyber-terminal">
            {logs_html}
        </div>
        """, unsafe_allow_html=True)
        
    # Auto-refresh loop
    if auto_refresh and is_running_now:
        time.sleep(2.0)
        st.rerun()

elif nav_selection == "📊 Threat Analytics":
    st.markdown("### Network Incident Security Analytics")
    
    # Load data from SQLite database
    alerts = database.get_all_alerts(limit=500)
    
    if not alerts:
        st.warning("⚠️ No security alerts logged in the database yet. Run the sniffer and trigger attacks to generate analytics data.")
    else:
        # Row 1: Donut and Horizontal Bar
        ar_col1, ar_col2 = st.columns(2)
        
        # Get statistics
        stats = database.get_alert_statistics()
        
        with ar_col1:
            st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
            st.markdown("<h4 style='color: #00F0FF; margin-top:0;'>Incident Severity Distribution</h4>", unsafe_allow_html=True)
            fig_donut = plot_severity_donut(stats.get('severity_counts', {}))
            st.plotly_chart(fig_donut, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
            
        with ar_col2:
            st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
            st.markdown("<h4 style='color: #00F0FF; margin-top:0;'>Attack Vector Analysis</h4>", unsafe_allow_html=True)
            fig_bar = plot_attack_bar(stats.get('attack_type_counts', {}))
            st.plotly_chart(fig_bar, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
            
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Row 2: Trend Timeline
        st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
        st.markdown("<h4 style='color: #00F0FF; margin-top:0;'>Incident Timeline Trend Rate</h4>", unsafe_allow_html=True)
        fig_trend = plot_threat_trend(alerts)
        st.plotly_chart(fig_trend, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

elif nav_selection == "🧠 ML Model Center":
    st.markdown("### Machine Learning Model Diagnostics")
    
    # Load model
    from detect import load_model, MODEL_PATH
    pipeline = load_model()
    
    if pipeline is None:
        st.error("Model Pipeline offline. Check terminal console.")
    else:
        # Information banner
        st.info("🤖 **Engine Classifier**: The detection engine uses a **Random Forest Classifier** trained on pre-processed flow-level variables to categorize packet metrics into specific threat vector profiles.")
        
        # Grid of charts
        ml_col1, ml_col2 = st.columns(2)
        
        # Load validation dataset to compute confusion matrix dynamically
        test_data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dataset', 'test_data.csv')
        
        if os.path.exists(test_data_path):
            test_df = pd.read_csv(test_data_path)
            from utils.preprocessing import ALL_FEATURES
            X_val = test_df[ALL_FEATURES]
            y_val = test_df['attack_type']
            
            with ml_col1:
                st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
                fig_cm = plot_confusion_matrix_plotly(pipeline, X_val, y_val)
                st.plotly_chart(fig_cm, use_container_width=True)
                st.markdown("</div>", unsafe_allow_html=True)
        else:
            with ml_col1:
                st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
                st.warning("Test dataset not found. Model Confusion Matrix unavailable.")
                st.markdown("</div>", unsafe_allow_html=True)
                
        with ml_col2:
            st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
            fig_importance = plot_feature_importance_plotly(pipeline)
            st.plotly_chart(fig_importance, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
            
        # Model Training Console Section
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("### Model Re-Training Administration")
        
        with st.expander("🛠️ Re-Train Model System"):
            st.write("Trigger automated generation of a new synthetic network dataset (10,000 samples) and re-fit the Random Forest classifier.")
            if st.button("🚀 Re-Run Model Training Pipeline", type="primary"):
                with st.spinner("Executing train_model.py. Fitting Random Forest pipelines..."):
                    # Clear session model so it reloads
                    global _model_pipeline
                    _model_pipeline = None
                    try:
                        # Call training function
                        from train_model import train_and_save_model
                        train_and_save_model()
                        st.success("🎉 ML Model Pipeline re-trained and saved successfully to models/threat_model.pkl!")
                        time.sleep(1.0)
                        st.rerun()
                    except Exception as ex:
                        st.error(f"Error training model: {ex}")

elif nav_selection == "🗄️ Alert Ticket System":
    st.markdown("### Threat Alert Ticket Database")
    
    # Controls for filtering
    search_col1, search_col2, search_col3 = st.columns(3)
    with search_col1:
        search_ip = st.text_input("🔍 Search IP Address", placeholder="e.g. 192.168.1.100")
    with search_col2:
        filter_sev = st.selectbox("Priority Severity Filter", ["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    with search_col3:
        filter_stat = st.selectbox("Ticket Status Filter", ["All", "Active", "Investigating", "Resolved"])
        
    # Get filtered list
    alerts_list = database.get_all_alerts(
        limit=200,
        filter_severity=filter_sev,
        filter_status=filter_stat,
        search_ip=search_ip
    )
    
    if not alerts_list:
        st.info("No logs matched the selected database filters.")
    else:
        df_alerts = pd.DataFrame(alerts_list)
        
        # Display main alert database grid
        display_df = df_alerts.copy()
        
        # Hide internal database primary key or reorder
        display_df = display_df[['id', 'timestamp', 'source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol', 'packet_length', 'attack_type', 'severity', 'confidence', 'status', 'analyst_notes']]
        display_df.columns = ['Ticket ID', 'Timestamp', 'Source IP', 'Src Port', 'Dest IP', 'Dest Port', 'Protocol', 'Length', 'Threat Category', 'Severity', 'Confidence', 'Ticket Status', 'Analyst Notes']
        
        st.dataframe(display_df, use_container_width=True, hide_index=True)
        
        # Actions layout: analyst can update ticket status
        st.markdown("### Analyst Action Desk")
        act_col1, act_col2 = st.columns(2)
        
        with act_col1:
            st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
            st.markdown("<h4 style='color: #00F0FF; margin-top:0;'>Update Ticket Status</h4>", unsafe_allow_html=True)
            
            with st.form("ticket_update_form"):
                ticket_id = st.selectbox("Select Ticket ID", options=df_alerts['id'].tolist())
                new_status = st.selectbox("Set Ticket Status", ["Active", "Investigating", "Resolved"])
                notes = st.text_area("Analyst Investigation Notes", max_chars=300)
                
                if st.form_submit_button("💾 Save Ticket Audit"):
                    # Update status in db
                    success = database.update_alert_status(ticket_id, new_status, notes)
                    if success:
                        st.toast(f"Ticket #{ticket_id} updated to {new_status}.")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error("Error updating ticket. Check console.")
            st.markdown("</div>", unsafe_allow_html=True)
            
        with act_col2:
            st.markdown("<div class='metric-card' style='height: 100%;'>", unsafe_allow_html=True)
            st.markdown("<h4 style='color: #00F0FF; margin-top:0;'>Export Incident Reports</h4>", unsafe_allow_html=True)
            st.write("Export current query results to CSV format for distribution or escalation to senior administration:")
            
            # Export data button
            csv_data = display_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download CSV Incident Report",
                data=csv_data,
                file_name=f"Threat_Alerts_Report_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime='text/csv',
                use_container_width=True
            )
            
            st.markdown("<br><br>", unsafe_allow_html=True)
            st.write("Report Metadata:")
            st.json({
                "Exported Timestamp": pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
                "Total Record Count": len(display_df),
                "Source Filter": f"IP Match: '{search_ip or 'None'}'",
                "Severity Filter": filter_sev,
                "Status Filter": filter_stat
            })
            st.markdown("</div>", unsafe_allow_html=True)

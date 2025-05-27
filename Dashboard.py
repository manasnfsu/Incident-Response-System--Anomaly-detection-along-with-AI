import os
import re
import io
import time
import base64
import smtplib
import hashlib
import sqlite3
import joblib
import paramiko
import requests
import ipaddress
import numpy as np
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import plotly.express as px

from io import StringIO
from PIL import Image
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from dotenv import load_dotenv
from sklearn.svm import OneClassSVM
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

import streamlit as st
from src.predict import ProcessAnomalyPredictor


# =============================================
# CONFIGURATION
# =============================================
# CONFIGURATION (Updated thresholds)
# =============================================
DB_PATH = "C:/Project/process_monitoring.db"
MY_IP = "192.168.154.133"
SCAN_THRESHOLD = 5
FLOOD_THRESHOLD = 15
TRAFFIC_THRESHOLD = 0.5
HIGH_CPU_THRESHOLD = 35
HIGH_MEM_THRESHOLD = 25  # Increased focus on memory
AUTO_KILL_CPU_THRESHOLD = 30
AUTO_KILL_MEM_THRESHOLD =  25 # New threshold for automatic process killing based on memory

MODEL_FILE = 'anomaly_detection_model.joblib'
SCALER_FILE = 'feature_scaler.joblib'
ENCODER_FILE = 'label_encoder.joblib'
THRESHOLD = 0.95  # Confidence threshold for alerts
DB_PATH = "C:\Project\process_monitoring.db"

# =============================================
# ALERT CONFIGURATION
# =============================================
ALERT_INTERVAL_HOURS = 4  # Send alerts every 4 hours
LAST_ALERT_SENT = None    # Track last alert time

# Database Connection Functions

def detect_c2_communication(network_df):
    """Enhanced C2 detection with TTP patterns"""
    suspicious_indicators = {
        'domains': ['pastebin.com', 'github.io', 'azurewebsites.net', 'ddns.net'],
        'ports': [4444, 8080, 53, 1337, 8443],
        'protocols': ['DNS', 'HTTP', 'ICMP', 'HTTPS'],
        'time_patterns': ['00:00-05:00']  # Late night activity
    }
    
    network_df['timestamp'] = pd.to_datetime(network_df['timestamp'])
    network_df['hour'] = network_df['timestamp'].dt.hour
    
    # Domain pattern detection
    domain_mask = network_df['dst_ip'].str.contains('|'.join(suspicious_indicators['domains']), case=False, na=False)
    
    # Time pattern detection
    time_mask = network_df['hour'].between(0, 5)
    
    # Combine indicators
    network_df['c2_risk'] = (
        domain_mask | 
        network_df['dst_port'].isin(suspicious_indicators['ports']) |
        network_df['protocol'].isin(suspicious_indicators['protocols']) |
        time_mask
    ).astype(int)
    
    return network_df

def send_alert_email(anomalies, network_threats, suspicious_cmds):
    """Send email alert for critical events only"""
    alert_email = MIMEMultipart()
    alert_email['Subject'] = f"🚨 Security Alert - Critical Events Detected"
    alert_email['From'] = EMAIL_SENDER
    alert_email['To'] = EMAIL_RECIPIENT

    # Build HTML content
    html_content = f"""
    <html>
        <body style="font-family: Arial; color: #333;">
            <h2 style="color: #d9534f;">Critical Security Alerts (Last {ALERT_INTERVAL_HOURS} Hours)</h2>
    """

    # Add anomaly section if exists
    if not anomalies.empty:
        html_content += f"""
        <h3>⚠️ Process Anomalies ({len(anomalies)})</h3>
        <ul>
            {''.join(f"<li>{row['Command']} (User: {row['User']}, Score: {row['Anomaly_Score']:.2f})</li>" 
            for _, row in anomalies.iterrows())}
        </ul>
        """

    # Add network threats if exists
    if not network_threats.empty:
        html_content += f"""
        <h3>🌐 Network Threats ({len(network_threats)})</h3>
        <table border="1">
            <tr><th>Source IP</th><th>Destination</th><th>Threat Score</th></tr>
            {''.join(
                f"<tr><td>{row['src_ip']}</td><td>{row['dst_ip']}:{row['dst_port']}</td><td>{row['threat_score']}</td></tr>"
                for _, row in network_threats.iterrows()
            )}
        </table>
        """

    html_content += """
            <p><em>Generated at: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</em></p>
        </body>
    </html>
    """

    alert_email.attach(MIMEText(html_content, 'html'))
    return send_email(alert_email)

def detect_data_exfiltration(network_df):
    """Enhanced exfiltration detection with behavioral analysis"""
    # Calculate byte transfer rates
    network_df['transfer_rate'] = network_df['bytes_sent'] / (network_df['duration'] + 0.001)
    
    # Detect large transfers to external IPs
    external_mask = ~network_df['dst_ip'].str.startswith(('10.', '192.168.', '172.'), na=False)
    large_transfer_mask = network_df['bytes_sent'] > 1024 * 1024  # 1MB threshold
    
    # Detect periodic transfers (potential beaconing)
    network_df = network_df.sort_values('timestamp')
    network_df['time_diff'] = network_df.groupby(['src_ip', 'dst_ip'])['timestamp'].diff().dt.total_seconds()
    periodic_mask = (network_df['time_diff'] > 0) & (network_df['time_diff'] <= 3600)  # Hourly or more frequent
    
    network_df['exfil_risk'] = (
        (external_mask & large_transfer_mask) |
        (external_mask & periodic_mask)
    ).astype(int)
    
    return network_df

def detect_port_scanning(network_df):
    """Port scanning detection with robust datetime handling"""
    # Initialize default columns if missing
    if 'timestamp' not in network_df.columns:
        network_df['timestamp'] = pd.to_datetime('now')
    if 'src_ip' not in network_df.columns:
        network_df['src_ip'] = '0.0.0.0'
    if 'dst_ip' not in network_df.columns:
        network_df['dst_ip'] = '0.0.0.0'
    if 'dst_port' not in network_df.columns:
        network_df['dst_port'] = -1
    
    # Ensure timestamp is datetime type
    network_df['timestamp'] = pd.to_datetime(network_df['timestamp'], errors='coerce')
    
    # Filter out invalid timestamps
    network_df = network_df[network_df['timestamp'].notna()]
    
    if network_df.empty:
        network_df['scan_risk'] = 0
        return network_df
    
    # Calculate scan statistics
    port_scan_stats = network_df.groupby(['src_ip', 'dst_ip']).agg({
        'dst_port': 'nunique',
        'timestamp': ['min', 'max']
    }).reset_index()
    
    # Flatten multi-index columns
    port_scan_stats.columns = [
        'src_ip', 'dst_ip', 'unique_ports', 
        'first_attempt', 'last_attempt'
    ]
    
    # Calculate scan duration in seconds
    port_scan_stats['scan_duration'] = (
        port_scan_stats['last_attempt'] - port_scan_stats['first_attempt']
    ).dt.total_seconds()
    
    # Detect scanning patterns
    scan_threshold = 20  # Number of unique ports to trigger alert
    port_scan_stats['is_scan'] = (
        (port_scan_stats['unique_ports'] >= scan_threshold) |
        (
            (port_scan_stats['unique_ports'] >= 10) & 
            (port_scan_stats['scan_duration'] <= 300)  # 5 minute window
        )
    )
    
    # Merge results back to original dataframe
    network_df = network_df.merge(
        port_scan_stats[['src_ip', 'dst_ip', 'is_scan']],
        on=['src_ip', 'dst_ip'],
        how='left'
    )
    
    # Convert to risk flag (0 or 1)
    network_df['scan_risk'] = network_df['is_scan'].fillna(0).astype(int)
    return network_df

def detect_c2_communication(network_df):
    """Detect potential Command & Control patterns"""
    suspicious_ports = [4444, 8080, 53, 1337, 8443]
    
    # Initialize default columns if missing
    if 'dst_port' not in network_df.columns:
        network_df['dst_port'] = -1
    
    if 'dst_ip' not in network_df.columns:
        network_df['dst_ip'] = ''
    
    # Basic port-based detection
    port_mask = network_df['dst_port'].isin(suspicious_ports)
    
    # Domain pattern detection (if applicable)
    suspicious_domains = ['pastebin.com', 'github.io']
    domain_mask = network_df['dst_ip'].str.contains(
        '|'.join(suspicious_domains), 
        case=False, 
        na=False
    )
    
    network_df['c2_risk'] = (port_mask | domain_mask).astype(int)
    return network_df

def detect_data_exfiltration(network_df):
    """Detect potential data exfiltration attempts"""
    # Initialize default columns if missing
    if 'bytes_sent' not in network_df.columns:
        network_df['bytes_sent'] = 0  # Default to 0 if column doesn't exist
    
    if 'duration' not in network_df.columns:
        network_df['duration'] = 1  # Default to 1 second if column doesn't exist
    
    # Calculate transfer rate safely
    network_df['transfer_rate'] = network_df['bytes_sent'] / (network_df['duration'] + 0.001)
    
    # Detect external IPs (if dst_ip exists)
    if 'dst_ip' in network_df.columns:
        external_mask = ~network_df['dst_ip'].str.startswith(('10.', '192.168.', '172.'), na=False)
    else:
        external_mask = False  # If no dst_ip column, assume internal
    
    # Detect large transfers (adjust threshold as needed)
    large_transfer_mask = network_df['bytes_sent'] > 1024 * 1024  # 1MB threshold
    
    network_df['exfil_risk'] = (external_mask & large_transfer_mask).astype(int)
    return network_df

def analyze_network_behavior(process_df, network_df):
    """Safe network behavior analysis with missing column handling"""
    # Initialize default columns in network data
    default_columns = {
        'bytes_sent': 0,
        'dst_port': -1,
        'dst_ip': '0.0.0.0',
        'src_ip': '0.0.0.0'
    }
    
    for col, default in default_columns.items():
        if col not in network_df.columns:
            network_df[col] = default
    
    # Convert timestamps safely
    for df in [process_df, network_df]:
        if 'Timestamp' in df.columns:
            df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    
    # Create time windows
    time_col = 'Timestamp' if 'Timestamp' in process_df.columns else 'timestamp'
    process_df['time_window'] = process_df[time_col].dt.floor('5min')
    network_df['time_window'] = network_df['timestamp'].dt.floor('5min')
    
    # Safe aggregation
    agg_params = {
        'bytes_sent': 'sum',
        'dst_port': 'nunique',
        'dst_ip': 'nunique'
    }
    
    # Add risk columns if they exist
    for risk_col in ['c2_risk', 'exfil_risk']:
        if risk_col in network_df.columns:
            agg_params[risk_col] = 'max'
    
    network_stats = network_df.groupby(['time_window', 'src_ip']).agg(agg_params).reset_index()
    
    # Safe merging
    merge_on = ['time_window']
    if 'SourceIP' in process_df.columns and 'src_ip' in network_stats.columns:
        merge_on.append('SourceIP')
    
    merged_df = pd.merge(
        process_df,
        network_stats,
        left_on=merge_on,
        right_on=['time_window', 'src_ip'] if 'src_ip' in merge_on else ['time_window'],
        how='left'
    )
    
    return merged_df

def get_db_connection():
    """Create and return a database connection"""
    return sqlite3.connect(DB_PATH, timeout=10)

def fetch_process_data(hours=24):
    """Fetch process data from the database for the last N hours"""
    conn = get_db_connection()
    query = f"""
    SELECT * FROM process_monitoring 
    WHERE datetime(Timestamp) >= datetime('now', '-{hours} hours')
    ORDER BY Timestamp DESC
    """
    df = pd.read_sql(query, conn)
    conn.close()
    return df

def fetch_network_data(hours=24):
    """Fetch network data from the database for the last N hours"""
    conn = get_db_connection()
    query = f"""
    SELECT * FROM network_events 
    WHERE datetime(timestamp) >= datetime('now', '-{hours} hours')
    ORDER BY timestamp DESC
    """
    df = pd.read_sql(query, conn)
    conn.close()
    return df

def fetch_suspicious_commands(hours=24):
    """Fetch suspicious commands from the database"""
    conn = get_db_connection()
    query = f"""
    SELECT * FROM suspicious_commands 
    WHERE datetime(timestamp) >= datetime('now', '-{hours} hours')
    ORDER BY timestamp DESC
    """
    df = pd.read_sql(query, conn)
    conn.close()
    return df

# Feature Engineering Functions
def preprocess_process_data(df):
    """Preprocess the process monitoring data"""
    # Convert timestamp to datetime
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    
    # Extract time features
    df['Hour'] = df['Timestamp'].dt.hour
    df['Minute'] = df['Timestamp'].dt.minute
    df['DayOfWeek'] = df['Timestamp'].dt.dayofweek
    
    # Convert time used to seconds
    df['Time_Used_Seconds'] = df['Time_Used'].apply(
        lambda x: int(x.split(':')[0]) * 60 + float(x.split(':')[1]) if isinstance(x, str) else 0)
    
    # Calculate memory ratios
    df['MEM_RATIO'] = df['RES'] / (df['VIRT'] + 1e-6)  # Avoid division by zero
    
    return df

def encode_features(df, categorical_cols=['User', 'Command', 'S', 'Hashed_Command']):
    """Encode categorical features with handling for new labels"""
    if os.path.exists(ENCODER_FILE):
        encoders = joblib.load(ENCODER_FILE)
    else:
        encoders = {col: LabelEncoder().fit(df[col]) for col in categorical_cols}
        joblib.dump(encoders, ENCODER_FILE)
    
    for col in categorical_cols:
        if col in df.columns:
            # Handle unseen labels by assigning a default value
            known_labels = set(encoders[col].classes_)
            current_labels = set(df[col].unique())
            new_labels = current_labels - known_labels
            
            if len(new_labels) > 0:
                # Assign -1 to new labels
                df[col + '_encoded'] = df[col].apply(
                    lambda x: encoders[col].transform([x])[0] if x in known_labels else -1
                )
            else:
                df[col + '_encoded'] = encoders[col].transform(df[col])
    
    return df, encoders

def normalize_features(df, numeric_cols=['CPU', 'Memory', 'VIRT', 'RES', 'SHR', 'Time_Used_Seconds']):
    """Normalize numeric features"""
    # Initialize or load scaler
    if os.path.exists(SCALER_FILE):
        scaler = joblib.load(SCALER_FILE)
    else:
        scaler = StandardScaler().fit(df[numeric_cols])
        joblib.dump(scaler, SCALER_FILE)
    
    # Apply scaling
    df[numeric_cols] = scaler.transform(df[numeric_cols])
    return df, scaler

def extract_behavior_features(df, window_size=5):
    """Extract behavior features from process data"""
    df = df.sort_values('Timestamp')
    
    # Calculate rolling statistics
    for col in ['CPU', 'Memory', 'Time_Used_Seconds']:
        df[f'{col}_rolling_mean'] = df.groupby('User')[col].transform(
            lambda x: x.rolling(window=window_size, min_periods=1).mean())
        df[f'{col}_rolling_std'] = df.groupby('User')[col].transform(
            lambda x: x.rolling(window=window_size, min_periods=1).std())
    
    # Command frequency
    command_counts = df['Hashed_Command'].value_counts().to_dict()
    df['Command_Frequency'] = df['Hashed_Command'].map(command_counts)
    
    return df

def prepare_features(df):
    """Prepare final feature set for modeling"""
    feature_cols = [
        'CPU', 'Memory', 'VIRT', 'RES', 'SHR', 'Time_Used_Seconds', 'MEM_RATIO',
        'Hour', 'Minute', 'DayOfWeek', 'Command_Frequency',
        'CPU_rolling_mean', 'CPU_rolling_std',
        'Memory_rolling_mean', 'Memory_rolling_std',
        'Time_Used_Seconds_rolling_mean', 'Time_Used_Seconds_rolling_std',
        'User_encoded', 'Command_encoded', 'S_encoded', 'Hashed_Command_encoded'
    ]
    
    # Ensure we only include columns that exist in the dataframe
    available_cols = [col for col in feature_cols if col in df.columns]
    return df[available_cols]

# Model Functions
def train_model(X_train):
    """Train the anomaly detection model"""
    model = IsolationForest(
        n_estimators=150,
        max_samples='auto',
        contamination=0.05,
        max_features=1.0,
        random_state=42,
        verbose=1
    )
    model.fit(X_train)
    joblib.dump(model, MODEL_FILE)
    return model

def load_or_train_model(X_train):
    """Load existing model or train a new one"""
    if os.path.exists(MODEL_FILE):
        model = joblib.load(MODEL_FILE)
    else:
        model = train_model(X_train)
    return model

def predict_anomalies(model, X):
    """Predict anomalies using the trained model"""
    scores = model.decision_function(X)
    predictions = model.predict(X)
    return scores, predictions

# Correlation Functions
def correlate_process_with_network(process_df, network_df):
    """Correlate process data with network events with proper timestamp handling"""
    # Ensure timestamp columns are datetime type
    process_df['Timestamp'] = pd.to_datetime(process_df['Timestamp'])
    network_df['timestamp'] = pd.to_datetime(network_df['timestamp'])
    
    correlated_data = []
    for _, process_row in process_df.iterrows():
        time_window = (
            process_row['Timestamp'] - pd.Timedelta(minutes=5),
            process_row['Timestamp'] + pd.Timedelta(minutes=5)
        )
        
        # Filter network events within the time window
        mask = (
            (network_df['timestamp'] >= time_window[0]) & 
            (network_df['timestamp'] <= time_window[1]) &
            (network_df['src_port'] == process_row['PID'])
        )
        matching_network = network_df[mask]
        
        if not matching_network.empty:
            for _, network_row in matching_network.iterrows():
                combined_row = {**process_row.to_dict(), **network_row.to_dict()}
                correlated_data.append(combined_row)
    
    return pd.DataFrame(correlated_data)

def retrain_model():
    """Retrain the anomaly detection model with recent data"""
    # Load recent data (last 7 days for robust training)
    process_data = fetch_process_data(hours=168)  # 168 hours = 7 days
    if process_data.empty:
        raise ValueError("No data available for training")
    
    # Preprocess data
    process_data = preprocess_process_data(process_data)
    process_data = extract_behavior_features(process_data)
    process_data, _ = encode_features(process_data)
    process_data, _ = normalize_features(process_data)
    
    # Prepare features
    X = prepare_features(process_data)
    
    # Train new model
    model = IsolationForest(
        n_estimators=150,
        max_samples='auto',
        contamination=0.05,
        max_features=1.0,
        random_state=42,
        verbose=1
    )
    model.fit(X)
    
    # Save the new model
    joblib.dump(model, MODEL_FILE)
    return model

# Main Analysis Function
def analyze_processes():
    """Main function to load data, analyze, and display results"""
    # Load data from database
    st.write("📡 Loading data from database...")
    process_data = fetch_process_data()
    network_data = fetch_network_data()
    suspicious_commands = fetch_suspicious_commands()
    
    if process_data.empty:
        st.error("No process data found in the database!")
        return
    
    # Preprocess and feature engineering
    st.write("🔧 Preprocessing data...")
    process_data = preprocess_process_data(process_data)
    process_data = extract_behavior_features(process_data)
    process_data, _ = encode_features(process_data)
    process_data, _ = normalize_features(process_data)
    
    # Prepare features for model
    X = prepare_features(process_data)
    
    # Load or train model
    st.write("🤖 Loading anomaly detection model...")
    model = load_or_train_model(X)
    
    # Predict anomalies
    st.write("🔍 Detecting anomalies...")
    scores, predictions = predict_anomalies(model, X)
    
    # Add results to dataframe
    process_data['Anomaly_Score'] = scores
    process_data['Is_Anomaly'] = predictions
    
    # Get anomalies (where prediction == -1)
    anomalies = process_data[process_data['Is_Anomaly'] == -1]
def safe_plot_scatter(df):
    required_columns = ['Timestamp', 'Command', 'src_ip']
    if not all(col in df.columns for col in required_columns):
        st.error("Missing required columns for visualization")
        return None
        
    size_options = ['Bytes_Sent', 'CPU', 'Memory', 'Time_Used_Seconds']
    size_col = next((col for col in size_options if col in df.columns), None)
    
    return px.scatter(
        df,
        x='Timestamp',
        y='Command',
        color='src_ip',
        size=size_col,
        hover_data=['dst_ip', 'dst_port', 'PID'],
        title="Process-Network Connections"
    )

load_dotenv()

# Email Configuration
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECIPIENT = "manas.dfis242604@nfsu.ac.in"

# SSH Config
SSH_USERNAME = os.getenv("SSH_USERNAME")
SSH_PASSWORD = os.getenv("SSH_PASSWORD")
UBUNTU_IP = os.getenv("UBUNTU_IP")
SSH_KEY_PATH = None

# Threat Intelligence Sources (no API keys needed)
THREAT_INTEL_SOURCES = {
    "AbuseIPDB": "https://www.abuseipdb.com/check/",
    "VirusTotal": "https://www.virustotal.com/gui/ip-address/",
    "GreyNoise": "https://viz.greynoise.io/ip/",
    "Shodan": "https://www.shodan.io/host/",
    "Talos": "https://talosintelligence.com/reputation_center/lookup?search="
}

# Whitelisted processes (command patterns that shouldn't trigger alerts)
WHITELISTED_PROCESSES = [
    "python3 /tst.py",  # Whitelist this specific command
    "python3 /script.py",  # Whitelist this specific command
    "python3",  # General Python interpreter
    "bash",  # Bourne-again shell
    "systemd",  # System service manager
    "sshd",  # SSH daemon
    "nginx",  # Web server
    "apache2"  # Web server
]

# =============================================
# REPORT GENERATION FUNCTIONS
# =============================================
def generate_report():
    """Generate a comprehensive security report with all data and graphs"""
    report = MIMEMultipart()
    report['Subject'] = f"Security Dashboard Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    report['From'] = EMAIL_SENDER
    report['To'] = EMAIL_RECIPIENT

    # Create HTML content for the report
    html_content = f"""
    <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #2e6c80; }}
                h2 {{ color: #3e7c90; margin-top: 30px; border-bottom: 1px solid #eee; padding-bottom: 5px; }}
                .metric {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; margin-bottom: 15px; }}
                .section {{ margin-bottom: 30px; }}
                .graph {{ margin: 20px 0; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .critical {{ color: #d9534f; font-weight: bold; }}
                .high {{ color: #f0ad4e; font-weight: bold; }}
                .medium {{ color: #5bc0de; font-weight: bold; }}
                .low {{ color: #5cb85c; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>Security Dashboard Report</h1>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    """

    # 1. Process Monitoring Section
    process_df = load_data("process_monitoring")
    if not process_df.empty:
        ts_col = "Timestamp" if "Timestamp" in process_df.columns else "timestamp"
        
        html_content += f"""
        <div class="section">
            <h2>Process Monitoring</h2>
            <div class="metric">
                <strong>Total Processes:</strong> {process_df.shape[0]}<br>
                <strong>Average CPU Usage:</strong> {process_df['CPU'].mean():.2f}%<br>
                <strong>Average Memory Usage:</strong> {process_df['Memory'].mean():.2f} MB
            </div>
        """

        # Add CPU and Memory graphs
        fig_cpu = px.line(process_df, x=ts_col, y="CPU", title="CPU Usage Over Time")
        fig_mem = px.line(process_df, x=ts_col, y="Memory", title="Memory Usage Over Time")
        
        cpu_img = plotly_fig_to_png(fig_cpu)
        mem_img = plotly_fig_to_png(fig_mem)
        
        html_content += """
            <div class="graph">
                <h3>CPU Usage</h3>
                <img src="cid:cpu_graph">
            </div>
            <div class="graph">
                <h3>Memory Usage</h3>
                <img src="cid:mem_graph">
            </div>
        </div>
        """
        
        # Attach the graphs
        cpu_attachment = MIMEApplication(cpu_img, _subtype="png")
        cpu_attachment.add_header('Content-ID', '<cpu_graph>')
        report.attach(cpu_attachment)
        
        mem_attachment = MIMEApplication(mem_img, _subtype="png")
        mem_attachment.add_header('Content-ID', '<mem_graph>')
        report.attach(mem_attachment)

    # 2. Network Events Section
    network_df = load_data("network_events")
    if not network_df.empty:
        network_df["threat_score"] = network_df.apply(calculate_threat_score, axis=1)
        network_df["flag_analysis"] = network_df["flags"].apply(analyze_tcp_flags)
        
        port_access = network_df[network_df['dst_ip'] == MY_IP].groupby(['src_ip','dst_port']).size().reset_index(name='count')
        port_access = port_access[port_access['count'] >= SCAN_THRESHOLD]
        
        floods = network_df[network_df['flags'] == 'S'].groupby(['src_ip','dst_ip']).size().reset_index(name='count')
        floods = floods[(floods['count'] >= FLOOD_THRESHOLD) & (floods['dst_ip'] == MY_IP)]
        
        inbound = network_df[network_df['dst_ip'] == MY_IP].groupby('src_ip').size().reset_index(name='count')
        outbound = network_df[network_df['src_ip'] == MY_IP].groupby('dst_ip').size().reset_index(name='count')
        
        html_content += f"""
        <div class="section">
            <h2>Network Traffic Analysis</h2>
            <div class="metric">
                <strong>Total Events:</strong> {network_df.shape[0]}<br>
                <strong>Unique IPs:</strong> {network_df["src_ip"].nunique()}<br>
                <strong>Multiple Port Accesses:</strong> {len(port_access)}<br>
                <strong>Potential Floods:</strong> {len(floods)}
            </div>
        """
        
        # Add network graphs
        if not inbound.empty:
            fig_inbound = px.bar(inbound.nlargest(5, 'count'), x='src_ip', y='count', title="Top Inbound IPs")
            inbound_img = plotly_fig_to_png(fig_inbound)
            html_content += """
                <div class="graph">
                    <h3>Top Inbound IPs</h3>
                    <img src="cid:inbound_graph">
                </div>
            """
            inbound_attachment = MIMEApplication(inbound_img, _subtype="png")
            inbound_attachment.add_header('Content-ID', '<inbound_graph>')
            report.attach(inbound_attachment)
            
        if not outbound.empty:
            fig_outbound = px.bar(outbound.nlargest(5, 'count'), x='dst_ip', y='count', title="Top Outbound IPs")
            outbound_img = plotly_fig_to_png(fig_outbound)
            html_content += """
                <div class="graph">
                    <h3>Top Outbound IPs</h3>
                    <img src="cid:outbound_graph">
                </div>
            """
            outbound_attachment = MIMEApplication(outbound_img, _subtype="png")
            outbound_attachment.add_header('Content-ID', '<outbound_graph>')
            report.attach(outbound_attachment)
            
        html_content += "</div>"

    # 3. Suspicious Commands Section
    suspicious_df = load_data("suspicious_commands")
    if not suspicious_df.empty:
        suspicious_df["threat_score"] = suspicious_df.apply(calculate_threat_score, axis=1)
        high_threat = len(suspicious_df[suspicious_df["threat_score"] > 70])
        
        html_content += f"""
        <div class="section">
            <h2>Suspicious Commands</h2>
            <div class="metric">
                <strong>Total Commands:</strong> {suspicious_df.shape[0]}<br>
                <strong>High Threat Commands:</strong> {high_threat}
            </div>
        """
        
        # Add top commands graph
        top_cmds = suspicious_df['command'].value_counts().head(5).reset_index()
        top_cmds.columns = ['Command', 'Count']
        fig_commands = px.bar(top_cmds, x='Command', y='Count', title="Top Suspicious Commands")
        commands_img = plotly_fig_to_png(fig_commands)
        html_content += """
            <div class="graph">
                <h3>Top Suspicious Commands</h3>
                <img src="cid:commands_graph">
            </div>
        </div>
        """
        commands_attachment = MIMEApplication(commands_img, _subtype="png")
        commands_attachment.add_header('Content-ID', '<commands_graph>')
        report.attach(commands_attachment)

    # 4. Incident Detection Section
    process_df = load_data("process_monitoring")
    incidents = detect_incidents(network_df, process_df)
    
    if incidents:
        incidents_df = pd.DataFrame(incidents)
        severity_counts = incidents_df['severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        
        html_content += f"""
        <div class="section">
            <h2>Security Incidents</h2>
            <div class="metric">
                <strong>Total Incidents Detected:</strong> {len(incidents)}
            </div>
        """
        
        # Add incidents by severity graph
        fig_severity = px.bar(severity_counts, x='Severity', y='Count', title="Incidents by Severity")
        severity_img = plotly_fig_to_png(fig_severity)
        html_content += """
            <div class="graph">
                <h3>Incidents by Severity</h3>
                <img src="cid:severity_graph">
            </div>
        """
        severity_attachment = MIMEApplication(severity_img, _subtype="png")
        severity_attachment.add_header('Content-ID', '<severity_graph>')
        report.attach(severity_attachment)
        
        # Add incidents table
        html_content += """
            <h3>Incident Details</h3>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Timestamp</th>
                </tr>
        """
        
        for _, row in incidents_df.sort_values(['severity', 'timestamp'], ascending=[False, False]).iterrows():
            severity_class = row['severity'].lower()
            html_content += f"""
                <tr>
                    <td>{row['type']}</td>
                    <td>{row['source']}</td>
                    <td class="{severity_class}">{row['severity']}</td>
                    <td>{row['description']}</td>
                    <td>{row['timestamp']}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </div>
        """
    else:
        html_content += """
        <div class="section">
            <h2>Security Incidents</h2>
            <p>No security incidents detected during this period.</p>
        </div>
        """

    # 5. Threat Intelligence Summary
    all_ips = get_all_ips()
    if all_ips:
        html_content += f"""
        <div class="section">
            <h2>Threat Intelligence Summary</h2>
            <p><strong>Unique IPs Detected:</strong> {len(all_ips)}</p>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Country</th>
                    <th>ISP</th>
                    <th>Threat Score</th>
                </tr>
        """
        
        # Sample the first 5 IPs for the report (to keep it manageable)
        for ip in all_ips[:5]:
            ip_info = get_ip_reputation(ip)
            if "error" not in ip_info:
                html_content += f"""
                <tr>
                    <td>{ip}</td>
                    <td>{ip_info.get('country', 'Unknown')}</td>
                    <td>{ip_info.get('isp', 'Unknown')}</td>
                    <td>{ip_info.get('threat_score', 0)}</td>
                </tr>
                """
        
        html_content += """
            </table>
            <p><em>Note: Showing first 5 IPs. Full list available in the dashboard.</em></p>
        </div>
        """

    # Close HTML content
    html_content += """
        </body>
    </html>
    """
    
    # Attach HTML content
    report.attach(MIMEText(html_content, 'html'))
    
    return report

def plotly_fig_to_png(fig):
    """Convert a Plotly figure to PNG bytes"""
    img_bytes = fig.to_image(format="png")
    return img_bytes

def send_email(report):
    """Send the generated report via email"""
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(report)
        return True
    except Exception as e:
        st.error(f"Failed to send email: {str(e)}")
        return False

# =============================================
# CORE FUNCTIONS (remain the same as before)
# =============================================
@st.cache_data(ttl=10)
def load_data(table_name):
    if not check_table_exists(table_name):
        return pd.DataFrame()
   
    conn = sqlite3.connect(DB_PATH)
    columns = pd.read_sql_query(f"PRAGMA table_info({table_name})", conn)["name"].tolist()
    timestamp_col = "Timestamp" if "Timestamp" in columns else "timestamp"
   
    query = f"SELECT * FROM {table_name} ORDER BY {timestamp_col} DESC LIMIT 1000"
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    # Convert timestamp if exists
    if timestamp_col in df.columns:
        df[timestamp_col] = pd.to_datetime(df[timestamp_col])
    
    return df

@st.cache_data(ttl=10)
def load_data(table_name):
    """Load data from SQLite database"""
    if not check_table_exists(table_name):
        return pd.DataFrame()
   
    conn = sqlite3.connect(DB_PATH)
    columns = pd.read_sql_query(f"PRAGMA table_info({table_name})", conn)["name"].tolist()
    timestamp_col = "Timestamp" if "Timestamp" in columns else "timestamp"
   
    query = f"SELECT * FROM {table_name} ORDER BY {timestamp_col} DESC LIMIT 1000"
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    if timestamp_col in df.columns:
        df[timestamp_col] = pd.to_datetime(df[timestamp_col])
    
    return df

def check_table_exists(table_name):
    """Check if a table exists in the database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table_name,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def test_ssh_connection():
    """Test SSH connection to Ubuntu server"""
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if SSH_KEY_PATH:
            private_key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)
            ssh.connect(UBUNTU_IP, username=SSH_USERNAME, pkey=private_key, timeout=5)
        else:
            ssh.connect(UBUNTU_IP, username=SSH_USERNAME, password=SSH_PASSWORD, timeout=5)
        
        return True, "SSH connection successful"
    except Exception as e:
        return False, f"SSH Connection Error: {str(e)}"
    finally:
        if ssh:
            ssh.close()

def get_ubuntu_processes():
    """Get running processes from Ubuntu server via SSH with improved error handling"""
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if SSH_KEY_PATH:
            private_key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)
            ssh.connect(UBUNTU_IP, username=SSH_USERNAME, pkey=private_key, timeout=5)
        else:
            ssh.connect(UBUNTU_IP, username=SSH_USERNAME, password=SSH_PASSWORD, timeout=5)
        
        stdin, stdout, stderr = ssh.exec_command(
            "ps -eo pid,user,%cpu,%mem,cmd --sort=-%cpu | head -n 11",
            timeout=10
        )
        
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error = stderr.read().decode()
            st.error(f"Command failed with status {exit_status}: {error}")
            return []
        
        processes = stdout.read().decode().split('\n')[1:]
        return [p.strip().split(None, 4) for p in processes if p.strip()]
    except Exception as e:
        st.error(f"Error getting processes: {str(e)}")
        return []
    finally:
        if ssh:
            ssh.close()

def is_whitelisted_process(command):
    """Check if a process command matches any whitelisted pattern"""
    if not command:
        return False
    command = str(command).strip()
    return any(whitelist in command for whitelist in WHITELISTED_PROCESSES)

def kill_ubuntu_process(pid):
    """Kill a process on Ubuntu server via SSH with better error handling"""
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if SSH_KEY_PATH:
            private_key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)
            ssh.connect(UBUNTU_IP, username=SSH_USERNAME, pkey=private_key, timeout=5)
        else:
            ssh.connect(UBUNTU_IP, username=SSH_USERNAME, password=SSH_PASSWORD, timeout=5)
        
        stdin, stdout, stderr = ssh.exec_command(f"kill -9 {pid}", timeout=5)
        exit_status = stdout.channel.recv_exit_status()
        return exit_status == 0
    except Exception as e:
        st.error(f"Error killing process: {str(e)}")
        return False
    finally:
        if ssh:
            ssh.close()

def auto_kill_high_cpu_processes():
    """Automatically kill processes exceeding CPU threshold"""
    processes = get_ubuntu_processes()
    if not processes:
        return 0
    
    killed_count = 0
    for proc in processes:
        try:
            pid = proc[0]
            cpu_usage = float(proc[2])
            command = proc[4]
            
            if is_whitelisted_process(command):
                continue
                
            if cpu_usage > AUTO_KILL_CPU_THRESHOLD:
                if kill_ubuntu_process(pid):
                    killed_count += 1
                    st.toast(f"Automatically killed process {pid} (CPU: {cpu_usage}%, Command: {command[:50]}...)")
                else:
                    st.toast(f"Failed to automatically kill process {pid}", icon="⚠️")
        except Exception as e:
            st.error(f"Error processing PID {pid}: {str(e)}")
            continue
    
    return killed_count

def auto_kill_high_mem_processes():
    """Automatically kill processes exceeding MEMORY threshold"""
    processes = get_ubuntu_processes()
    if not processes:
        return 0
    
    killed_count = 0
    for proc in processes:
        try:
            pid = proc[0]
            mem_usage = float(proc[3])
            command = proc[4]
            
            if is_whitelisted_process(command):
                continue
                
            if mem_usage > AUTO_KILL_MEM_THRESHOLD:
                if kill_ubuntu_process(pid):
                    killed_count += 1
                    st.toast(f"Automatically killed process {pid} (Memory: {mem_usage}%, Command: {command[:50]}...)")
                else:
                    st.toast(f"Failed to automatically kill process {pid}", icon="⚠️")
        except Exception as e:
            st.error(f"Error processing PID {pid}: {str(e)}")
            continue
    
    return killed_count

def calculate_threat_score(row):
    score = 0
    if "type" in row:
        if "bruteforce" in str(row["type"]).lower(): score += 70
        if "scan" in str(row["type"]).lower(): score += 50
        if "ddos" in str(row["type"]).lower(): score += 90
    if "command" in row:
        keywords = ["rm -rf", "chmod 777", "wget", "curl", "nc ", "nmap", "sshpass"]
        score += sum(60 for kw in keywords if kw in str(row["command"]).lower())
    if "CPU" in row and "Memory" in row:
        if row["CPU"] > 90 and row["Memory"] > 90: score += 40
    return min(score, 100)

def get_ubuntu_processes():
    """Get running processes from Ubuntu server via SSH"""
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if SSH_KEY_PATH:
            private_key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)
            ssh.connect(UBUNTU_IP, username=SSH_USERNAME, pkey=private_key)
        else:
            ssh.connect(UBUNTU_IP, username=SSH_USERNAME, password=SSH_PASSWORD)
        
        stdin, stdout, stderr = ssh.exec_command(
            "ps -eo pid,user,%cpu,%mem,cmd --sort=-%cpu | head -n 11"
        )
        processes = stdout.read().decode().split('\n')[1:]  # Skip header
        return [p.strip().split(None, 4) for p in processes if p.strip()]
    except Exception as e:
        st.error(f"SSH Connection Error: {str(e)}")
        return []
    finally:
        if ssh:
            ssh.close()

def is_whitelisted_process(command):
    """Check if a process command matches any whitelisted pattern"""
    if not command:
        return False
    command = str(command).strip()
    return any(whitelist in command for whitelist in WHITELISTED_PROCESSES)

def kill_ubuntu_process(pid):
    """Kill a process on Ubuntu server via SSH"""
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if SSH_KEY_PATH:
            private_key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)
            ssh.connect(UBUNTU_IP, username=SSH_USERNAME, pkey=private_key)
        else:
            ssh.connect(UBUNTU_IP, username=SSH_USERNAME, password=SSH_PASSWORD)
        
        stdin, stdout, stderr = ssh.exec_command(f"sudo kill -9 {pid}")
        exit_status = stdout.channel.recv_exit_status()
        return exit_status == 0
    except Exception as e:
        st.error(f"Error killing process: {str(e)}")
        return False
    finally:
        if ssh:
            ssh.close()

def auto_kill_high_cpu_processes():
    """Automatically kill processes exceeding CPU threshold (excluding whitelisted processes)"""
    processes = get_ubuntu_processes()
    if not processes:
        return 0
    
    killed_count = 0
    for proc in processes:
        try:
            pid = proc[0]
            cpu_usage = float(proc[2])
            command = proc[4]
            
            # Skip whitelisted processes and our specific excluded processes
            if is_whitelisted_process(command) or any(excluded in command for excluded in ["/tst.py", "/script.py"]):
                continue
                
            # Kill process if it exceeds the threshold
            if cpu_usage > AUTO_KILL_CPU_THRESHOLD:
                if kill_ubuntu_process(pid):
                    killed_count += 1
                    st.toast(f"Automatically killed process {pid} (CPU: {cpu_usage}%, Command: {command[:50]}...)")
                else:
                    st.toast(f"Failed to automatically kill process {pid}", icon="⚠️")
        except Exception as e:
            st.error(f"Error processing PID {pid}: {str(e)}")
            continue
    
    return killed_count

def analyze_tcp_flags(flags):
    """Enhanced TCP flag analysis with explanations"""
    if not flags or flags == "None":
        return "No flags"
    
    flags = str(flags).upper()
    explanations = {
        "S": "SYN (Connection initiation)",
        "SA": "SYN-ACK (Connection established)",
        "FA": "FIN-ACK (Graceful termination)",
        "RA": "RST-ACK (Abrupt termination)",
        "PA": "PSH-ACK (Data transmission)",
        "F": "FIN (Connection termination)",
        "A": "ACK (Acknowledgement)",
        "R": "RST (Reset connection)",
        "P": "PSH (Push data)",
        "U": "URG (Urgent pointer)"
    }
    
    # Check for known combinations first
    for combo, meaning in explanations.items():
        if flags == combo:
            return meaning
    
    # Analyze individual flags
    analysis = []
    for flag in flags:
        if flag in explanations:
            analysis.append(explanations[flag])
    
    return " | ".join(analysis) if analysis else f"Uncommon flags: {flags}"

def get_ip_reputation(ip):
    """Get IP reputation from free online sources"""
    if ip == MY_IP:
        return {"status": "Whitelisted", "threat_score": 0}
    
    try:
        ipaddress.ip_address(ip)
    except:
        return {"error": "Invalid IP address"}
    
    result = {
        "ip": ip,
        "country": "Unknown",
        "isp": "Unknown",
        "threat_score": 0,
        "reputation": "Unknown",
        "sources": {}
    }
    
    # Get basic IP info from ip-api.com (no API key needed)
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                result.update({
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "asn": data.get("as", "Unknown")
                })
    except:
        pass
    
    # Add links to threat intelligence sources
    for name, base_url in THREAT_INTEL_SOURCES.items():
        result['sources'][name] = f"{base_url}{ip}"
    
    return result

def get_process_info(process_name):
    """Get information about a process from online sources"""
    if not process_name or pd.isna(process_name):
        return {
            "process": "Unknown",
            "description": "No process information available",
            "risk_level": "Unknown",
            "sources": {}
        }
    
    # Clean the process name
    process_name = str(process_name).split()[0].split('/')[-1]
    
    result = {
        "process": process_name,
        "description": "Unknown",
        "risk_level": "Unknown",
        "sources": {
            "ProcessLibrary": f"https://www.processlibrary.com/en/search/?q={process_name}",
            "File.net": f"https://www.file.net/process/{process_name}.html"
        }
    }
    
    # Known process database
    known_processes = {
        "nmap": "Network scanning tool",
        "hydra": "Password cracking tool",
        "ssh": "Secure shell client",
        "wget": "File download utility",
        "curl": "Data transfer tool",
        "nc": "Netcat network utility",
        "python": "Python interpreter",
        "python3": "Python 3 interpreter",
        "bash": "Bourne-again shell",
        "systemd": "System service manager"
    }
    
    if process_name.lower() in known_processes:
        result["description"] = known_processes[process_name.lower()]
        result["risk_level"] = "High" if process_name.lower() in ["nmap", "hydra"] else "Medium"
    
    return result

def auto_kill_high_mem_processes():
    """Automatically kill processes exceeding MEMORY threshold (excluding whitelisted processes)"""
    processes = get_ubuntu_processes()
    if not processes:
        return 0
    
    killed_count = 0
    for proc in processes:
        try:
            pid = proc[0]
            mem_usage = float(proc[3])  # Memory is at index 3
            command = proc[4]
            
            # Skip whitelisted processes and our specific excluded processes
            if is_whitelisted_process(command) or any(excluded in command for excluded in ["/tst.py", "/script.py"]):
                continue
                
            # Kill process if it exceeds the threshold
            if mem_usage > AUTO_KILL_MEM_THRESHOLD:
                if kill_ubuntu_process(pid):
                    killed_count += 1
                    st.toast(f"Automatically killed process {pid} (Memory: {mem_usage}%, Command: {command[:50]}...)")
                else:
                    st.toast(f"Failed to automatically kill process {pid}", icon="⚠️")
        except Exception as e:
            st.error(f"Error processing PID {pid}: {str(e)}")
            continue
    
    return killed_count

def detect_incidents(network_df, process_df):
    """Detect security incidents from data (Updated for memory focus)"""
    incidents = []
    
    # Network incidents (unchanged)
    if not network_df.empty:
        port_access = network_df[network_df['dst_ip'] == MY_IP]
        port_access = port_access.groupby('src_ip')['dst_port'].nunique().reset_index(name='count')
        port_access = port_access[port_access['count'] >= SCAN_THRESHOLD]
        
        for _, row in port_access.iterrows():
            incidents.append({
                "type": "Multiple Ports Accessed",
                "source": row['src_ip'],
                "severity": "High",
                "description": f"{row['src_ip']} accessed {row['count']} different ports",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        
        syn_floods = network_df[network_df['flags'] == 'S']
        syn_floods = syn_floods[syn_floods['dst_ip'] == MY_IP]
        syn_floods = syn_floods.groupby('src_ip').size().reset_index(name='count')
        syn_floods = syn_floods[syn_floods['count'] >= FLOOD_THRESHOLD]
        
        for _, row in syn_floods.iterrows():
            incidents.append({
                "type": "Possible SYN Flood",
                "source": row['src_ip'],
                "severity": "Critical",
                "description": f"{row['src_ip']} sent {row['count']} SYN packets",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
    
    # Process incidents (updated for memory focus)
    if not process_df.empty:
        cmd_col = 'command' if 'command' in process_df.columns else 'Command' if 'Command' in process_df.columns else None
        
        # High Memory processes (replacing high CPU)
        high_mem = process_df[process_df['Memory'] > HIGH_MEM_THRESHOLD]
        
        if cmd_col:
            high_mem = high_mem[~high_mem[cmd_col].apply(is_whitelisted_process)]
        
        for _, row in high_mem.iterrows():
            cmd = row[cmd_col] if cmd_col else 'Unknown'
            incidents.append({
                "type": "High Memory Process",
                "source": row.get('ProcessName', 'Unknown'),
                "severity": "High",  # Increased severity for memory issues
                "description": f"Process using {row['Memory']}% Memory: {cmd}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        
        # Suspicious commands (unchanged)
        if cmd_col:
            suspicious_keywords = ["nmap", "hydra", "metasploit", "sqlmap", "wget", "curl", "nc ", "sshpass"]
            suspicious_procs = process_df[process_df[cmd_col].str.contains('|'.join(suspicious_keywords), case=False, na=False)]
            suspicious_procs = suspicious_procs[~suspicious_procs[cmd_col].apply(is_whitelisted_process)]
            for _, row in suspicious_procs.iterrows():
                incidents.append({
                    "type": "Suspicious Process",
                    "source": row[cmd_col],
                    "severity": "High",
                    "description": f"Suspicious command detected: {row[cmd_col]}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
    
    return incidents

def get_recent_events_for_ip(ip):
    """Get recent events for a specific IP from the database"""
    if not ip:
        return pd.DataFrame()
    
    conn = sqlite3.connect(DB_PATH)
    
    # Check which tables exist that might contain IP information
    tables = []
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [table[0] for table in cursor.fetchall()]
    
    all_events = []
    
    # Check network_events table
    if "network_events" in tables:
        query = f"""
        SELECT 'network' as source, src_ip as ip, dst_ip, dst_port, flags, timestamp 
        FROM network_events 
        WHERE src_ip = ? OR dst_ip = ?
        ORDER BY timestamp DESC 
        LIMIT 50
        """
        network_events = pd.read_sql_query(query, conn, params=(ip, ip))
        if not network_events.empty:
            all_events.append(network_events)
    
    # Check suspicious_commands table (if it has IP info)
    if "suspicious_commands" in tables:
        # Check if the table has an IP column
        cursor.execute(f"PRAGMA table_info(suspicious_commands)")
        columns = [column[1] for column in cursor.fetchall()]
        if "ip" in columns or "src_ip" in columns:
            ip_column = "ip" if "ip" in columns else "src_ip"
            query = f"""
            SELECT 'suspicious_command' as source, {ip_column} as ip, command, timestamp 
            FROM suspicious_commands 
            WHERE {ip_column} = ?
            ORDER BY timestamp DESC 
            LIMIT 50
            """
            cmd_events = pd.read_sql_query(query, conn, params=(ip,))
            if not cmd_events.empty:
                all_events.append(cmd_events)
    
    conn.close()
    
    if all_events:
        return pd.concat(all_events).sort_values("timestamp", ascending=False)
    return pd.DataFrame()

# Main Analysis Function
def analyze_processes():
    """Main function to load data, analyze, and display results"""
    # Load data from database
    st.write("📡 Loading data from database...")
    process_data = fetch_process_data()
    network_data = fetch_network_data()
    suspicious_commands = fetch_suspicious_commands()
    
    if process_data.empty:
        st.error("No process data found in the database!")
        return
    
    # Preprocess and feature engineering
    st.write("🔧 Preprocessing data...")
    process_data = preprocess_process_data(process_data)
    process_data = extract_behavior_features(process_data)
    process_data, _ = encode_features(process_data)
    process_data, _ = normalize_features(process_data)
    
    # Prepare features for model
    X = prepare_features(process_data)
    
    # Load or train model
    st.write("🤖 Loading anomaly detection model...")
    model = load_or_train_model(X)
    
    # Predict anomalies
    st.write("🔍 Detecting anomalies...")
    scores, predictions = predict_anomalies(model, X)
    
    # Add results to dataframe
    process_data['Anomaly_Score'] = scores
    process_data['Is_Anomaly'] = predictions
    
    # Get anomalies (where prediction == -1)
    anomalies = process_data[process_data['Is_Anomaly'] == -1]

    global LAST_ALERT_SENT
    
    # Check if alert interval has passed
    if LAST_ALERT_SENT is None or (datetime.now() - LAST_ALERT_SENT) >= timedelta(hours=ALERT_INTERVAL_HOURS):
        # Get high-confidence anomalies (threshold adjustable)
        critical_anomalies = anomalies[anomalies['Anomaly_Score'] < -0.8]  # Example threshold
        
        # Get high-risk network events
        network_threats = network_data[network_data['threat_score'] > 80]
        
        if not critical_anomalies.empty or not network_threats.empty:
            if send_alert_email(critical_anomalies, network_threats, suspicious_commands):
                LAST_ALERT_SENT = datetime.now()
                st.toast("Alert email sent successfully!", icon="📧")
    

def get_all_ips():
    """Get all unique IP addresses from network_events and suspicious_commands tables"""
    conn = sqlite3.connect(DB_PATH)
    ips = set()
    
    # Get IPs from network_events
    if check_table_exists("network_events"):
        network_ips = pd.read_sql_query(
            "SELECT DISTINCT src_ip as ip FROM network_events UNION SELECT DISTINCT dst_ip FROM network_events",
            conn
        )
        ips.update(network_ips['ip'].tolist())
    
    # Get IPs from suspicious_commands (if it has IP info)
    if check_table_exists("suspicious_commands"):
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(suspicious_commands)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if "ip" in columns or "src_ip" in columns:
            ip_column = "ip" if "ip" in columns else "src_ip"
            cmd_ips = pd.read_sql_query(
                f"SELECT DISTINCT {ip_column} as ip FROM suspicious_commands",
                conn
            )
            ips.update(cmd_ips['ip'].tolist())
    
    conn.close()
    
    # Remove our own IP and any empty values
    ips.discard(MY_IP)
    ips.discard('')
    ips.discard(None)
    
    return sorted(ips, key=lambda x: ipaddress.ip_address(x) if ipaddress.ip_address(x).version == 4 else ipaddress.ip_address(x))

# =============================================
# STREAMLIT UI
# =============================================
st.set_page_config(page_title="Enhanced SIEM Dashboard", layout="wide")
st.title("🔍 Enhanced SIEM Security Dashboard")

# Add report generation button to sidebar
with st.sidebar:
    st.subheader("Report Generation")
    if st.button("📩 Generate and Send Report"):
        with st.spinner("Generating report and sending email..."):
            report = generate_report()
            if send_email(report):
                st.success("Report successfully generated and sent!")
            else:
                st.error("Failed to send report")

menu = st.sidebar.radio("Select View", [
    "Process Monitoring",
    "Network Events", 
    "Suspicious Commands",
    "Cron Events",
    "Threat Intelligence",
    "Ubuntu Process Manager",
    "AI Process Intelligence",  # New menu option
    ])


# =============================================
# 1. PROCESS MONITORING
if menu == "Process Monitoring":
    st.subheader("🖥️ Process Monitoring")
    df = load_data("process_monitoring")
   
    if not df.empty:
        ts_col = "Timestamp" if "Timestamp" in df.columns else "timestamp"
       
        cols = st.columns(3)
        cols[0].metric("Total Processes", df.shape[0])
        cols[1].metric("Avg CPU", f"{df['CPU'].mean():.2f}%")
        cols[2].metric("Avg Memory", f"{df['Memory'].mean():.2f} MB")
       
        fig_cpu = px.line(df, x=ts_col, y="CPU", title="CPU Usage")
        fig_mem = px.line(df, x=ts_col, y="Memory", title="Memory Usage")
        c1, c2 = st.columns(2)
        c1.plotly_chart(fig_cpu, use_container_width=True)
        c2.plotly_chart(fig_mem, use_container_width=True)
       
        # Enhanced process view with new info
        st.subheader("Process Details")
        # Determine the command column name
        cmd_col = 'command' if 'command' in df.columns else 'Command' if 'Command' in df.columns else None
        if cmd_col:
            df["process_info"] = df[cmd_col].apply(lambda x: get_process_info(x))
            st.dataframe(df, use_container_width=True)
        else:
            st.warning("No command information found in process data")
    else:
        st.warning("No process data found")
# =============================================
# 2. NETWORK EVENTS
# =============================================
elif menu == "Network Events":
    st.subheader("🌐 Network Traffic Analysis")
    df = load_data("network_events")
   
    if not df.empty:
        df["threat_score"] = df.apply(calculate_threat_score, axis=1)
        df["flag_analysis"] = df["flags"].apply(analyze_tcp_flags)  # New flag analysis
       
        # Multiple ports accessed (replacing port scanning)
        port_access = df[df['dst_ip'] == MY_IP].groupby(['src_ip','dst_port']).size().reset_index(name='count')
        port_access = port_access[port_access['count'] >= SCAN_THRESHOLD]
       
        floods = df[df['flags'] == 'S'].groupby(['src_ip','dst_ip']).size().reset_index(name='count')
        floods = floods[(floods['count'] >= FLOOD_THRESHOLD) & (floods['dst_ip'] == MY_IP)]
       
        inbound = df[df['dst_ip'] == MY_IP].groupby('src_ip').size().reset_index(name='count')
        outbound = df[df['src_ip'] == MY_IP].groupby('dst_ip').size().reset_index(name='count')
       
        cols = st.columns(4)
        cols[0].metric("Total Events", df.shape[0])
        cols[1].metric("Unique IPs", df["src_ip"].nunique())
        cols[2].metric("Multiple Ports", len(port_access))
        cols[3].metric("Potential Floods", len(floods))
       
        st.subheader("Traffic Flow")
        c1, c2 = st.columns(2)
        with c1:
            if not inbound.empty:
                fig = px.bar(inbound.nlargest(5, 'count'), x='src_ip', y='count', title="Top Inbound IPs")
                st.plotly_chart(fig, use_container_width=True)
        with c2:
            if not outbound.empty:
                fig = px.bar(outbound.nlargest(5, 'count'), x='dst_ip', y='count', title="Top Outbound IPs")
                st.plotly_chart(fig, use_container_width=True)
        
        st.dataframe(df.sort_values("threat_score", ascending=False), use_container_width=True)
    else:
        st.warning("No network data found")

# =============================================
# 3. SUSPICIOUS COMMANDS
# =============================================
elif menu == "Suspicious Commands":
    st.subheader("⚠️ Suspicious Commands")
    df = load_data("suspicious_commands")
   
    if not df.empty:
        df["threat_score"] = df.apply(calculate_threat_score, axis=1)
       
        cols = st.columns(2)
        cols[0].metric("Total Commands", df.shape[0])
        cols[1].metric("High Threat", len(df[df["threat_score"] > 70]))
       
        top_cmds = df['command'].value_counts().head(5).reset_index()
        top_cmds.columns = ['Command', 'Count']
        fig = px.bar(top_cmds, x='Command', y='Count', title="Top Suspicious Commands")
        st.plotly_chart(fig, use_container_width=True)
       
        st.dataframe(df.sort_values("threat_score", ascending=False), use_container_width=True)
    else:
        st.warning("No suspicious commands found")

# =============================================
# 4. CRON EVENTS
# =============================================
elif menu == "Cron Events":
    st.subheader("⏳ Cron Jobs")
    df = load_data("cron_events")
   
    if not df.empty:
        ts_col = "Timestamp" if "Timestamp" in df.columns else "timestamp"
       
        st.metric("Total Cron Jobs", df.shape[0])
       
        fig = px.histogram(df, x=ts_col, title="Cron Job Timeline")
        st.plotly_chart(fig, use_container_width=True)
       
        st.dataframe(df, use_container_width=True)
    else:
        st.warning("No cron events found")

# =============================================
# 5. THREAT INTELLIGENCE
# =============================================
elif menu == "Threat Intelligence":
    st.subheader("🛡️ Threat Intelligence Center")
    
    # Load network data for event frequency analysis
    network_df = load_data("network_events")
    
    # Event Frequency Timeline
    if not network_df.empty:
        st.subheader("📈 Event Frequency Analysis")
        ts_col = "Timestamp" if "Timestamp" in network_df.columns else "timestamp"
        timeline = network_df.set_index(ts_col).resample('1H').size()
        fig = px.line(timeline, title="Event Frequency Over Time")
        st.plotly_chart(fig, use_container_width=True)
    
    # Incident Detection Section
    st.subheader("🚨 Security Incident Detection")
    process_df = load_data("process_monitoring")
    incidents = detect_incidents(network_df, process_df)
    
    if incidents:
        st.metric("Total Incidents Detected", len(incidents))
        
        # Group by severity
        severity_counts = pd.DataFrame(incidents)['severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        fig = px.bar(severity_counts, x='Severity', y='Count', title="Incidents by Severity")
        st.plotly_chart(fig, use_container_width=True)
        
        # Show incidents table
        st.dataframe(
            pd.DataFrame(incidents).sort_values(['severity', 'timestamp'], ascending=[False, False]),
            use_container_width=True,
            column_config={
                "type": "Incident Type",
                "source": "Source",
                "severity": "Severity",
                "description": "Description",
                "timestamp": "Timestamp"
            }
        )
    else:
        st.success("No security incidents detected")
    
    # IP Lookup
    st.subheader("IP Address Analysis")
    
    # Get all IPs from the database
    all_ips = get_all_ips()
    
    if not all_ips:
        st.warning("No IP addresses found in the database")
    else:
        # Create tabs for IP analysis
        tab1, tab2 = st.tabs(["Single IP Analysis", "Bulk IP Analysis"])
        
        with tab1:
            # Single IP analysis
            selected_ip = st.selectbox("Select IP Address:", all_ips)
            
            if selected_ip:
                with st.spinner(f"Gathering intelligence for {selected_ip}..."):
                    ip_info = get_ip_reputation(selected_ip)
                    
                    if "error" in ip_info:
                        st.error(ip_info["error"])
                    else:
                        cols = st.columns([1,1,2])
                        with cols[0]:
                            st.metric("Country", ip_info.get("country", "Unknown"))
                            st.metric("ISP", ip_info.get("isp", "Unknown"))
                        with cols[1]:
                            st.metric("Threat Score", f"{ip_info.get('threat_score', 0)}/100")
                            st.metric("Reputation", ip_info.get("reputation", "Unknown"))
                        
                        with cols[2]:
                            st.markdown("**Threat Intelligence Links**")
                            for source, url in ip_info.get("sources", {}).items():
                                st.markdown(f"- [{source}]({url})")
                
                # Show recent events for this IP
                st.subheader("Recent Events for This IP")
                recent_events = get_recent_events_for_ip(selected_ip)
                
                if not recent_events.empty:
                    st.write(f"Found {len(recent_events)} recent events involving {selected_ip}")
                    
                    # Format the events for display
                    if 'source' in recent_events.columns:
                        for source_type in recent_events['source'].unique():
                            st.write(f"**{source_type.replace('_', ' ').title()} Events**")
                            source_events = recent_events[recent_events['source'] == source_type]
                            
                            if source_type == 'network':
                                st.dataframe(source_events[['timestamp', 'ip', 'dst_ip', 'dst_port', 'flags']], 
                                           use_container_width=True)
                            elif source_type == 'suspicious_command':
                                st.dataframe(source_events[['timestamp', 'ip', 'command']], 
                                           use_container_width=True)
                            else:
                                st.dataframe(source_events, use_container_width=True)
                    else:
                        st.dataframe(recent_events, use_container_width=True)
                else:
                    st.info(f"No recent events found for IP {selected_ip}")
        
        with tab2:
            # Bulk IP analysis
            st.write(f"Found {len(all_ips)} unique IP addresses in the database")
            
            # Analyze all IPs in bulk
            if st.button("Analyze All IPs"):
                progress_bar = st.progress(0)
                status_text = st.empty()
                results = []
                
                for i, ip in enumerate(all_ips):
                    try:
                        status_text.text(f"Analyzing {ip} ({i+1}/{len(all_ips)})...")
                        progress_bar.progress((i + 1) / len(all_ips))
                        
                        ip_info = get_ip_reputation(ip)
                        if "error" not in ip_info:
                            results.append({
                                "IP": ip,
                                "Country": ip_info.get("country", "Unknown"),
                                "ISP": ip_info.get("isp", "Unknown"),
                                "Threat Score": ip_info.get("threat_score", 0),
                                "AbuseIPDB": ip_info.get("sources", {}).get("AbuseIPDB", ""),
                                "VirusTotal": ip_info.get("sources", {}).get("VirusTotal", "")
                            })
                        
                        # Add delay to avoid rate limiting
                        time.sleep(1)
                    except Exception as e:
                        st.error(f"Error analyzing {ip}: {str(e)}")
                        continue
                
                if results:
                    results_df = pd.DataFrame(results)
                    st.dataframe(results_df, use_container_width=True)
                    
                    # Export results
                    csv = results_df.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        label="Download IP Analysis Results",
                        data=csv,
                        file_name="ip_threat_analysis.csv",
                        mime="text/csv"
                    )
                else:
                    st.warning("No IP analysis results available")
    
    # Process Lookup
    st.subheader("Process Analysis")
    process_name = st.text_input("Enter Process Name:")
    if process_name:
        with st.spinner(f"Researching {process_name}..."):
            process_info = get_process_info(process_name)
            
            st.metric("Risk Level", process_info.get("risk_level", "Unknown"))
            st.write(f"**Description:** {process_info.get('description', 'Unknown')}")
            
            st.markdown("**Research Links**")
            for source, url in process_info.get("sources", {}).items():
                st.markdown(f"- [{source}]({url})")

# =============================================
# 6. UBUNTU PROCESS MANAGER
# =============================================
elif menu == "Ubuntu Process Manager":
    st.subheader("🐧 Ubuntu Process Manager")
    
    # Automatically kill high CPU processes when this page is loaded
    killed_count = auto_kill_high_cpu_processes()
    if killed_count > 0:
        st.success(f"Automatically killed {killed_count} high CPU processes")
    
    if st.button("🔄 Refresh Process List"):
        st.session_state.ubuntu_processes = get_ubuntu_processes()
        st.rerun()
    
    if 'ubuntu_processes' not in st.session_state:
        st.session_state.ubuntu_processes = get_ubuntu_processes()
    
    if st.session_state.ubuntu_processes:
        st.write("**Running Processes (Top 10 by CPU Usage)**")
        
        # Filter out whitelisted processes and the specific processes we want to exclude
        filtered_processes = [
            proc for proc in st.session_state.ubuntu_processes 
            if not is_whitelisted_process(proc[4]) and  # Command is the 5th element (index 4)
            not any(excluded in proc[4] for excluded in ["/tst.py", "/script.py"])
        ]
        
        if not filtered_processes:
            st.info("No non-whitelisted processes found")
        else:
            # Display headers
            cols = st.columns([1, 2, 1, 1, 3, 2])
            headers = ["PID", "User", "CPU%", "MEM%", "Command", "Action"]
            for col, header in zip(cols, headers):
                with col:
                    st.write(f"**{header}**")
            
            process_df = pd.DataFrame(
                filtered_processes,
                columns=["PID", "User", "CPU%", "MEM%", "Command"]
            )
            
            for _, row in process_df.iterrows():
                cols = st.columns([1, 2, 1, 1, 3, 2])
                with cols[0]: st.write(row["PID"])
                with cols[1]: st.write(row["User"])
                with cols[2]: st.write(row["CPU%"])
                with cols[3]: st.write(row["MEM%"])
                with cols[4]: 
                    st.text(row["Command"][:50] + "..." if len(row["Command"]) > 50 else row["Command"])
                with cols[5]:
                    if st.button(f"Kill {row['PID']}", key=f"kill_{row['PID']}"):
                        if kill_ubuntu_process(row["PID"]):
                            st.success(f"Successfully killed process {row['PID']}")
                            st.session_state.ubuntu_processes = get_ubuntu_processes()
                            st.rerun()
                        else:
                            st.error(f"Failed to kill process {row['PID']}")
    else:
        st.warning("No processes found or unable to connect to Ubuntu server")
# =============================================

elif menu == "AI Process Intelligence":
    st.subheader("🤖 AI-Powered Process Intelligence")
    
    # Time range selector
    hours_to_analyze = st.slider(
        "Analysis Time Window (hours):",
        min_value=1,
        max_value=72,
        value=24,
        help="Select how many hours of data to analyze"
    )
    
    # Model configuration
    with st.expander("⚙️ Model Configuration"):
        st.write("**Anomaly Detection Settings**")
        sensitivity = st.slider(
            "Detection Sensitivity:",
            min_value=1,
            max_value=10,
            value=5,
            help="Higher values catch more subtle anomalies but may increase false positives"
        )
        
        if st.button("🔄 Retrain Model with Latest Data"):
            with st.spinner("Training new model with recent data patterns..."):
                retrain_model()
                st.success("Model successfully retrained!")
    
    # Load data with progress indicator
    with st.spinner(f"Loading and analyzing last {hours_to_analyze} hours of data..."):
        process_data = fetch_process_data(hours_to_analyze)
        network_data = fetch_network_data(hours_to_analyze)
        suspicious_commands = fetch_suspicious_commands(hours_to_analyze)
        
        if process_data.empty:
            st.warning("No process data available for analysis")
            st.stop()
        
        # Enhanced network analysis
        network_data = detect_c2_communication(network_data)
        network_data = detect_data_exfiltration(network_data)
        network_data = detect_port_scanning(network_data)
        
        # Preprocess and analyze
        process_data = preprocess_process_data(process_data)
        process_data = extract_behavior_features(process_data)
        process_data, _ = encode_features(process_data)
        process_data, _ = normalize_features(process_data)
        
        X = prepare_features(process_data)
        model = load_or_train_model(X)
        scores, predictions = predict_anomalies(model, X)
        
        # Add results to dataframe
        process_data['Anomaly_Score'] = scores
        process_data['Anomaly_Risk'] = (10 - (scores * 10).round()).astype(int)  # Convert to 1-10 scale
        process_data['Is_Anomaly'] = predictions
        anomalies = process_data[process_data['Is_Anomaly'] == -1]
        
        # Correlate with network threats
        merged_data = analyze_network_behavior(process_data, network_data)
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Processes Analyzed", len(process_data))
    col2.metric("Anomalies Detected", len(anomalies))
    col3.metric("Network Threats", len(network_data[network_data['c2_risk'] == 1]))
    col4.metric("Exfil Attempts", len(network_data[network_data['exfil_risk'] == 1]))
    
    # Main tabs - Enhanced with network intelligence
    tab1, tab2, tab3, tab4 = st.tabs(["Anomaly Details", "Behavior Patterns", "Network Threats", "Threat Matrix"])
    
    with tab1:
        st.subheader("🚨 Detected Anomalies")
        if not anomalies.empty:
            # Sort by most anomalous
            anomalies = anomalies.sort_values('Anomaly_Score', ascending=True)
            
            # Enhanced anomaly display with network context
            for _, row in anomalies.head(10).iterrows():
                with st.expander(f"🔴 {row['Command']} (Risk: {row['Anomaly_Risk']}/10)"):
                    cols = st.columns([1,2])
                    cols[0].json({
                        "Process": {
                            "User": row['User'],
                            "PID": row['PID'],
                            "CPU": f"{row['CPU']}%",
                            "Memory": f"{row['Memory']} MB",
                            "Duration": row['Time_Used']
                        }
                    })
                    
                    # Get related network activity
                    related_net = merged_data[
                        (merged_data['PID'] == row['PID']) & 
                        (merged_data['Timestamp'] == row['Timestamp'])
                    ]
                    
                    if not related_net.empty:
                        cols[1].subheader("Associated Network Activity")
                        cols[1].dataframe(related_net[['src_ip', 'dst_ip', 'dst_port', 'bytes_sent']])
                    else:
                        cols[1].info("No related network activity")
        else:
            st.success("🎉 No anomalies detected in the selected time period")
    
    with tab2:
        st.subheader("📈 Process Behavior Patterns")
        selected_user = st.selectbox(
            "Select user to analyze:",
            process_data['User'].unique()
        )
        
        user_data = process_data[process_data['User'] == selected_user]
        
        if not user_data.empty:
            # Ensure Timestamp is datetime and calculate end time
            user_data['Timestamp'] = pd.to_datetime(user_data['Timestamp'])
            user_data['End_Time'] = user_data['Timestamp'] + pd.to_timedelta(user_data['Time_Used_Seconds'], unit='s')
            
            # Timeline visualization
            fig = px.timeline(
                user_data,
                x_start="Timestamp",
                x_end="End_Time",
                y="Command",
                color="Anomaly_Risk",
                color_continuous_scale="reds",
                title=f"Process Timeline for {selected_user}",
                hover_data=['PID', 'CPU', 'Memory']
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Resource usage heatmap
            heatmap_data = user_data.pivot_table(
                index=user_data['Timestamp'].dt.hour,
                columns=user_data['Command'],
                values='CPU',
                aggfunc='mean'
            )
            fig = px.imshow(
                heatmap_data,
                labels=dict(x="Command", y="Hour of Day", color="CPU Usage"),
                title="Hourly Command Patterns"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning(f"No data available for user: {selected_user}")
    
    with tab3:
        st.subheader("🌐 Network Threat Intelligence")
        
        # Threat type selector
        threat_type = st.radio(
            "Select threat type to visualize:",
            ["Command & Control", "Data Exfiltration", "Port Scanning"],
            horizontal=True
        )
        
        if threat_type == "Command & Control":
            threat_data = network_data[network_data['c2_risk'] == 1]
            if not threat_data.empty:
                fig = px.sunburst(
                    threat_data,
                    path=['src_ip', 'dst_ip', 'protocol'],
                    values='bytes_sent',
                    title="C2 Communication Patterns"
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.success("No C2 patterns detected")
        
        elif threat_type == "Data Exfiltration":
            threat_data = network_data[network_data['exfil_risk'] == 1]
            if not threat_data.empty:
                fig = px.scatter_geo(
                    threat_data,
                    lat=0,  # Simplified visualization
                    lon=0,
                    size='bytes_sent',
                    color='src_ip',
                    hover_name='dst_ip',
                    title="Data Exfiltration Flows"
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.success("No exfiltration attempts detected")
        
        else:  # Port Scanning
            threat_data = network_data[network_data['scan_risk'] == 1]
            if not threat_data.empty:
                fig = px.bar(
                    threat_data.groupby('src_ip')['dst_port'].nunique().reset_index(),
                    x='src_ip',
                    y='dst_port',
                    title="Unique Ports Scanned per IP"
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.success("No port scanning activity detected")
    
    with tab4:
        st.subheader("🛡️ Threat Correlation Matrix")
        
        # Create threat correlation matrix
        threat_matrix = merged_data.groupby(['Command', 'dst_port']).agg({
            'Anomaly_Risk': 'max',
            'bytes_sent': 'sum',
            'PID': 'nunique'
        }).reset_index()
        
        if not threat_matrix.empty:
            fig = px.density_heatmap(
                threat_matrix,
                x="dst_port",
                y="Command",
                z="Anomaly_Risk",
                histfunc="avg",
                title="Command/Port Risk Correlation"
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Top threat correlations
            st.dataframe(
                threat_matrix.sort_values('Anomaly_Risk', ascending=False).head(10),
                use_container_width=True
            )
        else:
            st.info("No threat correlations found")





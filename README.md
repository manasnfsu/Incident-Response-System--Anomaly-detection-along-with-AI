# Incident-Response-System--Anomaly-detection-along-with-AI

🔐 AI-Driven Cybersecurity Monitoring & Incident Response System (IRM)
A complete, intelligent threat detection and response system that monitors real-time activity across Linux and Windows environments, detects anomalies using AI, enriches data with threat intel, and automates response through a custom dashboard.

🔧 Infrastructure Components
📡 Data Collection (Ubuntu Agent)
Process Monitoring: PID, CPU/Memory, creation time

Network Analysis: Active TCP/UDP connections, flags

Suspicious Commands: Logs risky commands (rm -rf, chmod 777)

Cron Jobs: Tracks job changes & persistence threats

Tech: psutil, paramiko, systemd, Python

🔄 Data Transmission
TCP Sockets:

Port 5400: NDJSON security events

Port 5050: CSV-formatted process metrics

Error Handling: Reconnect/retry logic with logging

🖥️ Centralized Processing (Windows Server)
Multithreaded TCP Server

SQLite Database: Tables for processes, net events, cron jobs

Live Parser: Auto-updates DB with incoming logs

🧠 AI/ML-Based Anomaly Detection
Models: Isolation Forest, One-Class SVM

Features:

Timestamp pattern analysis (hour/day trends)

CPU/memory ratio spikes

Command frequency patterns

Output: Risk score assigned to each event or process

🌐 Threat Intelligence
IP lookups via AbuseIPDB, VirusTotal, GreyNoise

Maps IP locations and flags known bad actors

Correlates log patterns with threat intel indicators

🛠️ Automated Response
Kills resource-heavy or risky processes

Prioritizes alerts (Critical, High, Medium, Low)

Verifies safe process list via whitelisting

📊 Streamlit Dashboard
Visualization:

Process trends, anomalies, resource graphs

Network flows with TCP flag decoding

Suspicious command timelines

Tools:

1–72 hour time selection

Anomaly sensitivity control (1–10 scale)

Live model retraining

PDF/HTML reporting with email delivery

🧬 Technical Highlights
Feature Engineering: Memory ratios, rolling stats

Security: SSH-based control, encoded variables, process verification

Automation: Systemd services, real-time scoring loop, threat matrix correlation

🧪 Value Proposition
This system is built to:

Reduce false positives with context-aware anomaly detection

Provide real-time intelligence and threat correlation

Respond proactively with autonomous actions

Support incident forensics with deep historical data

🧑‍💻 Developed by [Your Name] | [LinkedIn]
🎓 Student @ NFSU | Focus: AI + Cybersecurity

#CyberThreats #AIForSecurity #MachineLearning #AnomalyDetection #Python #Streamlit #LinuxSecurity #IncidentResponse #SIEM #IRM #Forensics

# 🛡️ AI-Driven Cybersecurity Monitoring & Incident Response System (IRM)

## 🔍 Overview
This AI/ML-based **Incident Response Management (IRM)** system is a real-time cybersecurity monitoring framework that collects, analyzes, and responds to threats across a **Linux (Ubuntu) to Windows infrastructure**. It enhances traditional security solutions by integrating behavioral anomaly detection, threat intelligence, and automated response.

### 🚀 Key Innovations
- ✅ **AI/ML-Powered Anomaly Detection** – Detects abnormal behavior using Isolation Forest & One-Class SVM
- ✅ **False Positive Reduction** – Focus on behavior, not just signatures
- ✅ **Threat Intelligence Integration** – Includes AbuseIPDB, VirusTotal, GreyNoise
- ✅ **Automated Incident Response** – Auto-kills malicious processes and generates forensic reports
- ✅ **Interactive Dashboard** – Real-time visibility via Streamlit

---

## 🏗️ System Architecture

### 1. Infrastructure Components

| Component             | Role                          | Technologies Used                |
|----------------------|-------------------------------|----------------------------------|
| **Ubuntu VM (Client)**     | Data Collection               | Python, psutil, systemd           |
| **Windows VM (Server)**    | Data Processing & ML Analysis | Python, SQLite, Scikit-learn      |
| **Network Communication**  | Secure Data Transfer          | TCP Sockets (Ports 5050 & 5400)   |
| **Dashboard**              | Visualization & Alerts        | Streamlit, Plotly, Pandas         |

---

### 2. Data Flow

#### 🔹 Ubuntu VM (Client-Side)
- Collects **process metrics** (CPU, memory, commands)
- Monitors **network connections** (TCP flags, ports, IPs)
- Logs **suspicious commands** (e.g., `rm -rf`, `chmod 777`)
- Tracks **cron jobs** (persistence checks)
- Sends data via TCP (NDJSON on `5400`, CSV on `5050`)

#### 🔸 Windows VM (Server-Side)
- Receives logs via **Python socket server**
- Stores data in **SQLite**
- Runs **AI models** (Isolation Forest, SVM)
- Triggers alerts & **auto-response**

#### 🖥️ Streamlit Dashboard
- Visualizes **real-time behavior**
- Allows **manual actions**
- Generates **PDF/HTML forensic reports**

---

## 🧠 Key Features & Implementation Details

### 🔍 1. Real-Time Process Monitoring
- **Collected:** PID, CPU%, MEM%, Command, User
- **Anomaly Detection:** Trained Isolation Forest flags unexpected behaviors
- **Auto-Response:** Terminates high-CPU/memory processes (with whitelisting)

---

### 🌐 2. Network Traffic Analysis
- **Captured:** IPs, ports, TCP flags
- **Detections:** Port scanning, beaconing, data exfiltration
- **GeoIP Lookup:** Maps IP origin

---

### 🧾 3. Suspicious Command Detection
- **Flags:** `rm -rf`, `chmod 777`, reverse shells, malware downloads
- **Risk Score:** 0–100, triggers alerts above 70

---

### ⏰ 4. Cron Job Monitoring
- Detects **unauthorized** or **malicious** cron jobs
- Visual timeline + user-based filters

---

### 🌍 5. Threat Intelligence Integration
- **Sources:** AbuseIPDB, VirusTotal, GreyNoise
- **Features:** IP reputation score, country mapping, threat score

---

### 🤖 6. Automated Incident Response
- Auto-kills flagged processes
- Verifies kill success
- Sends **email alerts** + dashboard warnings

---

## 🧬 AI/ML Implementation

### 📊 Models Used

| Model             | Use Case                      | Input Features                    |
|------------------|-------------------------------|------------------------------------|
| Isolation Forest | Abnormal process behavior     | CPU%, MEM%, Runtime                |
| One-Class SVM    | Rare/suspicious command usage | Command frequency, user behavior   |
| K-Means (optional) | Network clustering           | IPs, ports                         |

### 🛠️ Feature Engineering
- **Process:** CPU/MEM ratios, command entropy
- **Network:** SYN/ACK ratios, IP reputation
- **Temporal:** Hourly and weekend patterns

---

## 📈 Streamlit Dashboard Features

### 📡 Real-Time Visualizations
- CPU/MEM usage (line charts)
- Anomaly score (histograms)
- IP traffic + threats (bar/pie charts)

### 🕹️ Interactive Controls
- Time selector (1h–72h)
- Sensitivity slider (1–10)
- Manual process kill
- PDF/HTML report generator

---

## 🔮 Future Enhancements
- ☁️ Cloud deployment (AWS/GCP)
- 🔍 MITRE ATT&CK mapping
- 📦 YARA rule integration
- 📊 SIEM integration (Splunk, ELK)

---

## 🏁 Conclusion
Your **AI-driven IRM system** replaces static rules with **dynamic behavior-based detection**, offering:

- ✔️ Lower false positives
- ✔️ Real-time attack response
- ✔️ Integrated threat intel
- ✔️ Forensic-level visibility

This project is **production-ready** and designed for scalable **SOC-level deployment**. 🚀

---

## 📬 Contact
For any collaboration, contributions, or questions, feel free to [connect on LinkedIn](https://linkedin.com/) or drop an issue in this repo.


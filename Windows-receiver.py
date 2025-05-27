import socket
import json
import logging
from datetime import datetime
from threading import Thread
import os

# Configuration
LISTEN_IP = "0.0.0.0"  # Listen on all interfaces
PORT_LOGS = 5400  # Port for NDJSON logs
PORT_CSV = 5050  # Port for CSV process data
LOG_DIR = "security_logs"  # Directory to store logs
BUFFER_SIZE = 4096  # Buffer size for receiving data

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("windows_server.log"),
        logging.StreamHandler()
    ]
)

class SecurityLogServer:
    def __init__(self):
        self.running = True
        self.create_log_dir()

    def create_log_dir(self):
        """Ensure the log directory exists."""
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
            logging.info(f"Created log directory: {LOG_DIR}")

    def log_event(self, event):
        """Log events in NDJSON format."""
        try:
            event_type = event.get("type", "unknown")
            timestamp = datetime.now().strftime("%Y%m%d")
            log_file = os.path.join(LOG_DIR, f"{event_type}_{timestamp}.ndjson")

            with open(log_file, "a") as f:
                f.write(json.dumps(event) + "\n")  # Append NDJSON entry

            logging.info(f"Logged {event_type} event to {log_file}")
        except Exception as e:
            logging.error(f"Error logging event: {e}")

    def handle_ndjson_client(self, conn, addr):
        """Handle client connection and process NDJSON data."""
        try:
            buffer = ""
            while True:
                data = conn.recv(BUFFER_SIZE).decode("utf-8")
                if not data:
                    break  # Connection closed by client

                buffer += data
                while "\n" in buffer:  # Process complete NDJSON lines
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        try:
                            event = json.loads(line)
                            logging.debug(f"Received event: {event}")  # Debugging
                            self.log_event(event)
                            self.generate_alert(event)
                        except json.JSONDecodeError:
                            logging.error(f"Invalid JSON received: {line}")
        except Exception as e:
            logging.error(f"Client handling error: {e}")
        finally:
            conn.close()
            logging.info(f"Connection closed with {addr}")

    def generate_alert(self, event):
        """Generate real-time alerts for critical events."""
        event_type = event.get("type", "")
        if event_type == "suspicious_command":
            logging.warning(f"ALERT: Suspicious command detected - {event.get('command', '')}")
        elif event_type == "network_event" and event.get("dst_port") in [22, 23]:
            logging.warning(f"ALERT: Suspicious network activity on port {event.get('dst_port')}")

    def start_ndjson_server(self):
        """Start the TCP server to listen for incoming NDJSON data."""
        self.create_log_dir()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((LISTEN_IP, PORT_LOGS))
            sock.listen(5)
            logging.info(f"NDJSON server listening on {LISTEN_IP}:{PORT_LOGS}")

            while self.running:
                try:
                    conn, addr = sock.accept()
                    logging.info(f"Connection established with {addr}")
                    client_thread = Thread(target=self.handle_ndjson_client, args=(conn, addr))
                    client_thread.start()
                except KeyboardInterrupt:
                    self.running = False
                    logging.info("Shutting down NDJSON server...")
                except Exception as e:
                    logging.error(f"NDJSON server error: {e}")

    def handle_csv_client(self, conn, addr):
        """Handle client connection and process CSV data."""
        try:
            csv_data = ""
            while True:
                chunk = conn.recv(BUFFER_SIZE).decode("utf-8")
                if not chunk:
                    break
                csv_data += chunk

            if csv_data:
                filename = os.path.join(LOG_DIR, f"process_data_{datetime.now().strftime('%Y%m%d')}.csv")
                self.save_csv_data(csv_data, filename)

        except Exception as e:
            logging.error(f"CSV client handling error: {e}")
        finally:
            conn.close()
            logging.info(f"Connection closed with {addr}")

    def save_csv_data(self, csv_data, filename):
        """Saves the received CSV data to a file. Appends if the file already exists."""
        file_exists = os.path.exists(filename)
        with open(filename, "a", encoding="utf-8") as file:
            if not file_exists:
                # Write the header if the file is new
                file.write("Timestamp,PID,User,CPU,Memory,VIRT,RES,SHR,S,Time Used,Command,Hashed Command\n")
            # Append the CSV data
            file.write(csv_data)
        logging.info(f"CSV data saved to {filename}")

    def start_csv_server(self):
        """Start the TCP server to listen for incoming CSV data."""
        self.create_log_dir()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((LISTEN_IP, PORT_CSV))
            sock.listen(5)
            logging.info(f"CSV server listening on {LISTEN_IP}:{PORT_CSV}")

            while self.running:
                try:
                    conn, addr = sock.accept()
                    logging.info(f"Connection established with {addr}")
                    client_thread = Thread(target=self.handle_csv_client, args=(conn, addr))
                    client_thread.start()
                except KeyboardInterrupt:
                    self.running = False
                    logging.info("Shutting down CSV server...")
                except Exception as e:
                    logging.error(f"CSV server error: {e}")

if __name__ == "__main__":
    server = SecurityLogServer()

    # Start NDJSON server in a separate thread
    ndjson_thread = Thread(target=server.start_ndjson_server)
    ndjson_thread.daemon = True
    ndjson_thread.start()

    # Start CSV server in the main thread
    server.start_csv_server()



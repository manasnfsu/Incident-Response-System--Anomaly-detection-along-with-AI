import sqlite3
import pandas as pd
import json
import os
import time
from datetime import datetime

# ✅ Get today's date in YYYYMMDD format
current_date = datetime.now().strftime("%Y%m%d")

# ✅ Database Path
DB_PATH = "process_monitoring.db"

# ✅ File Paths (Auto-update daily)
CSV_PATH = f"security_logs/process_data_{current_date}.csv"
NDJSON_NETWORK_PATH = f"security_logs/network_event_{current_date}.ndjson"
NDJSON_COMMANDS_PATH = f"security_logs/suspicious_command_{current_date}.ndjson"
NDJSON_CRON_PATH = f"security_logs/cron_event_{current_date}.ndjson"

# ✅ Initialize Database
def initialize_database():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cursor = conn.cursor()

    cursor.execute("""CREATE TABLE IF NOT EXISTS process_monitoring (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Timestamp TEXT UNIQUE,
        PID INTEGER,
        User TEXT,
        CPU REAL,
        Memory REAL,
        VIRT INTEGER,
        RES INTEGER,
        SHR INTEGER,
        S TEXT,
        Time_Used TEXT,
        Command TEXT,
        Hashed_Command TEXT
    )""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS network_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT UNIQUE,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        flags TEXT
    )""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS suspicious_commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT UNIQUE,
        user TEXT,
        command TEXT,
        pid INTEGER
    )""")

    cursor.execute("""CREATE TABLE IF NOT EXISTS cron_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT UNIQUE,
        cron_file TEXT,
        job TEXT
    )""")

    conn.commit()
    conn.close()
    print("[✅] Database initialized successfully!")

# ✅ Function to Load & Insert Data Efficiently
def load_and_insert_data(file_path, table_name, rename_cols=None, drop_columns=None):
    if not os.path.exists(file_path):
        print(f"[⚠] File not found: {file_path}")
        return

    try:
        time.sleep(1)  # Ensure file is fully written before reading
        conn = sqlite3.connect(DB_PATH, timeout=10)
        cursor = conn.cursor()

        # Load CSV or NDJSON
        if file_path.endswith(".csv"):
            df = pd.read_csv(file_path)
        elif file_path.endswith(".ndjson"):
            with open(file_path, "r") as file:
                data = [json.loads(line) for line in file]  
            df = pd.DataFrame(data)
        else:
            print(f"[⚠] Unsupported file format: {file_path}")
            return

        # Rename columns if needed
        if rename_cols:
            df.rename(columns=rename_cols, inplace=True)

        # Drop unnecessary columns
        if drop_columns:
            df.drop(columns=drop_columns, inplace=True, errors="ignore")

        # Ensure timestamp column is consistent
        timestamp_col = "Timestamp" if "Timestamp" in df.columns else "timestamp"
        df.drop_duplicates(subset=[timestamp_col], keep="first", inplace=True)

        # 🛠 **Check for truly new entries before inserting**
        existing_timestamps = set(row[0] for row in cursor.execute(f"SELECT {timestamp_col} FROM {table_name}").fetchall())
        new_data = df[~df[timestamp_col].isin(existing_timestamps)]

        if not new_data.empty:
            new_data.to_sql(table_name, conn, if_exists="append", index=False, method="multi")
            print(f"[+] {len(new_data)} new rows added to {table_name}.")
        else:
            print(f"[⚠] No new records to add in {table_name}.")

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Error updating {table_name}: {e}")

# ✅ Continuous Monitoring Loop
def monitor_files():
    print("[🚀] Monitoring files for real-time updates...")

    last_mod_times = {file: None for file in [CSV_PATH, NDJSON_NETWORK_PATH, NDJSON_COMMANDS_PATH, NDJSON_CRON_PATH]}

    while True:
        for file_path in last_mod_times.keys():
            if os.path.exists(file_path):
                mod_time = os.stat(file_path).st_mtime

                if last_mod_times[file_path] is None or mod_time > last_mod_times[file_path]:
                    print(f"[🔄] Detected update in {file_path}. Updating database...")

                    if file_path == CSV_PATH:
                        load_and_insert_data(file_path, "process_monitoring", 
                                             rename_cols={"timestamp": "Timestamp", "Time Used": "Time_Used", "Hashed Command": "Hashed_Command"})
                    elif file_path == NDJSON_NETWORK_PATH:
                        load_and_insert_data(file_path, "network_events", drop_columns=["type"])
                    elif file_path == NDJSON_COMMANDS_PATH:
                        load_and_insert_data(file_path, "suspicious_commands", drop_columns=["type"])
                    elif file_path == NDJSON_CRON_PATH:
                        load_and_insert_data(file_path, "cron_events", drop_columns=["type"])

                    last_mod_times[file_path] = mod_time

        time.sleep(5)  # Check every 5 seconds for faster updates

# 🚀 Run the Database Updater
if __name__ == "__main__":
    initialize_database()
    monitor_files()

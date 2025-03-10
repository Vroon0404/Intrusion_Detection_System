import os
import time
import re
import threading
import subprocess
import requests
import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime
from collections import deque

# Configuration
LOG_FILE = "/var/log/auth.log"
CENTRAL_LOG_SERVER = "http://your-central-log-server:port/logs"
THRESHOLD_ANOMALY_SCORE = -0.5  # Adjust based on your model
SUSPICIOUS_ACTIVITY_KEYWORDS = ["Failed password", "Invalid user", "BREAK-IN ATTEMPT"]
LOG_BUFFER_SIZE = 1000  # Number of log entries to keep in memory for anomaly detection
CHECK_INTERVAL = 60  # Time interval (in seconds) for anomaly detection

# Global buffer to store recent log entries
log_buffer = deque(maxlen=LOG_BUFFER_SIZE)

# Machine Learning Model (Isolation Forest for anomaly detection)
def train_anomaly_detection_model(log_data):
    """
    Train an anomaly detection model using Isolation Forest.
    """
    # Feature extraction (example: count of log entries per minute)
    log_data['timestamp'] = pd.to_datetime(log_data['timestamp'])
    log_data.set_index('timestamp', inplace=True)
    features = log_data.resample('T').count().fillna(0)

    # Train the model
    model = IsolationForest(contamination=0.1, random_state=42)  # Adjust contamination
    model.fit(features)
    return model

def detect_anomalies(model, new_logs):
    """
    Detect anomalies in new log entries.
    """
    new_logs['timestamp'] = pd.to_datetime(new_logs['timestamp'])
    new_logs.set_index('timestamp', inplace=True)
    new_features = new_logs.resample('T').count().fillna(0)
    predictions = model.predict(new_features)
    return predictions

# Log Monitoring
def monitor_logs():
    """
    Monitor system logs for suspicious activity.
    """
    print("Starting log monitoring...")
    with open(LOG_FILE, "r") as log_file:
        log_file.seek(0, os.SEEK_END)  # Go to the end of the file
        while True:
            line = log_file.readline()
            if line:
                log_buffer.append(line.strip())  # Add log entry to buffer
                for keyword in SUSPICIOUS_ACTIVITY_KEYWORDS:
                    if keyword in line:
                        print(f"Suspicious activity detected: {line.strip()}")
                        send_to_central_log_server(line.strip())
                        take_response_action(line.strip())
            time.sleep(0.1)  # Small delay to reduce CPU usage

# Centralized Logging
def send_to_central_log_server(log_entry):
    """
    Send log entries to a centralized logging system.
    """
    try:
        payload = {"timestamp": datetime.now().isoformat(), "log_entry": log_entry}
        response = requests.post(CENTRAL_LOG_SERVER, json=payload, timeout=5)
        if response.status_code != 200:
            print(f"Failed to send log to central server: {response.status_code}")
    except Exception as e:
        print(f"Error sending log to central server: {e}")

# Response Actions
def take_response_action(log_entry):
    """
    Automate response actions based on suspicious activity.
    """
    if "Failed password" in log_entry:
        ip_address = extract_ip_address(log_entry)
        if ip_address:
            print(f"Blocking IP address: {ip_address}")
            block_ip_address(ip_address)

    if "Invalid user" in log_entry:
        username = extract_username(log_entry)
        if username:
            print(f"Killing processes for user: {username}")
            kill_user_processes(username)

def extract_ip_address(log_entry):
    """
    Extract IP address from log entry.
    """
    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    match = re.search(ip_pattern, log_entry)
    return match.group(0) if match else None

def extract_username(log_entry):
    """
    Extract username from log entry.
    """
    parts = log_entry.split()
    if len(parts) > 2:
        return parts[2]
    return None

def block_ip_address(ip_address):
    """
    Block an IP address using fail2ban or iptables.
    """
    try:
        # Using fail2ban (recommended)
        subprocess.run(["fail2ban-client", "set", "sshd", "banip", ip_address], check=True)
        print(f"Successfully blocked IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP using fail2ban: {e}")
        # Fallback to iptables
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            print(f"Successfully blocked IP using iptables: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP using iptables: {e}")

def kill_user_processes(username):
    """
    Kill all processes for a specific user.
    """
    try:
        subprocess.run(["pkill", "-u", username], check=True)
        print(f"Successfully killed processes for user: {username}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to kill processes: {e}")

# Anomaly Detection Thread
def anomaly_detection_thread():
    """
    Periodically check for anomalies in log buffer.
    """
    print("Starting anomaly detection thread...")
    # Load historical log data for training (example)
    historical_logs = pd.read_csv("historical_logs.csv")  # Replace with your log data
    model = train_anomaly_detection_model(historical_logs)

    while True:
        if len(log_buffer) > 0:
            # Convert log buffer to DataFrame
            new_logs = pd.DataFrame(log_buffer, columns=["log_entry"])
            new_logs['timestamp'] = datetime.now()  # Add timestamp for resampling
            predictions = detect_anomalies(model, new_logs)

            # Check for anomalies
            for i, score in enumerate(predictions):
                if score < THRESHOLD_ANOMALY_SCORE:
                    print(f"Anomaly detected: {new_logs.iloc[i]['log_entry']}")
                    send_to_central_log_server(new_logs.iloc[i]['log_entry'])
                    take_response_action(new_logs.iloc[i]['log_entry'])

        time.sleep(CHECK_INTERVAL)

# Main Function
if __name__ == "__main__":
    # Start log monitoring in a separate thread
    log_monitor_thread = threading.Thread(target=monitor_logs)
    log_monitor_thread.daemon = True
    log_monitor_thread.start()

    # Start anomaly detection in a separate thread
    anomaly_thread = threading.Thread(target=anomaly_detection_thread)
    anomaly_thread.daemon = True
    anomaly_thread.start()

    # Keep the main thread alive
    while True:
        time.sleep(1)
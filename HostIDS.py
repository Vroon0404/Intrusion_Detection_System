import os
import time
import re
import threading
import subprocess
import requests
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from datetime import datetime
from collections import deque

# Configuration
LOG_FILE = "auth.log"  # Use a local test log file
CENTRAL_LOG_SERVER = "http://your-central-log-server:port/logs"
THRESHOLD_ANOMALY_SCORE = -0.5
SUSPICIOUS_ACTIVITY_KEYWORDS = ["Failed password", "Invalid user", "BREAK-IN ATTEMPT"]
LOG_BUFFER_SIZE = 1000
CHECK_INTERVAL = 60
MODEL_UPDATE_INTERVAL = 3600  # Retrain model every hour

# Global buffer and model
log_buffer = deque(maxlen=LOG_BUFFER_SIZE)
model_pipeline = None
scaler = StandardScaler()


def monitor_logs():
    print("Starting log monitoring...")
    if not os.path.exists(LOG_FILE):
        print(f"Log file {LOG_FILE} not found. Creating an empty one.")
        open(LOG_FILE, "w").close()

    with open(LOG_FILE, "r") as log_file:
        log_file.seek(0, os.SEEK_END)
        while True:
            line = log_file.readline()
            if line:
                log_buffer.append({'log_entry': line.strip(), 'timestamp': datetime.now().isoformat()})
                for keyword in SUSPICIOUS_ACTIVITY_KEYWORDS:
                    if keyword in line:
                        print(f"Suspicious activity detected: {line.strip()}")
                        send_to_central_log_server(line.strip())
                        take_response_action(line.strip())
            time.sleep(0.1)


def create_model_pipeline():
    return Pipeline([
        ('scaler', StandardScaler()),
        ('clf', IsolationForest(
            n_estimators=200,
            max_samples='auto',
            contamination=0.05,
            random_state=42,
            verbose=0
        ))
    ])


def train_model(log_data):
    if log_data.empty:
        print("No data available for training. Skipping model update.")
        return None

    log_data['timestamp'] = pd.to_datetime(log_data['timestamp'])
    log_data['hour'] = log_data['timestamp'].dt.hour
    log_data['failed_attempts'] = log_data['log_entry'].str.count('Failed password')
    log_data['invalid_users'] = log_data['log_entry'].str.count('Invalid user')

    X = log_data[['hour', 'failed_attempts', 'invalid_users']]
    X = X.fillna(0)

    if X.shape[0] == 0:
        print("Insufficient data for training. Skipping model update.")
        return None

    pipeline = create_model_pipeline()
    pipeline.fit(X)

    return pipeline


def model_update_thread():
    global model_pipeline
    print("Starting model update thread...")

    while True:
        try:
            if not os.path.exists("historical_logs.csv"):
                print("No historical logs found. Creating an empty dataset.")
                pd.DataFrame(columns=["log_entry", "timestamp"]).to_csv("historical_logs.csv", index=False)

            historical_logs = pd.read_csv("historical_logs.csv")
            current_logs = pd.DataFrame(log_buffer, columns=["log_entry", "timestamp"])
            combined_logs = pd.concat([historical_logs, current_logs])

            model_pipeline = train_model(combined_logs) or create_model_pipeline()
            print("Model successfully updated")

        except Exception as e:
            print(f"Model update failed: {e}")

        time.sleep(MODEL_UPDATE_INTERVAL)


def anomaly_detection_thread():
    print("Starting anomaly detection thread...")

    if not os.path.exists("historical_logs.csv"):
        print("No historical logs found. Creating an empty dataset.")
        pd.DataFrame(columns=["log_entry", "timestamp"]).to_csv("historical_logs.csv", index=False)

    historical_logs = pd.read_csv("historical_logs.csv")
    global model_pipeline
    model_pipeline = train_model(historical_logs) or create_model_pipeline()

    while True:
        if len(log_buffer) > 0 and model_pipeline is not None:
            new_logs = pd.DataFrame(log_buffer, columns=["log_entry"])
            new_logs['timestamp'] = datetime.now()

            try:
                scores = detect_anomalies(model_pipeline, new_logs)
                for i, score in enumerate(scores):
                    if score < THRESHOLD_ANOMALY_SCORE:
                        log_entry = new_logs.iloc[i]['log_entry']
                        print(f"Anomaly detected (score: {score:.2f}): {log_entry}")
                        send_to_central_log_server(log_entry)
                        take_response_action(log_entry)
            except Exception as e:
                print(f"Anomaly detection failed: {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    threads = [
        threading.Thread(target=monitor_logs, daemon=True),
        threading.Thread(target=anomaly_detection_thread, daemon=True),
        threading.Thread(target=model_update_thread, daemon=True)
    ]

    for t in threads:
        t.start()

    while True:
        time.sleep(1)

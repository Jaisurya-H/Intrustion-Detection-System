import pandas as pd
from sklearn.ensemble import IsolationForest
import socketio
import os
import threading
from datetime import datetime

try:
    sio = socketio.Client()
    sio.connect("http://127.0.0.1:5000")
except Exception as e:
    print(f"Could not connect to dashboard: {e}")

def _run_block_command(ip):
    try:
        command = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
        os.system(command)
        print(f"[FIREWALL] Blocked IP: {ip}")
    except Exception as e:
        print(f"Failed to block IP: {e}")

def block_ip_windows(ip):
    t = threading.Thread(target=_run_block_command, args=(ip,))
    t.daemon = True
    t.start()

# Load dataset
data = pd.read_csv("traffic_data.csv")

print("Dataset loaded. Rows:", len(data))

# Train Isolation Forest model
model = IsolationForest(contamination=0.05, random_state=42)
model.fit(data)

print("ML model trained successfully")

# Detect anomalies
predictions = model.predict(data)

anomalies = data[predictions == -1]
print("Total anomalies detected:", len(anomalies))

# Since it's a CSV, we will fake the IP for demonstration based on row index or a dummy IP
for idx, row in anomalies.iterrows():
    anomaly = -1 # we already filtered for this
    ip = f"192.168.1.{idx % 255}" # Fake IP for demonstration
    if anomaly == -1:
        severity = "CRITICAL"
        risk_score = 95

        try:
            sio.emit("alert_event", {
                "time": datetime.now().strftime("%H:%M:%S"),
                "message": f"ML Anomaly detected from {ip}",
                "severity": severity,
                "ip": ip,
                "risk_score": risk_score
            })
        except:
            pass

        block_ip_windows(ip)


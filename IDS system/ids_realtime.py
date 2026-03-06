from scapy.all import sniff, IP
from collections import defaultdict
import time
from datetime import datetime
import socketio

sio = socketio.Client()
sio.connect("http://127.0.0.1:5000")

packet_count = defaultdict(int)
THRESHOLD = 20
TIME_WINDOW = 10
start_time = time.time()

LOG_FILE = "alerts.log"

def log_alert(msg):
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def detect(packet):
    global start_time
    if IP in packet:
        src_ip = packet[IP].src

        # 🔵 Wi-Fi usage telemetry
        sio.emit("packet_event", {"src_ip": src_ip})

        packet_count[src_ip] += 1
        now = time.time()

        if now - start_time > TIME_WINDOW:
            for ip, count in packet_count.items():
                if count > THRESHOLD:
                    t = datetime.now().strftime("%H:%M:%S")
                    msg = f"High traffic from {ip} ({count} packets)"

                    log_alert(f"[{t}] ALERT: {msg}")
                    print(f"[{t}] ALERT:", msg)

                    # 🔴 Alert event
                    sio.emit("alert_event", {
                        "time": t,
                        "message": msg,
                        "severity": "HIGH"
                    })

            packet_count.clear()
            start_time = now

print("IDS running with full SOC integration...")
sniff(prn=detect, store=False)

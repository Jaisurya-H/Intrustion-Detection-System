from scapy.all import sniff, IP
from collections import defaultdict
import time
from datetime import datetime
import socketio
import os

sio = socketio.Client()
sio.connect("http://127.0.0.1:5000")

packet_count = defaultdict(int)

from scapy.all import TCP
port_tracker = defaultdict(set)
COMMON_PORTS = {80, 443, 22, 53, 25, 110, 143}
rare_port_tracker = defaultdict(int)
THRESHOLD = 20
TIME_WINDOW = 10
start_time = time.time()

LOG_FILE = "alerts.log"

def log_alert(msg):
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

import threading

def _run_block_command(ip):
    try:
        command = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
        os.system(command)
        print(f"[FIREWALL] Blocked IP: {ip}")
    except Exception as e:
        print(f"Failed to block IP: {e}")

def block_ip_windows(ip):
    # Run the blocking command in a background thread so it doesn't freeze the scapy sniffer
    t = threading.Thread(target=_run_block_command, args=(ip,))
    t.daemon = True
    t.start()

def detect(packet):
    global start_time
    if IP in packet:
        src_ip = packet[IP].src

        # -------- PORT SCAN TRACKING --------
        if TCP in packet:
            dst_port = packet[TCP].dport
            port_tracker[src_ip].add(dst_port)

            # Rare port tracking
            if dst_port not in COMMON_PORTS:
                rare_port_tracker[src_ip] += 1

        # 🔵 Wi-Fi usage telemetry
        sio.emit("packet_event", {"src_ip": src_ip})

        packet_count[src_ip] += 1
        now = time.time()

        if now - start_time > TIME_WINDOW:
            for ip, count in packet_count.items():
                if count > THRESHOLD:
                    timestamp = datetime.now().strftime("%H:%M:%S")

                    # ---- SEVERITY LOGIC ----
                    if count > 80:
                        severity = "CRITICAL"
                        risk_score = 90
                    elif count > 40:
                        severity = "HIGH"
                        risk_score = 70
                    else:
                        severity = "MEDIUM"
                        risk_score = 40

                    attack_type = "Traffic Flood"

                    alert_msg = f"{attack_type} detected from {ip} ({count} packets)"

                    full_msg = f"[{timestamp}] {severity} ALERT: {alert_msg} | Risk Score: {risk_score}"

                    print(full_msg)
                    log_alert(full_msg)

                    sio.emit("alert_event", {
                        "time": timestamp,
                        "message": alert_msg,
                        "severity": severity,
                        "ip": ip,
                        "count": count,
                        "risk_score": risk_score
                    })

                    if severity in ["HIGH", "CRITICAL"]:
                        block_ip_windows(ip)
            # -------- PORT SCAN DETECTION --------
            for ip, ports in port_tracker.items():
                if len(ports) > 15:
                    timestamp = datetime.now().strftime("%H:%M:%S")

                    attack_type = "Port Scan"
                    severity = "HIGH"
                    risk_score = 80

                    alert_msg = f"{attack_type} detected from {ip} ({len(ports)} ports scanned)"

                    full_msg = f"[{timestamp}] {severity} ALERT: {alert_msg} | Risk Score: {risk_score}"

                    print(full_msg)
                    log_alert(full_msg)

                    sio.emit("alert_event", {
                        "time": timestamp,
                        "message": alert_msg,
                        "severity": severity,
                        "ip": ip,
                        "risk_score": risk_score
                    })

                    if severity in ["HIGH", "CRITICAL"]:
                        block_ip_windows(ip)

            # -------- RARE PORT DETECTION --------
            for ip, count in rare_port_tracker.items():
                if count > 10:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    severity = "HIGH"
                    risk_score = 75
                    attack_type = "Rare Port Activity"

                    alert_msg = f"{attack_type} detected from {ip}"

                    print(f"[{timestamp}] {severity} ALERT: {alert_msg}")
                    log_alert(f"[{timestamp}] {severity} ALERT: {alert_msg}")

                    sio.emit("alert_event", {
                        "time": timestamp,
                        "message": alert_msg,
                        "severity": severity,
                        "ip": ip,
                        "risk_score": risk_score
                    })

            packet_count.clear()
            port_tracker.clear()
            rare_port_tracker.clear()
            start_time = now

print("IDS running with full SOC integration...")
sniff(prn=detect, store=False)

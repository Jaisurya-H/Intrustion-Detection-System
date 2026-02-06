from scapy.all import sniff, IP
from collections import defaultdict
import time

packet_count = defaultdict(int)
THRESHOLD = 20   # packets per time window
TIME_WINDOW = 10  # seconds

start_time = time.time()

def detect(packet):
    global start_time

    if IP in packet:
        src_ip = packet[IP].src
        packet_count[src_ip] += 1

        current_time = time.time()
        elapsed = current_time - start_time

        if elapsed > TIME_WINDOW:
            for ip, count in packet_count.items():
                if count > THRESHOLD:
                    print(f"[ALERT] Suspicious activity detected from {ip} ({count} packets in {TIME_WINDOW}s)")
            packet_count.clear()
            start_time = current_time

print("Rule-based IDS started...")
sniff(prn=detect, store=False)


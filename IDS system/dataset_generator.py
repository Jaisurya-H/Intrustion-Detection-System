from scapy.all import sniff, IP, TCP, UDP
import csv
import os

FILENAME = "traffic_data.csv"

print("Current working directory:", os.getcwd())
print("Creating dataset file:", FILENAME)

with open(FILENAME, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["length", "protocol", "src_port", "dst_port"])

def collect(packet):
    if IP in packet:
        length = len(packet)
        protocol = packet[IP].proto

        src_port = 0
        dst_port = 0

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        with open(FILENAME, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([length, protocol, src_port, dst_port])

        print("Row written:", length, protocol, src_port, dst_port)

print("Collecting traffic data... Press Ctrl+C to stop.")
sniff(prn=collect, store=False)


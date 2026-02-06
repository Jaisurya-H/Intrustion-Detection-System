
from scapy.all import sniff, IP, TCP, UDP

def extract_features(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = None
            dst_port = None

        print(f"SRC:{src_ip} DST:{dst_ip} PROTO:{proto} SPORT:{src_port} DPORT:{dst_port} LEN:{length}")

print("Extracting packet features...")
sniff(prn=extract_features, store=False)

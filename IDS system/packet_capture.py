from scapy.all import sniff

def capture_packet(packet):
    print(packet.summary())

iface = r"\Device\NPF_{C413D282-471B-4CD9-B00F-705E66A1EA4B}"

print("IDS is listening on active Wi-Fi interface...")
sniff(iface=iface, prn=capture_packet, store=False)

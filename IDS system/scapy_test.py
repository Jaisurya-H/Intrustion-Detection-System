from scapy.all import sniff, conf

print("Available interfaces:")
print(conf.ifaces)

def pkt(pkt):
    print(pkt.summary())

print("Starting capture...")
sniff(prn=pkt, store=False)



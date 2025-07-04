from scapy.all import sniff, IP, Raw

def packet_callback(packet):
    if IP in packet:
        print(f"\n[+] Packet Captured:")
        print(f"    Source IP      : {packet[IP].src}")
        print(f"    Destination IP : {packet[IP].dst}")
        print(f"    Protocol       : {packet[IP].proto}")
        if Raw in packet:
            try:
                payload = packet[Raw].load
                print(f"    Payload        : {payload.decode('utf-8', errors='ignore')}")
            except:
                print("    Payload        : [Unable to decode]")
    else:
        print("\n[!] Non-IP packet detected.")

print("📡 Packet Sniffer started... Press Ctrl+C to stop.\n")
sniff(prn=packet_callback, store=0)
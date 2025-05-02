from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Determine protocol name
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        elif proto == 1:
            protocol = "ICMP"
        else:
            protocol = f"Other ({proto})"

        print(f"\n[+] Packet: {protocol}")
        print(f"    From: {src_ip} --> To: {dst_ip}")

        # Show payload if available
        if Raw in packet:
            payload = packet[Raw].load
            print(f"    Payload (hex): {payload[:50].hex()}")

# Sniff packets (requires root/admin privileges)
print("Starting packet sniffer... (Press Ctrl+C to stop)")
sniff(filter="ip", prn=packet_callback,store=False)
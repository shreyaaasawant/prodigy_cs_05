from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Determine the protocol
        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        else:
            proto_name = "Other"
        
        # Print packet details
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {proto_name}")
        
        # Print payload data for TCP/UDP
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
            print(f"Payload: {payload}")
        elif packet.haslayer(UDP):
            payload = bytes(packet[UDP].payload)
            print(f"Payload: {payload}")
        print("")

def main():
    # Sniff packets on the network interface
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, filter="ip", store=0)

if __name__ == "__main__":
    main()
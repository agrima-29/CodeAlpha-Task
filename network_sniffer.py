from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"TCP packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
        
        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"UDP packet: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")
        else:
            print(f"Other IP packet: {ip_src} -> {ip_dst}")

sniff(count=10, prn=packet_callback)
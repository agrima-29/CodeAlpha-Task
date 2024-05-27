from scapy.all import sniff, IP, TCP, UDP

def pack_callback(pack):
    
    if IP in pack:
        ip_src = pack[IP].src
        ip_dst = pack[IP].dst

        
        if TCP in pack:
            tcp_sport = pack[TCP].sport
            tcp_dport = pack[TCP].dport
            print(f"TCP Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
        
        
        elif UDP in pack:
            udp_sport = pack[UDP].sport
            udp_dport = pack[UDP].dport
            print(f"UDP Packet: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")
        else:
            print(f"Other IP Packet: {ip_src} -> {ip_dst}")


sniff(count=10, prn=pack_callback)
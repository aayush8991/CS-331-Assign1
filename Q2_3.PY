from scapy.all import rdpcap, TCP
import sympy

def find_matching_tcp_packets(pcap_file):
    packets = rdpcap(pcap_file)

    print("Analyzing packets for specific IP and port conditions...")

    match_count = 0
    for packet in packets:
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]

            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            src_ip = packet["IP"].src

            if src_ip.startswith("18.234."):
                if sympy.isprime(src_port) and dst_port % 11 == 0:
                    dst_ip = packet["IP"].dst
                    print(f"Specific Match Found: Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}")
                    match_count += 1

    print(f"Total number of packets matching the specific IP and port criteria: {match_count}")

pcap_file = '7.pcap'
find_matching_tcp_packets(pcap_file)

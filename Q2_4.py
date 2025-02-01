from scapy.all import rdpcap, TCP
import sympy

def find_matching_tcp_packets(pcap_file):
    packets = rdpcap(pcap_file)

    print("Analyzing packets for Sequence + Acknowledgment conditions...")

    for packet in packets:
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]

            seq_num = tcp_layer.seq
            ack_num = tcp_layer.ack

            if seq_num + ack_num == 2512800625:
                checksum = tcp_layer.chksum

                if hex(checksum).endswith("70"):
                    src_ip = packet["IP"].src
                    dst_ip = packet["IP"].dst
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport

                    print(f"Sequence + Acknowledgment Match Found: Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}, Sequence: {seq_num}, Acknowledgment: {ack_num}, Checksum: {hex(checksum)}")

pcap_file = '7.pcap'
find_matching_tcp_packets(pcap_file)

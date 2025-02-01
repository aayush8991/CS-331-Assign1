from scapy.all import rdpcap, TCP

def find_matching_tcp_packets(pcap_file):
    try:
        # Read packets from the PCAP file
        packets = rdpcap(pcap_file)

        print("Analyzing packets for ACK and PSH conditions...")

        count = 0
        for packet in packets:
            # Check if the packet has a TCP layer
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]

                # Extract flags
                flags = tcp_layer.flags
                syn_flag = (flags & 0x02 != 0)  # Check if SYN flag is set

                if syn_flag:
                    # Get source port and sequence number
                    src_port = tcp_layer.sport
                    seq_num = tcp_layer.seq

                    # Check conditions: Source Port divisible by 11 and Sequence Number > 100000
                    if src_port % 11 == 0 and seq_num > 100000:
                        src_ip = packet["IP"].src
                        dst_ip = packet["IP"].dst
                        print(f"SYN Match Found: Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Sequence Number: {seq_num}")
                        count += 1

        print(f"Total number of SYN packets matching the criteria: {count}")

    except Exception as e:
        print(f"Error processing PCAP file: {e}")

# Specify the path to your PCAP file
pcap_file = '7.pcap'
find_matching_tcp_packets(pcap_file)
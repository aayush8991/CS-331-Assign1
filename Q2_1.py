from scapy.all import rdpcap, TCP

def find_matching_tcp_packets(pcap_file):
    try:
        # Read packets from the PCAP file
        packets = rdpcap(pcap_file)

        print("Analyzing packets...")


        # print(*packets)
        for packet in packets:
            # Check if the packet has a TCP layer
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]

                # Extract flags
                flags = tcp_layer.flags
                ack_flag = flags & 0x10 != 0  # Check if ACK flag is set
                psh_flag = flags & 0x08 != 0  # Check if PSH flag is set

                if ack_flag and psh_flag:
                    # Get source and destination port numbers
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport

                    # Check if the sum of source and destination ports equals 60303
                    if src_port + dst_port == 60303:
                        src_ip = packet["IP"].src
                        dst_ip = packet["IP"].dst

                        print(f"Match Found: Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}")

        print("Analysis complete.")

    except Exception as e:
        print(f"Error processing PCAP file: {e}")

# Specify the path to your PCAP file
pcap_file = '7.pcap'
find_matching_tcp_packets(pcap_file)

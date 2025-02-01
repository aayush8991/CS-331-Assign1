import argparse
import time
from scapy.all import sniff, TCP
from collections import defaultdict
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import sympy

# Global variables
captured_packets = []
start_time = 0

def packet_callback(packet):
    """Minimal processing during capture to prevent losses"""
    captured_packets.append(packet)

def analyze_packets():
    """Process all metrics after capture is complete"""
    total_data = 0
    packet_sizes = []
    unique_pairs = set()
    src_counts = defaultdict(int)
    dst_counts = defaultdict(int)
    data_transferred = defaultdict(int)

    for packet in captured_packets:
        if 'IP' in packet:
            # Basic packet metrics
            packet_size = len(packet)
            total_data += packet_size
            packet_sizes.append(packet_size)

            # Extract IP information
            ip = packet['IP']
            src_ip = ip.src
            dst_ip = ip.dst
            
            # Get ports if TCP/UDP present
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            else:
                src_port = None
                dst_port = None

            # Update statistics
            pair = (src_ip, src_port, dst_ip, dst_port)
            unique_pairs.add(pair)
            src_counts[src_ip] += 1
            dst_counts[dst_ip] += 1
            data_transferred[pair] += packet_size

    return {
        'total_data': total_data,
        'total_packets': len(captured_packets),
        'packet_sizes': packet_sizes,
        'unique_pairs': unique_pairs,
        'src_counts': src_counts,
        'dst_counts': dst_counts,
        'data_transferred': data_transferred
    }

def print_summary(stats):
    """Print capture summary"""
    elapsed_time = time.time() - start_time
    
    # Calculate speeds
    pps = stats['total_packets'] / elapsed_time
    mbps = (stats['total_data'] * 8) / (elapsed_time * 1000000)
    
    print("\n=== Capture Summary ===")
    print(f"Duration: {elapsed_time:.2f} seconds")
    print(f"Total Packets: {stats['total_packets']}")
    print(f"Total Data: {stats['total_data']} bytes")
    # print(f"Speed: {pps:.2f} pps")
    # print(f"Throughput: {mbps:.2f} Mbps")
    
    if stats['packet_sizes']:
        print(f"Min Packet Size: {min(stats['packet_sizes'])} bytes")
        print(f"Max Packet Size: {max(stats['packet_sizes'])} bytes")
        print(f"Avg Packet Size: {sum(stats['packet_sizes']) / len(stats['packet_sizes']):.2f} bytes")
    
    # Find max data transfer pair
    if stats['data_transferred']:
        max_pair = max(stats['data_transferred'].items(), key=lambda x: x[1])
        src_ip, src_port, dst_ip, dst_port = max_pair[0]
        print(f"\nMost Active Flow:")
        print(f"{src_ip}:{src_port} → {dst_ip}:{dst_port}")
        print(f"Transferred: {max_pair[1]} bytes")

def save_results(stats):
    """Save results to files"""
    with open('pcap__analysis.txt', 'w') as f:
        f.write("=== Complete Analysis Results ===\n\n")
        
        f.write("Basic Statistics:\n")
        f.write(f"Total IP packets: {stats['total_packets']:,}\n")
        f.write(f"Total data: {stats['total_data']:,} bytes\n")
        
        if stats['packet_sizes']:
            f.write(f"Min packet size: {min(stats['packet_sizes']):,} bytes\n")
            f.write(f"Max packet size: {max(stats['packet_sizes']):,} bytes\n")
            f.write(f"Avg packet size: {sum(stats['packet_sizes']) / len(stats['packet_sizes']):.2f} bytes\n\n")
        
        f.write(f"Unique source-destination pairs: {len(stats['unique_pairs']):,}\n\n")
        
        f.write("All Source IP Flows:\n")
        for ip, count in sorted(stats['src_counts'].items(), key=lambda x: x[1], reverse=True):
            f.write(f"{ip}: {count:,} flows\n")
        
        f.write("\nAll Destination IP Flows:\n")
        for ip, count in sorted(stats['dst_counts'].items(), key=lambda x: x[1], reverse=True):
            f.write(f"{ip}: {count:,} flows\n")
        
        f.write("\nAll Flows with Data Amounts:\n")
        for flow, data_amount in sorted(stats['data_transferred'].items(), key=lambda x: x[1], reverse=True):
            src_ip, src_port, dst_ip, dst_port = flow
            f.write(f"{src_ip}:{src_port} → {dst_ip}:{dst_port}: {data_amount:,} bytes\n")

def plot_packet_sizes(packet_sizes):
    """Create and save packet size distribution plot"""
    plt.figure(figsize=(10, 6))
    plt.hist(packet_sizes, bins=50, color='blue', alpha=0.7)
    plt.title("Packet Size Distribution")
    plt.xlabel("Size (bytes)")
    plt.ylabel("Frequency")
    plt.savefig("packet_distribution.png")
    plt.close()

def main(interface, duration):
    """Main capture and analysis function"""
    global start_time
    
    print(f"Starting capture on {interface} for {duration} seconds...")
    start_time = time.time()
    
    # Capture phase
    sniff(iface=interface, prn=packet_callback, timeout=duration)
    
    # Analysis phase
    print("Capture complete. Processing data...")
    stats = analyze_packets()
    
    # Output phase
    print_summary(stats)
    save_results(stats)
    plot_packet_sizes(stats['packet_sizes'])
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Packet Analyzer")
    parser.add_argument("--interface", required=True, help="Network interface to capture from")
    parser.add_argument("--time", type=int, required=True, help="Capture duration in seconds")
    args = parser.parse_args()
    
    main(args.interface, args.time)


# import argparse
# import time
# from scapy.all import sniff
# from collections import defaultdict
# import matplotlib
# matplotlib.use('TkAgg')
# import matplotlib.pyplot as plt

# total_data = 0
# total_packets = 0
# packet_sizes = []
# unique_pairs = set()
# src_counts = defaultdict(int)
# dst_counts = defaultdict(int)
# data_transferred = defaultdict(int)
# captured_packets = []  # Store packets here instead of processing them immediately

# def count(packet):
#     captured_packets.append(packet)

# def capture_packets(interface, duration):
#     global start_time, captured_packets
#     start_time = time.time()
#     print(f"Listening on {interface} for {duration} seconds...")

#     try:
#         sniff(iface=interface, prn=count, timeout=duration)

#     except KeyboardInterrupt:
#         print("\nStopping packet capture...\n")

#     process_packets()
#     summarize_results()

# def process_packets():
#     global total_data, total_packets

#     for packet in captured_packets:
#         if 'IP' in packet:
#             src = packet['IP'].src
#             dst = packet['IP'].dst
#             src_port = packet['IP'].sport if 'sport' in packet['IP'].fields else None
#             dst_port = packet['IP'].dport if 'dport' in packet['IP'].fields else None

#             packet_size = len(packet)
#             total_data += packet_size
#             total_packets += 1
#             packet_sizes.append(packet_size)

#             unique_pairs.add((src, src_port, dst, dst_port))
#             src_counts[src] += 1
#             dst_counts[dst] += 1
#             data_transferred[(src, src_port, dst, dst_port)] += packet_size

# def summarize_results():
#     elapsed_time = time.time() - start_time
#     min_size = min(packet_sizes) if packet_sizes else 0
#     max_size = max(packet_sizes) if packet_sizes else 0
#     avg_size = total_data / total_packets if total_packets > 0 else 0

#     max_data_pair = max(data_transferred, key=data_transferred.get, default=None)
#     max_data_value = data_transferred[max_data_pair] if max_data_pair else 0

#     print("\n--- Final Capture Summary ---")
#     print(f"Total data captured: {total_data} bytes")
#     print(f"Total packets captured: {total_packets}")
#     print(f"Capture duration: {elapsed_time:.2f} seconds")
#     print(f"Min packet size: {min_size} bytes")
#     print(f"Max packet size: {max_size} bytes")
#     print(f"Avg packet size: {avg_size:.2f} bytes")
#     print(f"Unique Source-Destination Pairs: {len(unique_pairs)}\n")

#     if max_data_pair:
#         src, src_port, dst, dst_port = max_data_pair
#         print(f"Source-Destination pair with most data: {src}:{src_port} → {dst}:{dst_port} ({max_data_value} bytes)")

#     with open('output_live.txt', 'w') as f:
#         f.write(f"Total data: {total_data} bytes\n")
#         f.write(f"Total packets: {total_packets}\n")
#         f.write(f"Capture duration: {elapsed_time:.2f} seconds\n")
#         f.write(f"Min size: {min_size} bytes\n")
#         f.write(f"Max size: {max_size} bytes\n")
#         f.write(f"Avg size: {avg_size:.2f} bytes\n")
#         f.write(f"Unique Source-Destination Pairs: {len(unique_pairs)}\n\n")

#         f.write("Source IP flow counts:\n")
#         for src, count in src_counts.items():
#             f.write(f"  {src}: {count}\n")

#         f.write("\nDestination IP flow counts:\n")
#         for dst, count in dst_counts.items():
#             f.write(f"  {dst}: {count}\n")

#         if max_data_pair:
#             f.write(f"\nSource-Destination pair with most data:\n")
#             f.write(f"  Source: {src}, Destination: {dst}, Data: {max_data_value} bytes\n")

#     plt.hist(packet_sizes, bins=50, color='blue', alpha=0.7)
#     plt.title("Live Packet Size Distribution")
#     plt.xlabel("Size (bytes)")
#     plt.ylabel("Frequency")
#     plt.show()

# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(description="Analyze live network packets")
#     parser.add_argument("--interface", required=True, help="Network interface to capture packets from (e.g., eth0)")
#     parser.add_argument("--time", type=int, required=True, help="Duration in seconds to capture packets")
#     args = parser.parse_args()

#     capture_packets(args.interface, args.time)









# from scapy.all import *
# from time import time
# from collections import defaultdict
# import matplotlib.pyplot as plt
# capture_duration = 100
# interface = "eth0"     # Adjust to your network interface




# ##########################################     Q 1     #########################################################


# # Global variables for metrics
# packets = []
# total_data = 0

# # Callback to process each packet
# def process_packet(packet):
#     global total_data
#     packets.append(packet)
#     total_data += len(packet)

# # Start capturing
# print(f"Capturing packets for {capture_duration} seconds...")
# start_time = time()
# sniff(iface=interface, prn=process_packet, timeout=capture_duration)
# end_time = time()

# # Calculate metrics
# duration = end_time - start_time
# pps = len(packets) / duration
# mbps = (total_data * 8 / duration) / 1e6

# # Print results
# print(f"Total packets captured: {len(packets)}")
# print(f"Total data captured: {total_data} bytes")
# print(f"Capture duration: {duration:.2f} seconds")
# print(f"Packets-per-second (PPS): {pps:.2f}")
# print(f"Bandwidth (Mbps): {mbps:.2f}")



# # Metrics storage
# total_data = 0
# packet_sizes = []
# all_flows = []
# src_flow_count = defaultdict(int)
# dst_flow_count = defaultdict(int)
# flow_data = defaultdict(int)

# # Analyze packets
# for pkt in packets:
#     # Update total data and packet size
#     size = len(pkt)
#     # print(f"size is {size}")
#     total_data += size
#     packet_sizes.append(size)

#     # Extract flow details if IP layer exists
#     if "IP" in pkt:
#         src_ip = pkt["IP"].src
#         dst_ip = pkt["IP"].dst
#         src_port = pkt.sport if pkt.haslayer("TCP") or pkt.haslayer("UDP") else None
#         dst_port = pkt.dport if pkt.haslayer("TCP") or pkt.haslayer("UDP") else None

#         flow = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
#         all_flows.append(flow)

#         src_flow_count[src_ip] += 1
#         dst_flow_count[dst_ip] += 1
#         flow_data[flow] += size
# # Q1 Display results
# print(f"Total data transferred: {total_data} bytes")
# print(f"Total packets transferred: {len(packets)}")
# print(f"Minimum packet size: {min(packet_sizes)} bytes")
# print(f"Maximum packet size: {max(packet_sizes)} bytes")
# print(f"Average packet size: {sum(packet_sizes) / len(packet_sizes):.2f} bytes")


# # Plot histogram of packet sizes
# plt.hist(packet_sizes, bins=20, color='blue', edgecolor='black')
# plt.title("Packet Size Distribution")
# plt.xlabel("Packet Size (bytes)")
# plt.ylabel("Frequency")

# # Save the plot to a PNG file
# plt.savefig("packet_size_distribution.png")

# # Optionally, close the plot to free up memory
# plt.close()

# ##########################################     Q 2     #########################################################
# unique_flows = {}
# for i in all_flows:
#     if i not in unique_flows:
#         unique_flows[i] = 1
#     else:
#         unique_flows[i] += 1

# filename = 'unique_flows.txt'
# with open(filename, "w") as file:
#         for value in unique_flows:
#             file.write(str(value) + "\n")

# ##########################################     Q 3     #########################################################
# filename = 'source_flow_count.txt'
# with open(filename, "w") as file:
#         for value in src_flow_count:
#             file.write(str(value) + " : " + str(src_flow_count[value]) + "\n")

# filename = 'destination_flow_count.txt'
# with open(filename, "w") as file:
#         for value in dst_flow_count:
#             file.write(str(value) + " : " + str(dst_flow_count[value]) + "\n")

# max_flow = max(flow_data, key=flow_data.get)
# print(f"\nSource-destination pair with most data transferred: {max_flow} ({flow_data[max_flow]} bytes)")






# ##########################################     PART - 2  CATCH ME IF YOU CAN     #########################################################

# # Q1: Find the TCP packet containing the file name
# file_name = None
# tcp_checksum = None
# source_ip = None

# for packet in packets:
#     if TCP in packet and Raw in packet:
#         payload = packet[Raw].load.decode('utf-8', errors='ignore')
#         if 'The name of file is = ' in payload:
#             print(payload)
#             file_name = payload.split('The name of file is = ')[1].split('>')[0]
#             tcp_checksum = packet[TCP].chksum
#             source_ip = packet[IP].src
#             break

# print(f"Q1a. File Name: {file_name}")
# print(f"Q1b. TCP Checksum: {tcp_checksum}")
# print(f"Q1c. Source IP Address: {source_ip}")

# # Q2: Find the number of packets with that IP address
# if source_ip:
#     ip_packet_count = sum(1 for pkt in packets if IP in pkt and pkt[IP].src == source_ip)
#     print(f"Q2. Number of packets with IP {source_ip}: {ip_packet_count}")

# # Variables to store results
# file_name = None
# tcp_checksum = None
# source_ip = None
# target_ip_count = 0
# localhost_port = None
# localhost_packet_count = 0


# # Step 3: Find localhost requests for phone company name
# for packet in packets:
#     if TCP in packet and packet.haslayer(Raw):
#         payload = packet[Raw].load.decode(errors="ignore")
#         if "Company of phone" in payload:
#             print(payload)
#             localhost_port = packet[TCP].sport  # Get port used by localhost
#             break  # Stop after first match

# # Step 4: Count packets from localhost (127.0.0.1)
# localhost_packet_count = sum(1 for pkt in packets if IP in pkt and pkt[IP].src == "127.0.0.1")


# print(f"3a. Port used by localhost: {localhost_port}")
# print(f"3b. Number of packets from localhost: {localhost_packet_count}")



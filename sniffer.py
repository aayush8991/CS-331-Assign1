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
    captured_packets.append(packet)

def analyze_packets():
    total_data = 0
    packet_sizes = []
    unique_pairs = set()
    src_counts = defaultdict(int)
    dst_counts = defaultdict(int)
    data_transferred = defaultdict(int)

    for packet in captured_packets:
        if 'IP' in packet:
            packet_size = len(packet)
            total_data += packet_size
            packet_sizes.append(packet_size)

            ip = packet['IP']
            src_ip = ip.src
            dst_ip = ip.dst
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            else:
                src_port = None
                dst_port = None

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
    
    pps = stats['total_packets'] / elapsed_time
    mbps = (stats['total_data'] * 8) / (elapsed_time * 1000000)
    
    print("\n=== Capture Summary ===")
    print(f"Duration: {elapsed_time:.2f} seconds")
    print(f"Total Packets: {stats['total_packets']}")
    print(f"Total Data: {stats['total_data']} bytes")

    
    if stats['packet_sizes']:
        print(f"Min Packet Size: {min(stats['packet_sizes'])} bytes")
        print(f"Max Packet Size: {max(stats['packet_sizes'])} bytes")
        print(f"Avg Packet Size: {sum(stats['packet_sizes']) / len(stats['packet_sizes']):.2f} bytes")
    
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
    
    sniff(iface=interface, prn=packet_callback, timeout=duration)
    
    print("Capture complete. Processing data...")
    stats = analyze_packets()
    
    print_summary(stats)
    save_results(stats)
    plot_packet_sizes(stats['packet_sizes'])
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Packet Analyzer")
    parser.add_argument("--interface", required=True, help="Network interface to capture from")
    parser.add_argument("--time", type=int, required=True, help="Capture duration in seconds")
    args = parser.parse_args()
    
    main(args.interface, args.time)



import argparse
import time
from scapy.all import sniff
from collections import defaultdict
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt

total_data = 0
total_packets = 0
packet_sizes = []
unique_pairs = set()
src_counts = defaultdict(int)
dst_counts = defaultdict(int)
data_transferred = defaultdict(int)
captured_packets = []  # Store packets here instead of processing them immediately

def count(packet):
    captured_packets.append(packet)

def capture_packets(interface, duration):
    global start_time, captured_packets
    start_time = time.time()
    print(f"Listening on {interface} for {duration} seconds...")

    try:
        sniff(iface=interface, prn=count, timeout=duration)

    except KeyboardInterrupt:
        print("\nStopping packet capture...\n")

    process_packets()
    summarize_results()

def process_packets():
    global total_data, total_packets

    for packet in captured_packets:
        if 'IP' in packet:
            src = packet['IP'].src
            dst = packet['IP'].dst
            src_port = packet['IP'].sport if 'sport' in packet['IP'].fields else None
            dst_port = packet['IP'].dport if 'dport' in packet['IP'].fields else None

            packet_size = len(packet)
            total_data += packet_size
            total_packets += 1
            packet_sizes.append(packet_size)

            unique_pairs.add((src, src_port, dst, dst_port))
            src_counts[src] += 1
            dst_counts[dst] += 1
            data_transferred[(src, src_port, dst, dst_port)] += packet_size

def summarize_results():
    elapsed_time = time.time() - start_time
    min_size = min(packet_sizes) if packet_sizes else 0
    max_size = max(packet_sizes) if packet_sizes else 0
    avg_size = total_data / total_packets if total_packets > 0 else 0

    max_data_pair = max(data_transferred, key=data_transferred.get, default=None)
    max_data_value = data_transferred[max_data_pair] if max_data_pair else 0

    print("\n--- Final Capture Summary ---")
    print(f"Total data captured: {total_data} bytes")
    print(f"Total packets captured: {total_packets}")
    print(f"Capture duration: {elapsed_time:.2f} seconds")
    print(f"Min packet size: {min_size} bytes")
    print(f"Max packet size: {max_size} bytes")
    print(f"Avg packet size: {avg_size:.2f} bytes")
    print(f"Unique Source-Destination Pairs: {len(unique_pairs)}\n")

    if max_data_pair:
        src, src_port, dst, dst_port = max_data_pair
        print(f"Source-Destination pair with most data: {src}:{src_port} → {dst}:{dst_port} ({max_data_value} bytes)")

    with open('output_live.txt', 'w') as f:
        f.write(f"Total data: {total_data} bytes\n")
        f.write(f"Total packets: {total_packets}\n")
        f.write(f"Capture duration: {elapsed_time:.2f} seconds\n")
        f.write(f"Min size: {min_size} bytes\n")
        f.write(f"Max size: {max_size} bytes\n")
        f.write(f"Avg size: {avg_size:.2f} bytes\n")
        f.write(f"Unique Source-Destination Pairs: {len(unique_pairs)}\n\n")

        f.write("Source IP flow counts:\n")
        for src, count in src_counts.items():
            f.write(f"  {src}: {count}\n")

        f.write("\nDestination IP flow counts:\n")
        for dst, count in dst_counts.items():
            f.write(f"  {dst}: {count}\n")

        if max_data_pair:
            f.write(f"\nSource-Destination pair with most data:\n")
            f.write(f"  Source: {src}, Destination: {dst}, Data: {max_data_value} bytes\n")

    plt.hist(packet_sizes, bins=50, color='blue', alpha=0.7)
    plt.title("Live Packet Size Distribution")
    plt.xlabel("Size (bytes)")
    plt.ylabel("Frequency")
    plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze live network packets")
    parser.add_argument("--interface", required=True, help="Network interface to capture packets from (e.g., eth0)")
    parser.add_argument("--time", type=int, required=True, help="Duration in seconds to capture packets")
    args = parser.parse_args()

    capture_packets(args.interface, args.time)
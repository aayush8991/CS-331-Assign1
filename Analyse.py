import argparse
from scapy.all import rdpcap
from collections import defaultdict
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt

def analyze_packets(pcap_file):
    packets = rdpcap(pcap_file)

    total_data = sum(len(packet) for packet in packets)
    total_packets = len(packets)
    packet_sizes = [len(packet) for packet in packets]
    min_size = min(packet_sizes)
    max_size = max(packet_sizes)
    avg_size = total_data / total_packets if total_packets > 0 else 0

    unique_pairs = set()
    src_counts = defaultdict(int)
    dst_counts = defaultdict(int)
    data_transferred = defaultdict(int)

    for packet in packets:
        if 'IP' in packet:
            src = packet['IP'].src
            dst = packet['IP'].dst
            src_port = packet['IP'].sport if 'sport' in packet['IP'].fields else None
            dst_port = packet['IP'].dport if 'dport' in packet['IP'].fields else None

            unique_pairs.add((src, src_port, dst, dst_port))
            src_counts[src] += 1
            dst_counts[dst] += 1

            # Track data transferred for each source-destination pair
            key = (src, src_port, dst, dst_port)
            data_transferred[key] += len(packet)

    max_data_pair = max(data_transferred, key=data_transferred.get, default=None)
    max_data_value = data_transferred[max_data_pair] if max_data_pair else 0

    print("Part 1 Q1:")
    print(f"Total data: {total_data} bytes")
    print(f"Total packets: {total_packets}")
    print(f"Min size: {min_size} bytes")
    print(f"Max size: {max_size} bytes")
    print(f"Avg size: {avg_size:.2f} bytes")

    print("\nPart 1 Q2:")
    print(f"Unique Source-Destination Pairs: {len(unique_pairs)}\n ")

    # Save results to output.txt
    with open('output.txt', 'w') as f:
        f.write(f"Total data: {total_data} bytes\n")
        f.write(f"Total packets: {total_packets}\n")
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
            src, src_port, dst, dst_port = max_data_pair
            f.write(f"\nSource-Destination pair with most data:\n")
            f.write(f"  Source: {src}, Destination: {dst}, Data: {max_data_value} bytes\n")

    # Print the source with the most data transferred in the command line
    print("Part 1 Q3:")
    if max_data_pair:
        src, src_port, dst, dst_port = max_data_pair
        print(f"Source-Destination pair with most data:")
        print(f"Source: {src}, Destination: {dst}, Data: {max_data_value} bytes\n")

    # Plot packet sizes
    plt.hist(packet_sizes, bins=50, color='blue', alpha=0.7)
    plt.title("Packet Size Distribution")
    plt.xlabel("Size (bytes)")
    plt.ylabel("Frequency")
    plt.show()

# Main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze packets in a PCAP file")
    parser.add_argument("--pcap", required=True, help="Path to the pcap file")
    args = parser.parse_args()
    analyze_packets(args.pcap)
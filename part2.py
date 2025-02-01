from scapy.all import sniff, TCP
import argparse
import time
import sympy

# Global storage for captured packets
captured_packets = []

def packet_callback(packet):
    """Store packets with minimal processing to prevent loss"""
    captured_packets.append(packet)

def analyze_tcp_question1(file):
    """Find TCP packets with ACK+PSH flags and port sum = 60303"""
    file.write("\nQuestion 1: TCP Packets with ACK+PSH flags and port sum = 60303\n")
    file.write("-" * 70 + "\n")
    
    matches = 0
    for packet in captured_packets:
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.flags & 0x18 == 0x18:  # Both ACK and PSH are set
                if tcp.sport + tcp.dport == 60303:
                    matches += 1
                    file.write(f"Match {matches}:\n")
                    file.write(f"Source IP: {packet['IP'].src}\n")
                    file.write(f"Destination IP: {packet['IP'].dst}\n")
                    file.write(f"Source Port: {tcp.sport}\n")
                    file.write(f"Destination Port: {tcp.dport}\n\n")
    
    if matches == 0:
        file.write("No matching packets found.\n")
    print(f"Question 1: Found {matches} matches")

def analyze_tcp_question2(file):
    """Find TCP packets with specific conditions"""
    file.write("\nQuestion 2: TCP Packets with SYN flag, source port % 11 = 0, seq > 100000\n")
    file.write("-" * 70 + "\n")
    
    matches = 0
    for packet in captured_packets:
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.flags & 0x02:
                if tcp.sport % 11 == 0 and tcp.seq > 100000:
                    matches += 1
                    file.write(f"Match {matches}:\n")
                    file.write(f"Source IP: {packet['IP'].src}\n")
                    file.write(f"Destination IP: {packet['IP'].dst}\n")
                    file.write(f"Source Port: {tcp.sport}\n")
                    file.write(f"Sequence Number: {tcp.seq}\n\n")
    
    file.write(f"Total matching packets: {matches}\n")
    print(f"Question 2: Found {matches} matches")

def analyze_tcp_question3(file):
    """Find TCP packets with specific IP and port conditions"""
    file.write("\nQuestion 3: TCP Packets from 18.234.xx.xxx with prime source port and dst port % 11 = 0\n")
    file.write("-" * 70 + "\n")
    
    matches = 0
    for packet in captured_packets:
        if packet.haslayer(TCP) and packet.haslayer('IP'):
            tcp = packet[TCP]
            if packet['IP'].src.startswith('18.234.'):
                if sympy.isprime(tcp.sport) and tcp.dport % 11 == 0:
                    matches += 1
                    file.write(f"Match {matches}:\n")
                    file.write(f"Source IP: {packet['IP'].src}\n")
                    file.write(f"Destination IP: {packet['IP'].dst}\n")
                    file.write(f"Source Port (prime): {tcp.sport}\n")
                    file.write(f"Destination Port: {tcp.dport}\n\n")
    
    file.write(f"Total matching packets: {matches}\n")
    print(f"Question 3: Found {matches} matches")

def analyze_tcp_question4(file):
    """Find TCP packets with specific sequence and checksum conditions"""
    file.write("\nQuestion 4: TCP Packets with seq + ack = 2512800625 and checksum ending in 70\n")
    file.write("-" * 70 + "\n")
    
    matches = 0
    for packet in captured_packets:
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.seq + tcp.ack == 2512800625:
                if hex(tcp.chksum)[-2:] == '70':
                    matches += 1
                    file.write(f"Match {matches}:\n")
                    file.write(f"Source IP: {packet['IP'].src}\n")
                    file.write(f"Destination IP: {packet['IP'].dst}\n")
                    file.write(f"Sequence Number: {tcp.seq}\n")
                    file.write(f"Acknowledgement Number: {tcp.ack}\n")
                    file.write(f"Checksum: {hex(tcp.chksum)}\n\n")
    
    if matches == 0:
        file.write("No matching packets found.\n")
    print(f"Question 4: Found {matches} matches")

def main(interface, duration):
    """Main capture and analysis function"""
    print(f"Starting capture on {interface} for {duration} seconds...")
    print("Waiting for tcpreplay data...\n")
    
    # Capture phase
    try:
        sniff(iface=interface, prn=packet_callback, timeout=duration)
    except Exception as e:
        print(f"Error during capture: {e}")
        return
    
    print(f"Capture complete. Total packets captured: {len(captured_packets)}")
    
    # Analysis phase
    try:
        with open('tcp_analysis_results.txt', 'w') as f:
            f.write("=== TCP Packet Analysis Results ===\n")
            f.write(f"Total packets captured: {len(captured_packets)}\n")
            f.write(f"Analysis timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            analyze_tcp_question1(f)
            analyze_tcp_question2(f)
            analyze_tcp_question3(f)
            analyze_tcp_question4(f)
            
        print("\nAnalysis complete. Results saved to 'tcp_analysis_results.txt'")
            
    except Exception as e:
        print(f"Error during analysis: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP Packet Analyzer for Part 2")
    parser.add_argument("--interface", required=True, help="Network interface to capture from")
    parser.add_argument("--time", type=int, required=True, help="Capture duration in seconds")
    args = parser.parse_args()
    
    main(args.interface, args.time)
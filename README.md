# CS-331-Assign1

# Network Packet Sniffer

## **Team Members**  
- **Aayush Parmar** (22110181)  
- **Bhoumik Patidar** (22110049)  

# Network Packet Analysis Tool

This repository contains tools for capturing and analyzing network packets, including basic packet statistics and TCP-specific analysis.

## Files
- `sniffer.py`: Main packet capture and analysis tool for basic metrics (Part 1)
- `part2.py`: TCP packet analysis tool for specific conditions (Part 2)
- `test_script.sh`: Test script to run both tools with tcpreplay
- Sample output files:
  - `pcap_analysis.txt`: Contains basic packet analysis results
  - `tcp_analysis_results.txt`: Contains TCP-specific analysis results

## Requirements
- Python 3.x
- Scapy
- Matplotlib
- tcpreplay
- sympy



## Setup
1. Clone this repository:
2. Make the test script executable:
chmod +x test_script.sh

## Usage
### Running the test script:
\```bash
./test_script.sh your_pcap_file.pcap
\```

This will:
- Run tcpreplay at 500 pps
- Execute both analysis tools
- Generate output files

### Running tools individually:
1. Part 1 (Basic Analysis):
\```bash
sudo python3 sniffer.py --interface eth0 --time 600
\```

2. Part 2 (TCP Analysis):
\```bash
sudo python3 part2.py --interface eth0 --time 600
\```

## Output Files
- `pcap_analysis.txt`: Contains
  - Total packets and data transferred
  - Packet size statistics
  - Flow information
  - Source/destination pairs

- `tcp_analysis_results.txt`: Contains analysis of TCP packets matching specific criteria:
  - ACK+PSH flags with specific port sum
  - SYN packets with specific conditions
  - Packets from specific IP ranges
  - Packets with specific sequence numbers

## Note
- Requires sudo privileges for packet capture
- Designed to work with tcpreplay for PCAP file analysis
- Default configuration uses loopback interface

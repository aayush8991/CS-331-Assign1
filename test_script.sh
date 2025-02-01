#!/bin/bash

# Check if PCAP file is provided
if [ $# -ne 1 ]; then
    echo "Error: Please provide PCAP file path"
    echo "Usage: ./test_script.sh <pcap_file>"
    exit 1
fi

PCAP_FILE=$1
INTERFACE="eth0"
DURATION=600  # 600 seconds = 10 minutes
PPS=500      # 500 packets per second

echo "=== Starting Network Analysis Test ==="
echo "PCAP File: $PCAP_FILE"
echo "Interface: $INTERFACE"
echo "Duration: $DURATION seconds"
echo "Rate: $PPS pps"

# Part 1: Packet Analysis
echo -e "\n=== Running Part 1: Packet Analysis ==="
# Start tcpreplay with specified pps
sudo tcpreplay --pps=$PPS -i $INTERFACE $PCAP_FILE &
TCPREPLAY_PID=$!

# Run sniffer.py
sudo python3 sniffer.py --interface $INTERFACE --time $DURATION

# Kill tcpreplay
kill $TCPREPLAY_PID 2>/dev/null

# Part 2: TCP Analysis
echo -e "\n=== Running Part 2: TCP Analysis ==="
# Start tcpreplay again
sudo tcpreplay --pps=$PPS -i $INTERFACE $PCAP_FILE &
TCPREPLAY_PID=$!

# Run part2.py
sudo python3 part2.py --interface $INTERFACE --time $DURATION

# Kill tcpreplay
kill $TCPREPLAY_PID 2>/dev/null

echo -e "\n=== Test Complete ==="
echo "Check the following output files:"
echo "- pcap_analysis.txt"
echo "- packet_size_distribution.png"
echo "- tcp_analysis_results.txt"
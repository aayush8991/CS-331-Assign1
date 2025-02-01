# CS-331-Assign1

# Network Packet Sniffer

## **Team Members**  
- **Aayush Parmar** (22110181)  
- **Bhoumik Patidar** (22110049)  

## **Overview**  
The `sniffer.py` file uses the `scapy` library in Python to capture network packets and store them in a list. These packets are then used to answer specific network-related questions.  

## **Requirements**  
- `scapy`  
- `argparse`  

## **Usage**  

### **Running the Packet Sniffer**  
To run `sniffer.py`, use the following command:  

```bash
python3 sniffer.py --interface eth0 --time 60
```
To run tcpreplay, use the following comman:

```bash
tcpreplay --intf1=eth0 --pps=500 7.pcap
```
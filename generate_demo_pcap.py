#!/usr/bin/env python3
"""
Generates a synthetic .pcap file simulating a port scan and an ICMP flood,
so NetGuard can be demoed/tested without needing live network capture
privileges. Run this once, then:

    python3 netguard.py --pcap sample_output/sample_capture.pcap
"""

from scapy.all import IP, TCP, ICMP, wrpcap
import random

packets = []
attacker_ip = "10.0.0.66"
victim_ip = "10.0.0.10"

# --- Simulate a port scan: attacker probes 20 different ports quickly ---
for port in range(1, 21):
    pkt = IP(src=attacker_ip, dst=victim_ip) / TCP(dport=port, flags="S")
    packets.append(pkt)

# --- Simulate an ICMP flood: 60 ping packets from the same attacker ---
for _ in range(60):
    pkt = IP(src=attacker_ip, dst=victim_ip) / ICMP()
    packets.append(pkt)

# --- Simulate brute-force pattern: 25 attempts on port 22 (SSH) ---
for _ in range(25):
    pkt = IP(src=attacker_ip, dst=victim_ip) / TCP(dport=22, flags="S")
    packets.append(pkt)

# --- Some normal, benign traffic mixed in ---
normal_ip = "10.0.0.20"
for port in [80, 443]:
    pkt = IP(src=normal_ip, dst=victim_ip) / TCP(dport=port, flags="S")
    packets.append(pkt)

random.shuffle(packets)
wrpcap("sample_output/sample_capture.pcap", packets)
print(f"[+] Generated {len(packets)} packets -> sample_output/sample_capture.pcap")

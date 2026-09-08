#!/usr/bin/env python3
"""
NetGuard - A Lightweight Network Intrusion Detection Tool
============================================================
Author: <YOUR NAME HERE>
Course: Arabian Academy - Prove It Challenge (Day 03)

Description:
    NetGuard is a mini SOC-style detection tool that monitors network
    traffic (live or from a .pcap file) and flags common malicious
    activity patterns:

        1. Port Scanning      -> many distinct ports probed by one IP
        2. ICMP Flood         -> abnormal volume of ping packets (DoS-like)
        3. Brute-force pattern-> repeated connection attempts to one port

    Every detection is logged with a timestamp, source IP, and alert type,
    simulating how a real SOC detection/alerting pipeline works.

Usage:
    sudo python3 netguard.py                # live capture (needs root)
    python3 netguard.py --pcap file.pcap    # analyze a saved capture
"""

import argparse
import json
import csv
import time
import sys
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, rdpcap, IP, TCP, ICMP
except ImportError:
    print("[!] Scapy is not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

import config


class NetGuard:
    def __init__(self):
        # Tracks: {src_ip: [(timestamp, dst_port), ...]}  -> for port scan detection
        self.port_activity = defaultdict(list)

        # Tracks: {src_ip: [timestamp, ...]} -> for ICMP flood detection
        self.icmp_activity = defaultdict(list)

        # Tracks: {(src_ip, dst_port): [timestamp, ...]} -> for brute-force detection
        self.connection_activity = defaultdict(list)

        # Prevent duplicate alerts spamming the log for the same ongoing event
        self.recent_alerts = {}
        self.alert_cooldown = 30  # seconds before the same alert type/IP can fire again

        self.alerts_raised = 0
        self._init_log_file()

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    def _init_log_file(self):
        if config.LOG_FORMAT == "csv":
            with open(config.LOG_FILE.replace(".log", ".csv"), "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "alert_type", "source_ip", "details"])

    def log_alert(self, alert_type, source_ip, details):
        # Cooldown check to avoid flooding the log with the same alert
        key = (alert_type, source_ip)
        now = time.time()
        if key in self.recent_alerts and now - self.recent_alerts[key] < self.alert_cooldown:
            return
        self.recent_alerts[key] = now

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.alerts_raised += 1

        entry = {
            "timestamp": timestamp,
            "alert_type": alert_type,
            "source_ip": source_ip,
            "details": details,
        }

        # Print to console immediately (real-time alerting)
        print(f"[ALERT] {timestamp} | {alert_type} | Source: {source_ip} | {details}")

        # Persist to disk
        if config.LOG_FORMAT == "csv":
            with open(config.LOG_FILE.replace(".log", ".csv"), "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, alert_type, source_ip, details])
        else:
            with open(config.LOG_FILE.replace(".log", ".json"), "a") as f:
                f.write(json.dumps(entry) + "\n")

    # ------------------------------------------------------------------
    # Detection Logic
    # ------------------------------------------------------------------
    def _prune_old(self, records, window):
        """Remove timestamps older than the sliding window."""
        cutoff = time.time() - window
        return [r for r in records if r[0] >= cutoff] if records and isinstance(records[0], tuple) \
            else [t for t in records if t >= cutoff]

    def detect_port_scan(self, src_ip, dst_port):
        now = time.time()
        self.port_activity[src_ip].append((now, dst_port))
        self.port_activity[src_ip] = self._prune_old(
            self.port_activity[src_ip], config.PORT_SCAN_TIME_WINDOW
        )

        distinct_ports = {p for _, p in self.port_activity[src_ip]}
        if len(distinct_ports) >= config.PORT_SCAN_THRESHOLD:
            self.log_alert(
                "PORT_SCAN",
                src_ip,
                f"{len(distinct_ports)} distinct ports probed in "
                f"{config.PORT_SCAN_TIME_WINDOW}s window",
            )

    def detect_icmp_flood(self, src_ip):
        now = time.time()
        self.icmp_activity[src_ip].append(now)
        self.icmp_activity[src_ip] = self._prune_old(
            self.icmp_activity[src_ip], config.ICMP_FLOOD_TIME_WINDOW
        )

        if len(self.icmp_activity[src_ip]) >= config.ICMP_FLOOD_THRESHOLD:
            self.log_alert(
                "ICMP_FLOOD",
                src_ip,
                f"{len(self.icmp_activity[src_ip])} ICMP packets in "
                f"{config.ICMP_FLOOD_TIME_WINDOW}s window",
            )

    def detect_brute_force(self, src_ip, dst_port):
        now = time.time()
        key = (src_ip, dst_port)
        self.connection_activity[key].append(now)
        self.connection_activity[key] = self._prune_old(
            self.connection_activity[key], config.BRUTE_FORCE_TIME_WINDOW
        )

        if len(self.connection_activity[key]) >= config.BRUTE_FORCE_THRESHOLD:
            self.log_alert(
                "BRUTE_FORCE_PATTERN",
                src_ip,
                f"{len(self.connection_activity[key])} attempts to port {dst_port} "
                f"in {config.BRUTE_FORCE_TIME_WINDOW}s window",
            )

    # ------------------------------------------------------------------
    # Packet Handler
    # ------------------------------------------------------------------
    def process_packet(self, packet):
        if IP not in packet:
            return

        src_ip = packet[IP].src

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            self.detect_port_scan(src_ip, dst_port)
            self.detect_brute_force(src_ip, dst_port)

        elif packet.haslayer(ICMP):
            self.detect_icmp_flood(src_ip)

    # ------------------------------------------------------------------
    # Entry Points
    # ------------------------------------------------------------------
    def run_live(self, interface=None):
        print(f"[*] NetGuard starting live capture on interface: {interface or 'default'}")
        print(f"[*] Logging alerts to: {config.LOG_FILE.replace('.log', '.' + config.LOG_FORMAT)}")
        print("[*] Press Ctrl+C to stop.\n")
        try:
            sniff(iface=interface, prn=self.process_packet, store=False)
        except KeyboardInterrupt:
            print(f"\n[*] Stopped. Total alerts raised: {self.alerts_raised}")
        except PermissionError:
            print("[!] Permission denied. Try running with sudo.")

    def run_pcap(self, path):
        print(f"[*] Analyzing pcap file: {path}")
        packets = rdpcap(path)
        for pkt in packets:
            self.process_packet(pkt)
        print(f"\n[*] Analysis complete. Total alerts raised: {self.alerts_raised}")


def main():
    parser = argparse.ArgumentParser(description="NetGuard - Mini Network Intrusion Detection Tool")
    parser.add_argument("--pcap", help="Path to a .pcap file to analyze instead of live sniffing")
    parser.add_argument("--iface", help="Network interface to sniff on (live mode only)")
    args = parser.parse_args()

    ng = NetGuard()

    if args.pcap or config.READ_FROM_PCAP:
        pcap_path = args.pcap or config.PCAP_FILE_PATH
        ng.run_pcap(pcap_path)
    else:
        ng.run_live(interface=args.iface or config.NETWORK_INTERFACE)


if __name__ == "__main__":
    main()

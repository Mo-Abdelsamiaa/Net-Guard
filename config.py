"""
NetGuard - Configuration File
------------------------------
Adjust these thresholds to tune detection sensitivity
based on the network environment you are monitoring.
"""

# --- Port Scan Detection ---
# Number of DIFFERENT destination ports a single source IP
# can attempt to connect to within TIME_WINDOW before it's flagged.
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_TIME_WINDOW = 15  # seconds

# --- ICMP Flood Detection ---
# Number of ICMP (ping) packets from a single source IP
# within TIME_WINDOW before it's flagged as a potential flood/DoS.
ICMP_FLOOD_THRESHOLD = 50
ICMP_FLOOD_TIME_WINDOW = 5  # seconds

# --- Repeated Failed Connection (Brute-force pattern) ---
# Number of connection attempts to the SAME destination port
# from a single source IP within TIME_WINDOW.
BRUTE_FORCE_THRESHOLD = 20
BRUTE_FORCE_TIME_WINDOW = 15  # seconds

# --- Logging ---
LOG_FILE = "alerts.log"
LOG_FORMAT = "json"  # options: "json" or "csv"

# --- Capture Settings ---
# Set to None to sniff on the default interface, or provide
# an interface name (e.g. "eth0") to sniff a specific one.
NETWORK_INTERFACE = None

# If True, the tool reads from a .pcap file instead of live sniffing.
# Useful for testing/demo without needing raw socket privileges.
READ_FROM_PCAP = False
PCAP_FILE_PATH = "sample_output/sample_capture.pcap"

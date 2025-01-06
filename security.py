from scapy.all import sniff
from collections import defaultdict
import time
import logging

# Configure logging to log detected intrusions to a file
logging.basicConfig(
    filename="ids_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Dictionary to track connection attempts per source IP
connection_attempts = defaultdict(list)

# Function to log intrusions
def log_intrusion(message):
    logging.info(message)
    print(message)

# Function to detect brute force attacks based on repeated connection attempts
def detect_brute_force(packet):
    try:
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            current_time = time.time()

            # Record the timestamp for each connection attempt from this IP
            connection_attempts[src_ip].append(current_time)

            # Keep only timestamps within the last 60 seconds
            connection_attempts[src_ip] = [t for t in connection_attempts[src_ip] if current_time - t < 60]

            # Check if there are more than 10 attempts in the last 60 seconds
            if len(connection_attempts[src_ip]) > 10:
                log_intrusion(f"Brute force attack detected from {src_ip}")
    except Exception as e:
        log_intrusion(f"Error processing packet: {e}")

# Start sniffing packets on the network
if __name__ == "__main__":
    print("Starting Intrusion Detection System...")
    try:
        sniff(prn=detect_brute_force)
    except PermissionError:
        print("Permission denied: Please run the script with administrative privileges.")


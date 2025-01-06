# This program monitors the network traffic/logon attempts from users on a network. It can be used for basic auditing and security purposes. The Program logs show an example of how it functions.

from scapy.all import sniff
from collections import defaultdict
import time
import logging

logging.basicConfig(
    filename="ids_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

connection_attempts = defaultdict(list)

def log_intrusion(message):
    logging.info(message)
    print(message)

def detect_brute_force(packet):
    try:
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            current_time = time.time()

            connection_attempts[src_ip].append(current_time)

            connection_attempts[src_ip] = [t for t in connection_attempts[src_ip] if current_time - t < 60]

            if len(connection_attempts[src_ip]) > 10:
                log_intrusion(f"Brute force attack detected from {src_ip}")
    except Exception as e:
        log_intrusion(f"Error processing packet: {e}")

if __name__ == "__main__":
    print("Starting Intrusion Detection System...")
    try:
        sniff(prn=detect_brute_force)
    except PermissionError:
        print("Permission denied: Please run the script with administrative privileges.")


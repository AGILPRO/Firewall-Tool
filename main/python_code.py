import os
import subprocess
from scapy.all import *
from sklearn.tree import DecisionTreeClassifier
import numpy as np
import logging
import socket
import time

# Set up logging for attack monitoring
logging.basicConfig(filename='attack_monitoring.log', level=logging.INFO)

# Example dataset for packet classification (for demonstration purposes)
X_train = np.array([
    [12345, 80, 64, 6],   # TCP packet, allowed
    [54321, 443, 128, 6], # TCP packet, allowed
    [12345, 23, 64, 6],   # TCP packet, restricted
    [54321, 22, 32, 6],   # TCP packet, restricted
    [11111, 53, 128, 17], # UDP packet, allowed
])
y_train = np.array([0, 0, 1, 1, 0])

# Initialize and train the classifier
clf = DecisionTreeClassifier()
clf.fit(X_train, y_train)

# List to hold suspected IPs, blocked IPs, and suspend list
suspected_ips = {}
blocked_ips = set()
suspend_list = {}

# Function to classify incoming packets
def classify_packet(packet):
    features = np.array([packet.sport, packet.dport, len(packet), packet.proto]).reshape(1, -1)
    return clf.predict(features)[0]

# Function to perform reverse port scanning
def reverse_port_scan(ip_address, ports=[80, 443, 1194, 1723, 8080]):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception as e:
            logging.error(f"Error scanning {ip_address}:{port} - {e}")
            continue
    return open_ports

# Function to check if an IP might be a VPN
def is_potential_vpn(open_ports):
    vpn_ports = [1194, 1723]  # Common VPN ports for OpenVPN and PPTP
    return any(port in vpn_ports for port in open_ports)

# Function to block an IP using Windows Firewall
def block_ip(ip_address):
    try:
        rule_name = f"Block IP {ip_address}"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule", "name=", rule_name,
             "dir=in", "action=block", "remoteip=", ip_address],
            check=True
        )
        logging.info(f"IP {ip_address} has been blocked using Windows Firewall.")
        blocked_ips.add(ip_address)  # Add IP to blocked list
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP {ip_address}: {e}")

# Function to analyze and block suspected IPs
def analyze_and_block_suspected_ips():
    for ip_address, details in list(suspected_ips.items()):
        if details['checked']:
            continue

        logging.info(f"Analyzing suspected IP: {ip_address}")

        # Reverse port scan to check if the IP is a VPN IP
        open_ports = reverse_port_scan(ip_address)
        if open_ports:
            logging.info(f"Open ports on {ip_address}: {open_ports}")
            if is_potential_vpn(open_ports):
                logging.info(f"The IP {ip_address} might be a VPN.")
            else:
                logging.info(f"The IP {ip_address} is likely not a VPN.")
        else:
            logging.info(f"No open ports detected on {ip_address}.")

        # Assuming you analyze further and decide to block if classified as restricted and potential VPN
        if details['classification'] == 1 or is_potential_vpn(open_ports):
            block_ip(ip_address)
            del suspected_ips[ip_address]  # Remove from suspected list after blocking
        else:
            suspected_ips[ip_address]['checked'] = True  # Mark as checked if not blocked

# Function to check if ping, port scan, and packet sending happened within a timestamp
def check_timed_attack(ip_address):
    events = suspected_ips[ip_address].get('events', [])
    
    if len(events) >= 3:
        first_event_time = events[0]['timestamp']
        last_event_time = events[-1]['timestamp']
        if last_event_time - first_event_time <= 10:  # 10 seconds window, adjust as needed
            logging.info(f"Timed attack detected from {ip_address}. Adding to suspend list.")
            suspend_list[ip_address] = suspected_ips[ip_address]
            block_ip(ip_address)

# Function to drop packets from blocked IPs
def drop_packet(packet):
    ip_src = packet[IP].src
    if ip_src in blocked_ips:
        logging.info(f"Dropping packet from blocked IP: {ip_src}")
        return None  # Drop the packet
    return packet

# Packet handling function
def handle_packet(packet):
    if IP not in packet:
        return
    
    packet = drop_packet(packet)  # Drop packets from blocked IPs
    if packet is None:
        return
    
    ip_src = packet[IP].src
    event_type = ""

    # Classify packet
    decision = classify_packet(packet)

    # Add to suspected IPs list if classified as restricted
    if decision == 1:
        if ip_src not in suspected_ips:
            suspected_ips[ip_src] = {
                'classification': decision,
                'checked': False,
                'request_count': 0,
                'events': []
            }
        suspected_ips[ip_src]['request_count'] += 1  # Increment request count
        logging.info(f"Packet from {ip_src} is suspicious and added to the suspected IP list.")

    # Identify potential attacks and log events
    if packet.haslayer(ICMP):  # Ping
        logging.info(f"Ping detected from {ip_src}")
        event_type = "ping"
    elif packet.haslayer(TCP) or packet.haslayer(UDP):  # Port scan or packet sending
        logging.info(f"Packet detected from {ip_src} to {packet[IP].dst}")
        event_type = "port_scan" if packet.haslayer(TCP) else "packet_send"

    if event_type:
        event = {'type': event_type, 'timestamp': time.time()}
        suspected_ips[ip_src]['events'].append(event)
        check_timed_attack(ip_src)  # Check for timed attack

    # Analyze suspected IPs after processing each packet
    analyze_and_block_suspected_ips()

# Sniffing for packets
def start_sniffing():
    sniff(filter="ip", prn=handle_packet)

if __name__ == "__main__":
    print("Starting packet sniffer...")
    start_sniffing()

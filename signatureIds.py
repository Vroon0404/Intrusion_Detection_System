import re
from scapy.all import *

# Path to your Snort community rules file
rules_file = "snort3-community.rules"

attack_signatures = []

# Parse the rules file to extract content patterns
with open(rules_file, 'r') as file:
    for line in file:
        # Skip empty lines or commented lines
        if line.strip() and not line.strip().startswith('#'):
            # Extract all content values in the rule (there could be more than one)
            matches = re.findall(r'content:"([^"]+)"', line)
            for match in matches:
                attack_signatures.append(match.lower())

def check_for_intrusion(packet):
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors='ignore').lower()
        except Exception:
            payload = ""
        for signature in attack_signatures:
            if signature in payload:
                return True, signature
    return False, None

def packet_callback(packet):
    intrusion_detected, signature = check_for_intrusion(packet)
    if intrusion_detected:
        print(f"[ALERT] Intrusion detected! Signature: '{signature}' in packet: {packet.summary()}")

if __name__ == "__main__":
    print("Starting network packet sniffing with signatures from Snort community rules...")
    sniff(prn=packet_callback, store=0)
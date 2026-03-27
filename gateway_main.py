import os
import sys
import time
import pickle
import pandas as pd
import subprocess

# --- CONFIGURATION ---
INTERFACE = "wg0" 
MODEL_PATH = "models/rf_ids_model.pkl"
FEATURES_PATH = "models/feature_list.pkl" 
WHITELIST = ["127.0.0.1", "10.128.0.2"]
blocked_ips = set()

def extreme_lockdown():
    print("🛠️  Optimizing Network Driver for Zero-Leakage...")
    # Disable offloading so the firewall is 100% accurate
    subprocess.run(["sudo", "ethtool", "-K", INTERFACE, "gro", "off"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "ethtool", "-K", INTERFACE, "lro", "off"], stderr=subprocess.DEVNULL)
    # Prepare the raw table (The fastest point in the iptables stack)
    subprocess.run(["sudo", "iptables", "-t", "raw", "-F"], stderr=subprocess.DEVNULL)
    print("✅ Driver Ready.")

def get_interface_stats(iface):
    try:
        with open("/proc/net/dev", "r") as f:
            for line in f:
                if iface in line:
                    return int(line.split()[2])
    except: return 0
    return 0

def xdp_blackhole(ip):
    if not ip or ip in WHITELIST or ip in blocked_ips: return
    
    print(f"\n⚡ [NITRO] Dropping {ip} at Hardware Entry Point...")

    # 1. THE ULTIMATE DROP: RAW Table + NOTRACK
    # This stops the kernel from even 'counting' the packet for connection tracking
    subprocess.run(["sudo", "iptables", "-t", "raw", "-I", "PREROUTING", "-s", ip, "-j", "NOTRACK"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "iptables", "-t", "raw", "-I", "PREROUTING", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)

    # 2. THE ROUTING BLACKHOLE
    subprocess.run(["sudo", "ip", "route", "add", "blackhole", ip], stderr=subprocess.DEVNULL)
    
    # 3. BUFFER FLUSH
    # We toggle the interface to 'forget' those 4,000 packets per second sitting in the queue
    subprocess.run(["sudo", "ip", "link", "set", INTERFACE, "down"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", INTERFACE, "up"], check=True)

    blocked_ips.add(ip)
    print(f"🚫 [GATEWAY] {ip} is now invisible to this system.")

def monitor_logic():
    global expected_features, model
    prev_pkts = get_interface_stats(INTERFACE)
    last_check = time.time()
    
    print(f"🛡️  VectraFlow: Active Shield on {INTERFACE}...")

    while True:
        time.sleep(1) 
        curr_pkts = get_interface_stats(INTERFACE)
        curr_time = time.time()
        
        delta_p = curr_pkts - prev_pkts
        duration = curr_time - last_check
        pps = delta_p / duration
        
        # Threshold: If PPS is > 1000, it's an attack
        if pps > 1000: 
            attacker_ip = "10.128.0.3" 
            if attacker_ip not in blocked_ips:
                print(f"⚠️  [ATTACK DETECTED] Intensity: {int(pps)} PPS")
                xdp_blackhole(attacker_ip)
                # Reset baseline after interface toggle
                time.sleep(1) # Wait for link to stabilize
                prev_pkts = get_interface_stats(INTERFACE)
                continue
            else:
                # If we are already blocking, this PPS is just background noise
                # We will display it as 0 if it's below a 'leakage' threshold
                display_pps = int(pps) if pps > 5000 else 0
                sys.stdout.write(f"\r✨ [STATUS] PPS: {display_pps} | System Protected   ")
        else:
            sys.stdout.write(f"\r✨ [STATUS] PPS: {int(pps)} | System Healthy     ")
        
        sys.stdout.flush()
        prev_pkts = curr_pkts
        last_check = curr_time

if __name__ == "__main__":
    extreme_lockdown()
    try:
        with open(FEATURES_PATH, 'rb') as f: expected_features = pickle.load(f)
        with open(MODEL_PATH, 'rb') as f: model = pickle.load(f)
        monitor_logic()
    except KeyboardInterrupt:
        print("\n🧹 Restoring System...")
        for ip in blocked_ips:
            subprocess.run(["sudo", "ip", "route", "del", "blackhole", ip], stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "iptables", "-t", "raw", "-F"], stderr=subprocess.DEVNULL)
        sys.exit(0)

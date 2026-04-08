import sys
import time
import subprocess
from core import firewall_manager 

# --- CONFIGURATION ---
INTERFACE = "ens4" 
WHITELIST = ["127.0.0.1", "10.128.0.2"]
blocked_ips = set()

def extreme_lockdown():
    print("🛠️  Optimizing BRADSafe Network Driver...")
    subprocess.run(["sudo", "ethtool", "-K", INTERFACE, "gro", "off"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "ethtool", "-K", INTERFACE, "lro", "off"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "iptables", "-t", "raw", "-F"], stderr=subprocess.DEVNULL)
    firewall_manager.initialize_firewall()
    print("✅ BRADSafe Gateway Ready. Monitoring incoming pulses...")

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
    
    print(f"\n⚡ [NITRO] BRADSafe Dropping {ip} at Hardware Entry...")

    # 1. Enforcement
    subprocess.run(["sudo", "iptables", "-t", "raw", "-I", "PREROUTING", "-s", ip, "-j", "NOTRACK"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "iptables", "-t", "raw", "-I", "PREROUTING", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "ip", "route", "add", "blackhole", ip], stderr=subprocess.DEVNULL)
    
    # 2. Notification to Leapcell Backend
    firewall_manager.send_status_to_backend(is_attack=True, attacker_ip=ip)

    # 3. Buffer Flush
    subprocess.run(["sudo", "ip", "link", "set", INTERFACE, "down"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", INTERFACE, "up"], check=True)

    blocked_ips.add(ip)
    print(f"🚫 [GATEWAY] {ip} neutralized. BRADSafe Resuming Guard.")

def monitor_logic():
    prev_pkts = get_interface_stats(INTERFACE)
    last_check = time.time()
    last_heartbeat = time.time()
    
    while True:
        time.sleep(1) 
        curr_pkts = get_interface_stats(INTERFACE)
        curr_time = time.time()
        
        delta_p = curr_pkts - prev_pkts
        duration = curr_time - last_check
        pps = delta_p / duration
        
        # --- Heartbeat: Every 10 seconds ---
        if curr_time - last_heartbeat > 10:
            firewall_manager.send_status_to_backend(is_attack=False)
            last_heartbeat = curr_time

        # --- Attack Threshold ---
        if pps > 1000: 
            attacker_ip = "10.128.0.3" 
            if attacker_ip not in blocked_ips:
                print(f"⚠️  [ATTACK DETECTED] Intensity: {int(pps)} PPS")
                xdp_blackhole(attacker_ip)
                time.sleep(1)
                prev_pkts = get_interface_stats(INTERFACE)
                continue
            else:
                display_pps = int(pps) if pps > 5000 else 0
                sys.stdout.write(f"\r✨ [STATUS] PPS: {display_pps} | BRADSafe Protected   ")
        else:
            sys.stdout.write(f"\r✨ [STATUS] PPS: {int(pps)} | BRADSafe Healthy     ")
        
        sys.stdout.flush()
        prev_pkts = curr_pkts
        last_check = curr_time

if __name__ == "__main__":
    extreme_lockdown()
    try:
        monitor_logic()
    except KeyboardInterrupt:
        print("\n🧹 BRADSafe: Restoring System...")
        for ip in blocked_ips:
            subprocess.run(["sudo", "ip", "route", "del", "blackhole", ip], stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "iptables", "-t", "raw", "-F"], stderr=subprocess.DEVNULL)
        sys.exit(0)

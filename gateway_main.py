import sys
import os
import time
from scapy.all import sniff, IP
from collections import Counter

# Ensure Python can find your 'core' and 'dashboard' modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.ai_engine import AIAnalyzer
from core.feature_extractor import FeatureExtractor
from core.firewall_manager import block_ip  
from dashboard_bridge import log_event

# Initialize the Brain and the Translator
brain = AIAnalyzer()
extractor = FeatureExtractor()

# --- CONFIGURATION ---
WHITELIST = ["10.0.0.1", "127.0.0.1", "10.0.0.3", "10.0.0.6", "10.0.0.7"]
ATTACK_THRESHOLD = 5 
attack_counter = Counter()

# Timers for logging control
last_log_time = {}      # Tracks attacks per IP
LOG_COOLDOWN = 30       # Don't spam DB for same IP attack
last_heartbeat = 0      # Tracks the 5-second terminal update
normal_packet_count = 0

def process_packet(packet):
    global normal_packet_count, last_heartbeat
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        features = extractor.extract(packet)
        
        current_time = time.time()

        if features:
            prediction = brain.predict(features)
            
            # --- ATTACK DETECTED ---
            if prediction == "ATTACK":
                status = "Allowed"
                
                # Check cooldown to avoid spamming Atlas
                should_report = (src_ip not in last_log_time) or (current_time - last_log_time[src_ip] > LOG_COOLDOWN)

                if src_ip in WHITELIST:
                    status = "Allowed (Whitelisted)"
                else:
                    attack_counter[src_ip] += 1
                    if attack_counter[src_ip] >= ATTACK_THRESHOLD:
                        status = "Blocked"
                        block_ip(src_ip)
                        attack_counter[src_ip] = 0 
                    else:
                        status = f"Suspected ({int(attack_counter[src_ip])}/{ATTACK_THRESHOLD})"

                if should_report:
                    last_log_time[src_ip] = current_time
                    # Log to Database
                    info = {"src": src_ip, "dst": dst_ip, "size": len(packet)}
                    log_event(info, status=status, label=prediction)
                    # Print to Terminal
                    print(f"🔴 [GATEWAY] ATTACK DETECTED | {src_ip} -> {dst_ip} | {status}")

            # --- NORMAL TRAFFIC ---
            else:
                normal_packet_count += 1
                # Slowly decay the suspicion counter if traffic is now clean
                if attack_counter[src_ip] > 0:
                    attack_counter[src_ip] -= 0.1

        # --- HEARTBEAT (Every 5 Seconds) ---
        # This shows you the gateway is alive even if no attacks are happening
        if current_time - last_heartbeat > 5:
            print(f"🟢 [HEARTBEAT] Gateway Active | Packets Analyzed: {normal_packet_count} | Status: Normal")
            last_heartbeat = current_time

def main():
    print("--- AI Security Gateway: BRAIN ONLINE ---")
    print(f"🛡️  Admin Whitelist: {WHITELIST}")
    print(f"🕵️  Listening on wg0... (Heartbeat every 5s)")
    
    # Reset firewall at start for clean demo
    os.system("sudo iptables -F") 
    os.system("sudo iptables -t nat -A POSTROUTING -o ens4 -j MASQUERADE")
    
    try:
        sniff(iface="wg0", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n[!] Gateway shutting down.")
        sys.exit(0)

if __name__ == "__main__":
    main()

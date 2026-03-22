import sys
import os
import time
import pandas as pd
from scapy.all import sniff, IP, conf, L3RawSocket
from collections import Counter

# --- PATH SETUP ---
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.ai_engine import AIAnalyzer
from core.feature_extractor import FeatureExtractor
from core.firewall_manager import block_ip, flush_rules
from core.utils import get_google_ips, is_whitelisted

# --- INITIALIZE GLOBALS ---
brain = AIAnalyzer()
extractor = FeatureExtractor()
GOOGLE_WHITELIST = get_google_ips()

# CONFIGURATION
ATTACK_THRESHOLD = 3   
blocked_ips = set()
attack_counter = Counter()
total_analyzed = 0
last_heartbeat = time.time()

def process_packet(packet):
    global total_analyzed, last_heartbeat
    
    if packet and packet.haslayer(IP):
        src_ip = packet[IP].src
        
        # 1. WHITELIST CHECK (Ignore Google Infrastructure)
        if is_whitelisted(src_ip, GOOGLE_WHITELIST):
            return 

        # 2. FEATURE EXTRACTION
        features = extractor.extract(packet)

        if features:
            total_analyzed += 1
            
            try:
                # 3. AI INFERENCE
                feat_df = pd.DataFrame([features], columns=brain.feature_names)
                probs = brain.model.predict_proba(feat_df)[0]
                attack_prob = probs[1] 

                # 4. DETECTION LOGIC
                # Trigger on High AI Probability OR extreme Packet-Per-Second (PPS)
                if (attack_prob > 0.75) or (features[6] > 800):
                    if src_ip not in blocked_ips:
                        attack_counter[src_ip] += 1
                        print(f"⚠️  [DETECTED] {src_ip} | AI Prob: {attack_prob:.2f} | PPS: {features[6]:.1f}")

                        if attack_counter[src_ip] >= ATTACK_THRESHOLD:
                            print(f"🔴 [BLOCKING] Confirmed Attack Source: {src_ip}")
                            block_ip(src_ip)
                            blocked_ips.add(src_ip)
            except Exception:
                pass

        # 5. HEARTBEAT (Status Update every 5s)
        if time.time() - last_heartbeat > 5:
            print(f"🟢 [GATEWAY ACTIVE] Analyzed: {total_analyzed} | Blocked IPs: {len(blocked_ips)}")
            last_heartbeat = time.time()

def main():
    os.system('clear')
    print("==========================================")
    print("   AI SECURITY GATEWAY: CLOUD-READY V2    ")
    print("==========================================")
    
    if brain.model is None:
        print("❌ FATAL: AI Model failed to load. Check /models/ folder.")
        sys.exit(1)

    # Use L3RawSocket for Cloud 'any' interface compatibility
    conf.L3socket = L3RawSocket
    
    print("🛡️  Resetting Firewall Rules...")
    flush_rules()
    
    print(f"🚀 Monitoring Network... (Targeting Internal IP 10.128.0.2)")
    print("💡 Tip: Attack from VM B using Internal IP for best results.")

    try:
        # sniff(iface=None) targets the 'any' interface
        sniff(iface=None, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n[!] User Shutdown. Cleaning up...")
        flush_rules()
        sys.exit(0)

if __name__ == "__main__":
    main()

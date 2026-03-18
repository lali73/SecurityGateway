import sys
import os
from scapy.all import sniff, IP

# Ensure Python can find your 'core' and 'dashboard' modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.ai_engine import AIAnalyzer
from core.feature_extractor import FeatureExtractor
from core.firewall_manager import block_ip  # <--- IMPORT THE FIREWALL ENGINE
from dashboard_bridge import log_event

# Initialize the Brain and the Translator
brain = AIAnalyzer()
extractor = FeatureExtractor()

# Safety Whitelist (Don't block the gateway or yourself)
WHITELIST = ["10.0.0.1", "127.0.0.1","10.0.0.3", "10.0.0.6"]

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # 1. Extract features (returns the 6-feature list for the RF model)
        features = extractor.extract(packet)
        
        if features:
            # 2. Get AI Prediction
            prediction = brain.predict(features)
            
            # 3. Decision Logic: If Attack, Block it!
            if prediction == "ATTACK":
                status = "Blocked"
                if src_ip not in WHITELIST:
                    block_ip(src_ip) # <--- CALL THE FIREWALL HERE
            else:
                status = "Allowed"

            # 4. Log to MongoDB Atlas for the Node.js website
            info = {"src": src_ip, "dst": dst_ip, "size": len(packet)}
            log_event(info, status=status, label=prediction)
            
            # 5. Live Terminal Output
            icon = "🔴" if prediction == "ATTACK" else "🟢"
            print(f"{icon} [GATEWAY] {prediction} | {src_ip} -> {dst_ip} ({status})")

            if prediction == "ATTACK":
                if src_ip not in WHITELIST:
                    print(f"DEBUG: Attempting to block IP: {src_ip}") # Add this
                    block_ip(src_ip)
def main():
    print("--- AI Security Gateway: BRAIN ONLINE ---")
    print("🕵️  Listening on wg0... (Press Ctrl+C to stop)")
    # Reset firewall at start of demo to ensure a clean state
    os.system("sudo iptables -F") 
    sniff(iface="wg0", prn=process_packet, store=0)

if __name__ == "__main__":
    main()

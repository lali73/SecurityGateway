import os
import sys
import time
import threading
import joblib 
import pandas as pd
from scapy.all import sniff, IP

from core.firewall_manager import initialize_firewall, block_ip
from core.peer_manager import monitor_new_peers # Import the monitor function directly

# --- CONFIG ---
MODEL_PATH = "models/rf_ids_model.pkl"
INTERFACE = "wg0"  
SENSITIVITY_THRESHOLD = 0.85 

traffic_stats = {} 
model = None

def load_security_model():
    global model
    try:
        model = joblib.load(MODEL_PATH)
        print(f"🧠 AI Model Loaded: {MODEL_PATH}")
    except Exception as e:
        print(f"❌ Failed to load AI model: {e}")
        sys.exit(1)

def packet_callback(pkt):
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        if src_ip not in traffic_stats:
            traffic_stats[src_ip] = {'count': 0, 'size': 0}
        traffic_stats[src_ip]['count'] += 1
        traffic_stats[src_ip]['size'] += len(pkt)

def analysis_loop():
    print(f"🚀 Monitoring Network on {INTERFACE}...")
    while True:
        time.sleep(1.0)
        current_batch = list(traffic_stats.items())
        traffic_stats.clear() 

        for ip, stats in current_batch:
            pps = stats['count']
            avg_size = stats['size'] / stats['count'] if stats['count'] > 0 else 0
            
            # Ensure order: [pps, avg_size]
            features = pd.DataFrame([[pps, avg_size]], columns=['pps', 'avg_size'])
            
            try:
                prob = model.predict_proba(features)[0][1]
                if prob >= SENSITIVITY_THRESHOLD:
                    print(f"⚠️  [ALERT] {ip} | Prob: {prob:.2f} | PPS: {pps}")
                    block_ip(ip, threat_type="DDoS Anomaly", confidence=prob)
            except:
                continue

def main():
    print("==========================================")
    print("    VECTRAFLOW: AI SECURITY GATEWAY v2    ")
    print("==========================================")
    
    initialize_firewall()
    load_security_model()
    
    # Start Peer Watcher in a background thread
    watcher_thread = threading.Thread(target=monitor_new_peers, daemon=True)
    watcher_thread.start()
    
    # Start Analysis in a background thread
    analysis_thread = threading.Thread(target=analysis_loop, daemon=True)
    analysis_thread.start()
    
    print(f"📡 Sniffer started on {INTERFACE}. Monitoring for threats...")
    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()

import os
import pandas as pd
import numpy as np
import pickle
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# --- UPDATED CONFIGURATION ---
# Added PPS (Packets Per Second) and BPS (Bytes Per Second)
FEATURES = ['PROTOCOL', 'FLOW_DURATION', 'IN_PKTS', 'IN_BYTES', 'MAX_PKT_LEN', 'STD_PKT_LEN', 'PPS', 'BPS']
PCAP_DIR = "pcap_files"
DATA_DIR = "data"
MODEL_DIR = "models"
EXTENSIONS = (".pcap", ".pcapng")

def extract_flow_features(pcap_path, label):
    """Converts a single PCAP/PCAPNG into a list of flow features."""
    flows = {}
    
    def process_pkt(pkt):
        if IP not in pkt: return
        proto = pkt[IP].proto
        src, dst = pkt[IP].src, pkt[IP].dst
        sport, dport = (pkt.sport, pkt.dport) if (TCP in pkt or UDP in pkt) else (0, 0)
        
        # Unique key for the flow
        key = tuple(sorted((src, dst))) + tuple(sorted((sport, dport))) + (proto,)
        
        if key not in flows: 
            flows[key] = {'ts': [], 'len': []}
        
        flows[key]['ts'].append(float(pkt.time))
        flows[key]['len'].append(len(pkt))

    print(f"   [>] Reading: {os.path.basename(pcap_path)}")
    try:
        sniff(offline=pcap_path, prn=process_pkt, store=False)
    except Exception as e:
        print(f"   [!] Error reading {pcap_path}: {e}")
        return []
    
    flow_data = []
    for key, val in flows.items():
        ts, lengths = val['ts'], val['len']
        if not ts: continue
        
        # Duration in seconds for PPS/BPS calculation
        duration_sec = max(ts) - min(ts)
        duration_ms = duration_sec * 1000 
        
        total_pkts = len(ts)
        total_bytes = sum(lengths)

        # --- NEW TEMPORAL LOGIC ---
        # If duration is 0 (single packet flow), PPS and BPS are 0
        pps = total_pkts / duration_sec if duration_sec > 0 else 0
        bps = total_bytes / duration_sec if duration_sec > 0 else 0

        flow_data.append({
            'PROTOCOL': key[4],
            'FLOW_DURATION': duration_ms,
            'IN_PKTS': total_pkts,
            'IN_BYTES': total_bytes,
            'MAX_PKT_LEN': max(lengths),
            'STD_PKT_LEN': np.std(lengths),
            'PPS': pps,
            'BPS': bps,
            'Label': label
        })
    return flow_data

# ... [run_pipeline remains largely the same, but will now use the new FEATURES list] ...

def run_pipeline():
    all_data = []
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # 1. Process Benign
    benign_path = os.path.join(PCAP_DIR, "benign")
    if os.path.exists(benign_path):
        for f in os.listdir(benign_path):
            if f.lower().endswith(EXTENSIONS):
                all_data.extend(extract_flow_features(os.path.join(benign_path, f), 0))

    # 2. Process Attack
    attack_path = os.path.join(PCAP_DIR, "attack")
    if os.path.exists(attack_path):
        for f in os.listdir(attack_path):
            if f.lower().endswith(EXTENSIONS):
                all_data.extend(extract_flow_features(os.path.join(attack_path, f), 1))

    if not all_data:
        print("[-] Failure: No data extracted.")
        return

    df = pd.DataFrame(all_data)
    df.replace([np.inf, -np.inf], 0, inplace=True) # Replace inf with 0 for safety
    df.dropna(inplace=True)
    
    df.to_csv(os.path.join(DATA_DIR, "master_dataset.csv"), index=False)
    
    X = df[FEATURES]
    y = df['Label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("[*] Training Random Forest with Temporal Features...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(os.path.join(MODEL_DIR, "rf_ids_model.pkl"), "wb") as f:
        pickle.dump(clf, f)
    with open(os.path.join(MODEL_DIR, "feature_list.pkl"), "wb") as f:
        pickle.dump(FEATURES, f)
        
    print(f"\n[SUCCESS] Pipeline Complete with {len(df)} flows!")

if __name__ == "__main__":
    run_pipeline()

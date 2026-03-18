import time
import numpy as np
import joblib
import os
from scapy.all import IP

class FeatureExtractor:
    def __init__(self):
        # Path to your feature list
        self.list_path = "/home/lali/Desktop/SecurityGateway_v1/models/feature_list.pkl"
        
        try:
            self.required_features = joblib.load(self.list_path)
            print(f"📋 Extractor: Loaded feature map: {self.required_features}")
        except Exception as e:
            print(f"❌ Extractor Error: Could not load feature_list.pkl: {e}")
            # Fallback to your known 6 features if file load fails
            self.required_features = ['PROTOCOL', 'FLOW_DURATION', 'IN_PKTS', 'IN_BYTES', 'MAX_PKT_LEN', 'STD_PKT_LEN']

        # Dictionary to track flows: {(src, dst, proto): {'times': [], 'lengths': []}}
        self.flows = {}

    def extract(self, packet):
        if not packet.haslayer(IP):
            return None

        # 1. Identify the flow (Source, Destination, Protocol)
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        key = (src, dst, proto)
        
        current_time = time.time()
        pkt_len = len(packet)

        # 2. Update Flow Memory
        if key not in self.flows:
            self.flows[key] = {'times': [current_time], 'lengths': [pkt_len]}
        else:
            self.flows[key]['times'].append(current_time)
            self.flows[key]['lengths'].append(pkt_len)

        # Keep memory lean (last 50 packets per flow)
        if len(self.flows[key]['times']) > 50:
            self.flows[key]['times'].pop(0)
            self.flows[key]['lengths'].pop(0)

        # 3. Calculate the 6 specific features
        times = self.flows[key]['times']
        lengths = self.flows[key]['lengths']

        # Feature Mapping
        feature_map = {
            'PROTOCOL': proto,
            'FLOW_DURATION': float(times[-1] - times[0]),
            'IN_PKTS': len(times),
            'IN_BYTES': sum(lengths),
            'MAX_PKT_LEN': max(lengths),
            'STD_PKT_LEN': float(np.std(lengths)) if len(lengths) > 1 else 0.0
        }

        # 4. Return features in the exact order the model expects
        ordered_vector = [feature_map.get(feat, 0) for feat in self.required_features]
        return ordered_vector
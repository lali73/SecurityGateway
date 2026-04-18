import numpy as np
from scapy.all import IP

class FeatureExtractor:
    def __init__(self):
        self.flow_history = {}

    def extract(self, packet):
        if not packet.haslayer(IP):
            return None

        src = packet[IP].src
        proto = int(packet[IP].proto)
        now = float(packet.time)
        length = len(packet)

        if src not in self.flow_history:
            self.flow_history[src] = {'ts': [], 'lens': []}

        self.flow_history[src]['ts'].append(now)
        self.flow_history[src]['lens'].append(length)

        if len(self.flow_history[src]['ts']) > 100:
            self.flow_history[src]['ts'].pop(0)
            self.flow_history[src]['lens'].pop(0)

        ts = self.flow_history[src]['ts']
        lens = self.flow_history[src]['lens']

        # --- PREVENT INFINITE PPS ---
        duration_sec = max(ts) - min(ts)

        # If duration is too small (sub-millisecond), we treat it as 1ms
        # to avoid exploding PPS/BPS values
        safe_duration = max(duration_sec, 0.001)

        duration_ms = float(duration_sec * 1000)
        pps = float(len(ts) / safe_duration)
        bps = float(sum(lens) / safe_duration)

        return [
            proto,
            duration_ms,
            len(ts),
            sum(lens),
            max(lens),
            float(np.std(lens)),
            pps,
            bps
        ]

    def build_peer_features(self, snapshot):
        safe_duration = max(snapshot.duration_seconds, 0.001)

        return [
            int(snapshot.protocol),
            float(snapshot.duration_seconds * 1000),
            int(snapshot.packet_count),
            int(snapshot.byte_count),
            int(snapshot.max_packet_length),
            float(snapshot.std_packet_length),
            float(snapshot.packet_count / safe_duration),
            float(snapshot.byte_count / safe_duration),
        ]

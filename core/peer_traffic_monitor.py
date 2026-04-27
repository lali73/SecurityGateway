from collections import Counter, deque
from dataclasses import dataclass
import ipaddress
from threading import Lock

import numpy as np
from scapy.all import AsyncSniffer, IP, TCP, UDP


BYPASS_PORTS = {53, 67, 68}


@dataclass
class PeerTrafficSnapshot:
    victim_ip: str
    protocol: int
    duration_seconds: float
    packet_count: int
    byte_count: int
    max_packet_length: int
    std_packet_length: float
    pps: float
    bps: float
    tcp_ratio: float
    udp_ratio: float
    syn_ratio: float
    top_attacker_ip: str | None
    attacker_packet_count: int
    attacker_byte_count: int
    last_seen: float

    def to_metrics(self):
        return {
            "window_seconds": round(self.duration_seconds, 3),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "pps": round(self.pps, 3),
            "bps": round(self.bps, 3),
            "tcp_ratio": round(self.tcp_ratio, 4),
            "udp_ratio": round(self.udp_ratio, 4),
            "syn_ratio": round(self.syn_ratio, 4),
            "top_attacker_ip": self.top_attacker_ip,
            "top_attacker_packet_count": self.attacker_packet_count,
            "top_attacker_byte_count": self.attacker_byte_count,
        }


class PeerTrafficMonitor:
    def __init__(self, interface, vpn_subnet, window_seconds=5):
        self.interface = interface
        self.window_seconds = window_seconds
        self.vpn_network = ipaddress.ip_network(vpn_subnet, strict=False)
        self.peer_packets = {}
        self.lock = Lock()
        self.sniffer = None

    def start(self):
        if self.sniffer is not None:
            return

        self.sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self.handle_packet,
            store=False,
            filter=f"ip and (src net {self.vpn_network.with_prefixlen} or dst net {self.vpn_network.with_prefixlen})",
        )
        self.sniffer.start()

    def stop(self):
        if self.sniffer is None:
            return

        try:
            self.sniffer.stop()
        finally:
            self.sniffer = None

    def handle_packet(self, packet):
        if not packet.haslayer(IP):
            return

        # Bypass DNS/DHCP traffic early to avoid false positives from control-plane bursts.
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            if int(tcp_layer.sport) in BYPASS_PORTS or int(tcp_layer.dport) in BYPASS_PORTS:
                return
        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            if int(udp_layer.sport) in BYPASS_PORTS or int(udp_layer.dport) in BYPASS_PORTS:
                return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        try:
            src_in_vpn = ipaddress.ip_address(src_ip) in self.vpn_network
            dst_in_vpn = ipaddress.ip_address(dst_ip) in self.vpn_network
            if not src_in_vpn and not dst_in_vpn:
                return
        except ValueError:
            return

        if src_in_vpn and not dst_in_vpn:
            peer_ip = src_ip
            remote_ip = dst_ip
        elif dst_in_vpn and not src_in_vpn:
            peer_ip = dst_ip
            remote_ip = src_ip
        else:
            peer_ip = dst_ip
            remote_ip = src_ip

        now = float(packet.time)
        proto = int(packet[IP].proto)
        length = len(packet)
        is_syn = bool(
            packet.haslayer(TCP)
            and packet[TCP].flags & 0x02
            and not packet[TCP].flags & 0x10
        )
        is_tcp = packet.haslayer(TCP)
        is_udp = packet.haslayer(UDP)

        with self.lock:
            peer_queue = self.peer_packets.setdefault(peer_ip, deque())
            peer_queue.append(
                {
                    "ts": now,
                    "src_ip": remote_ip,
                    "proto": proto,
                    "length": length,
                    "is_tcp": is_tcp,
                    "is_udp": is_udp,
                    "is_syn": is_syn,
                }
            )
            self._prune_peer(peer_ip, now)

    def _prune_peer(self, victim_ip, now):
        peer_queue = self.peer_packets.get(victim_ip)
        if peer_queue is None:
            return

        cutoff = now - self.window_seconds
        while peer_queue and peer_queue[0]["ts"] < cutoff:
            peer_queue.popleft()

        if not peer_queue:
            self.peer_packets.pop(victim_ip, None)

    def snapshots(self, now=None):
        if now is None:
            from time import time

            now = time()

        snapshots = []
        with self.lock:
            victim_ips = list(self.peer_packets.keys())

            for victim_ip in victim_ips:
                self._prune_peer(victim_ip, now)
                peer_queue = self.peer_packets.get(victim_ip)
                if not peer_queue:
                    continue

                lengths = [entry["length"] for entry in peer_queue]
                proto_counts = Counter(entry["proto"] for entry in peer_queue)
                attacker_packets = Counter(entry["src_ip"] for entry in peer_queue)
                attacker_bytes = Counter()
                tcp_count = 0
                udp_count = 0
                syn_count = 0

                for entry in peer_queue:
                    attacker_bytes[entry["src_ip"]] += entry["length"]
                    tcp_count += int(entry["is_tcp"])
                    udp_count += int(entry["is_udp"])
                    syn_count += int(entry["is_syn"])

                first_ts = peer_queue[0]["ts"]
                last_ts = peer_queue[-1]["ts"]
                duration_seconds = max(last_ts - first_ts, 0.001)
                packet_count = len(peer_queue)
                byte_count = sum(lengths)
                top_attacker_ip = None
                attacker_packet_count = 0
                attacker_byte_count = 0

                if attacker_packets:
                    top_attacker_ip, attacker_packet_count = attacker_packets.most_common(1)[0]
                    attacker_byte_count = attacker_bytes[top_attacker_ip]

                snapshots.append(
                    PeerTrafficSnapshot(
                        victim_ip=victim_ip,
                        protocol=proto_counts.most_common(1)[0][0],
                        duration_seconds=duration_seconds,
                        packet_count=packet_count,
                        byte_count=byte_count,
                        max_packet_length=max(lengths),
                        std_packet_length=float(np.std(lengths)),
                        pps=float(packet_count / duration_seconds),
                        bps=float(byte_count / duration_seconds),
                        tcp_ratio=float(tcp_count / packet_count),
                        udp_ratio=float(udp_count / packet_count),
                        syn_ratio=float(syn_count / packet_count),
                        top_attacker_ip=top_attacker_ip,
                        attacker_packet_count=attacker_packet_count,
                        attacker_byte_count=attacker_byte_count,
                        last_seen=last_ts,
                    )
                )

        snapshots.sort(key=lambda snapshot: snapshot.pps, reverse=True)
        return snapshots

import sys
import time
import subprocess
from core import firewall_manager
from config.vpn_config import VPN_INTERFACE, VPN_SUBNET
from core.ai_engine import AIAnalyzer
from core.feature_extractor import FeatureExtractor
from core.peer_traffic_monitor import PeerTrafficMonitor

# --- CONFIGURATION ---
INTERFACE = "ens4"
IDENTITY_INTERFACE = VPN_INTERFACE
WHITELIST = ["127.0.0.1", "10.128.0.2"]
DISCOVERY_RETRY_SECONDS = 5
DISCOVERY_TIMEOUT_SECONDS = 60
HEARTBEAT_SECONDS = 10
DETECTION_INTERVAL_SECONDS = 1
MONITOR_WINDOW_SECONDS = 5
AI_ATTACK_THRESHOLD = 0.80
RAW_BLOCK_CHAIN = "BRADSAFE_RAW"
FILTER_BLOCK_CHAIN = "BRADSAFE_FILTER"
blocked_flows = set()


def run_quiet(command, check=False):
    return subprocess.run(
        command,
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        check=check,
    )


def clear_runtime_blocks():
    run_quiet(["sudo", "iptables", "-t", "raw", "-F", RAW_BLOCK_CHAIN])
    run_quiet(["sudo", "iptables", "-F", FILTER_BLOCK_CHAIN])
    blocked_flows.clear()


def ensure_block_chains():
    run_quiet(["sudo", "iptables", "-t", "raw", "-N", RAW_BLOCK_CHAIN])
    run_quiet(["sudo", "iptables", "-N", FILTER_BLOCK_CHAIN])
    if subprocess.run(
        ["sudo", "iptables", "-t", "raw", "-C", "PREROUTING", "-j", RAW_BLOCK_CHAIN],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        check=False,
    ).returncode != 0:
        run_quiet(["sudo", "iptables", "-t", "raw", "-I", "PREROUTING", "-j", RAW_BLOCK_CHAIN])

    if subprocess.run(
        ["sudo", "iptables", "-C", "FORWARD", "-j", FILTER_BLOCK_CHAIN],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        check=False,
    ).returncode != 0:
        run_quiet(["sudo", "iptables", "-I", "FORWARD", "-j", FILTER_BLOCK_CHAIN])


def get_interface_ipv4(iface):
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return None

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("inet "):
            continue

        cidr = line.split()[1]
        return cidr.split("/", 1)[0]

    return None


def discover_gateway_identity():
    deadline = time.time() + DISCOVERY_TIMEOUT_SECONDS

    while time.time() < deadline:
        discovered_ip = get_interface_ipv4(IDENTITY_INTERFACE)
        if discovered_ip:
            firewall_manager.set_discovered_vpn_ip(discovered_ip)
            print(f"[IDENTITY] Discovered {IDENTITY_INTERFACE} IPv4: {discovered_ip}")
            return discovered_ip

        remaining = max(int(deadline - time.time()), 0)
        print(
            f"[IDENTITY] Waiting for IPv4 on {IDENTITY_INTERFACE}... "
            f"retrying in {DISCOVERY_RETRY_SECONDS}s ({remaining}s left)"
        )
        time.sleep(DISCOVERY_RETRY_SECONDS)

    raise RuntimeError(
        f"Could not discover an IPv4 address on {IDENTITY_INTERFACE} "
        f"within {DISCOVERY_TIMEOUT_SECONDS} seconds."
    )


def extreme_lockdown():
    print("[INIT] Optimizing BRADSafe Network Driver...")
    run_quiet(["sudo", "ethtool", "-K", INTERFACE, "gro", "off"])
    run_quiet(["sudo", "ethtool", "-K", INTERFACE, "lro", "off"])
    ensure_block_chains()
    clear_runtime_blocks()
    firewall_manager.initialize_firewall()
    print("[READY] BRADSafe Gateway Ready. Monitoring incoming pulses with a fresh blocklist...")

def protect_peer(attacker_ip, victim_ip, analysis, snapshot):
    flow_key = (attacker_ip, victim_ip)
    if not attacker_ip or not victim_ip or attacker_ip in WHITELIST or flow_key in blocked_flows:
        return

    print(f"\n[BLOCK] BRADSafe Dropping {attacker_ip} traffic targeting {victim_ip}...")

    run_quiet(
        ["sudo", "iptables", "-t", "raw", "-A", RAW_BLOCK_CHAIN, "-s", attacker_ip, "-d", victim_ip, "-j", "DROP"]
    )
    run_quiet(["sudo", "iptables", "-A", FILTER_BLOCK_CHAIN, "-s", attacker_ip, "-d", victim_ip, "-j", "DROP"])

    firewall_manager.send_status_to_backend(
        is_attack=True,
        attacker_ip=attacker_ip,
        victim_vpn_ip=victim_ip,
        attack_type=analysis["attack_type"],
        attack_probability=analysis["attack_probability"],
        peer_metrics=snapshot.to_metrics(),
    )

    blocked_flows.add(flow_key)
    print(
        f"[LOCKED] {attacker_ip} -> {victim_ip} neutralized "
        f"(type={analysis['attack_type']}, score={analysis['attack_probability']:.3f})."
    )


def monitor_logic():
    peer_monitor = PeerTrafficMonitor(INTERFACE, VPN_SUBNET, window_seconds=MONITOR_WINDOW_SECONDS)
    feature_extractor = FeatureExtractor()
    ai_analyzer = AIAnalyzer()
    last_heartbeat = time.time()

    peer_monitor.start()

    try:
        while True:
            time.sleep(DETECTION_INTERVAL_SECONDS)
            curr_time = time.time()
            snapshots = peer_monitor.snapshots(now=curr_time)

            if not snapshots:
                sys.stdout.write("\r[STATUS] No active protected peers detected.     ")
                sys.stdout.flush()
                continue

            peer_summaries = []
            send_heartbeat = curr_time - last_heartbeat >= HEARTBEAT_SECONDS

            for snapshot in snapshots:
                feature_vector = feature_extractor.build_peer_features(snapshot)
                analysis = ai_analyzer.analyze(feature_vector)
                peer_summaries.append(
                    f"{snapshot.victim_ip}:score={analysis['attack_probability']:.2f},pps={int(snapshot.pps)}"
                )

                if (
                    analysis["label"] == "ATTACK"
                    and analysis["attack_probability"] >= AI_ATTACK_THRESHOLD
                    and snapshot.top_attacker_ip
                ):
                    print(
                        f"\n[ATTACK DETECTED] victim={snapshot.victim_ip} "
                        f"attacker={snapshot.top_attacker_ip} "
                        f"type={analysis['attack_type']} score={analysis['attack_probability']:.3f}"
                    )
                    protect_peer(snapshot.top_attacker_ip, snapshot.victim_ip, analysis, snapshot)

                if send_heartbeat:
                    firewall_manager.send_status_to_backend(
                        is_attack=False,
                        victim_vpn_ip=snapshot.victim_ip,
                        attack_type=analysis["attack_type"],
                        attack_probability=analysis["attack_probability"],
                        peer_metrics=snapshot.to_metrics(),
                    )

            if send_heartbeat:
                last_heartbeat = curr_time

            sys.stdout.write(f"\r[STATUS] {' | '.join(peer_summaries[:5])}     ")
            sys.stdout.flush()
    finally:
        peer_monitor.stop()


if __name__ == "__main__":
    try:
        discover_gateway_identity()
        extreme_lockdown()
        monitor_logic()
    except RuntimeError as e:
        print(f"[FATAL] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] BRADSafe: Restoring System...")
        clear_runtime_blocks()
        sys.exit(0)

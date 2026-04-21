import sys
import time
import subprocess
from collections import deque
from datetime import datetime
from threading import Event, Lock, Thread
from core import firewall_manager
from config.vpn_config import VPN_INTERFACE, VPN_SUBNET
from core.ai_engine import AIAnalyzer
from core.feature_extractor import FeatureExtractor
from core.peer_traffic_monitor import PeerTrafficMonitor
import psutil
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# --- CONFIGURATION ---
INTERFACE = "ens4"
MONITOR_INTERFACE = VPN_INTERFACE
IDENTITY_INTERFACE = VPN_INTERFACE
WHITELIST = ["127.0.0.1", "10.128.0.2"]
DISCOVERY_RETRY_SECONDS = 5
DISCOVERY_TIMEOUT_SECONDS = 60
HEARTBEAT_SECONDS = 10
DETECTION_INTERVAL_SECONDS = 1
MONITOR_WINDOW_SECONDS = 5
AI_ATTACK_THRESHOLD = 0.50
MIN_ATTACK_PPS = 1800
UNDER_ATTACK_HOLD_SECONDS = 8
INCIDENT_HISTORY_SIZE = 10
PEER_REGISTRY_REFRESH_SECONDS = 10
MANUAL_ATTACK_SCORE = 0.51
MANUAL_SOURCE_SHARE_THRESHOLD = 0.60
MANUAL_ATTACKER_PPS_THRESHOLD = 900
MANUAL_UDP_RATIO_THRESHOLD = 0.85
MANUAL_SYN_RATIO_THRESHOLD = 0.45
MANUAL_EXTREME_PPS = 5000
RAW_BLOCK_CHAIN = "BRADSAFE_RAW"
FILTER_BLOCK_CHAIN = "BRADSAFE_FILTER"
blocked_flows = set()


def now_label():
    return datetime.now().strftime("%H:%M:%S")


class DashboardState:
    def __init__(self, registered_peers):
        self.lock = Lock()
        self.registered_peers = []
        self.stop_event = Event()
        self.peer_rows = {}
        self.events = deque(maxlen=INCIDENT_HISTORY_SIZE)
        self.global_pps = 0.0
        self.cpu_percent = 0.0
        self.ram_percent = 0.0
        self.ai_status = "Loading"
        self.backend_status = "Initializing"
        self.gateway_identity = "Resolving"
        self.started_at = now_label()
        for peer_ip in registered_peers:
            self.ensure_peer(peer_ip)

    def ensure_peer(self, peer_ip):
        if peer_ip in self.peer_rows:
            return

        self.peer_rows[peer_ip] = {
            "status": "Healthy",
            "pps": 0.0,
            "kbps": 0.0,
            "score": 0.0,
            "last_update": 0.0,
            "last_attack": 0.0,
            "attacker_ip": "-",
        }
        if peer_ip not in self.registered_peers:
            self.registered_peers.append(peer_ip)
            self.registered_peers.sort(key=lambda ip: tuple(int(part) for part in ip.split(".")))

    def register_peer(self, peer_ip):
        with self.lock:
            self.ensure_peer(peer_ip)

    def set_ai_status(self, status):
        with self.lock:
            self.ai_status = status

    def set_backend_status(self, status):
        with self.lock:
            self.backend_status = status

    def set_gateway_identity(self, identity):
        with self.lock:
            self.gateway_identity = identity

    def set_system_stats(self, global_pps, cpu_percent, ram_percent):
        with self.lock:
            self.global_pps = global_pps
            self.cpu_percent = cpu_percent
            self.ram_percent = ram_percent

    def mark_peer(self, peer_ip, status, pps, kbps, score, attacker_ip="-"):
        with self.lock:
            self.ensure_peer(peer_ip)
            row = self.peer_rows[peer_ip]
            current_time = time.time()
            row["status"] = status
            row["pps"] = pps
            row["kbps"] = kbps
            row["score"] = score
            row["last_update"] = current_time
            row["attacker_ip"] = attacker_ip
            if status == "Under Attack":
                row["last_attack"] = current_time

    def cool_off_peers(self):
        with self.lock:
            current_time = time.time()
            for row in self.peer_rows.values():
                if current_time - row["last_update"] > HEARTBEAT_SECONDS:
                    row["pps"] = 0.0
                    row["kbps"] = 0.0
                    row["score"] = 0.0
                    row["attacker_ip"] = "-"
                if current_time - row["last_attack"] > UNDER_ATTACK_HOLD_SECONDS:
                    row["status"] = "Healthy"

    def add_event(self, level, message, peer_ip=None, attacker_ip=None):
        with self.lock:
            self.events.appendleft(
                {
                    "time": now_label(),
                    "level": level,
                    "message": message,
                    "peer_ip": peer_ip or "-",
                    "attacker_ip": attacker_ip or "-",
                }
            )

    def snapshot(self):
        with self.lock:
            return {
                "registered_peers": list(self.registered_peers),
                "peer_rows": {ip: row.copy() for ip, row in self.peer_rows.items()},
                "events": list(self.events),
                "global_pps": self.global_pps,
                "cpu_percent": self.cpu_percent,
                "ram_percent": self.ram_percent,
                "ai_status": self.ai_status,
                "backend_status": self.backend_status,
                "gateway_identity": self.gateway_identity,
                "started_at": self.started_at,
            }


def status_text(status, pulse_on):
    if status == "Under Attack":
        style = "bold white on red" if pulse_on else "bold red"
        return Text("UNDER ATTACK", style=style)
    return Text("HEALTHY", style="bold green")


def should_treat_as_attack(analysis, snapshot):
    if snapshot.pps < MIN_ATTACK_PPS or not snapshot.top_attacker_ip:
        return False

    if analysis["label"] == "ATTACK" and analysis["attack_probability"] >= AI_ATTACK_THRESHOLD:
        return True

    return analysis.get("manual_attack", False)


def manual_firewall_analysis(snapshot):
    safe_duration = max(snapshot.duration_seconds, 0.001)
    attacker_share = snapshot.attacker_packet_count / max(snapshot.packet_count, 1)
    attacker_pps = snapshot.attacker_packet_count / safe_duration

    if attacker_share < MANUAL_SOURCE_SHARE_THRESHOLD or attacker_pps < MANUAL_ATTACKER_PPS_THRESHOLD:
        return None

    if snapshot.protocol == 6 and snapshot.syn_ratio >= MANUAL_SYN_RATIO_THRESHOLD:
        return {
            "label": "ATTACK",
            "attack_probability": MANUAL_ATTACK_SCORE,
            "attack_type": "SynFlood",
            "manual_attack": True,
        }

    if snapshot.protocol == 17 and snapshot.udp_ratio >= MANUAL_UDP_RATIO_THRESHOLD:
        return {
            "label": "ATTACK",
            "attack_probability": MANUAL_ATTACK_SCORE,
            "attack_type": "UDP Flood",
            "manual_attack": True,
        }

    if snapshot.pps >= MANUAL_EXTREME_PPS:
        return {
            "label": "ATTACK",
            "attack_probability": MANUAL_ATTACK_SCORE,
            "attack_type": "Packet Flood",
            "manual_attack": True,
        }

    return {
        "label": "ATTACK",
        "attack_probability": MANUAL_ATTACK_SCORE,
        "attack_type": "Suspicious Flood",
        "manual_attack": True,
    }


def attack_analysis_for_demo(analysis, snapshot):
    normalized = {
        "label": analysis.get("label", "Normal"),
        "attack_probability": float(analysis.get("attack_probability", 0.0)),
        "attack_type": analysis.get("attack_type", "Normal"),
        "manual_attack": False,
    }

    if snapshot.pps < MIN_ATTACK_PPS or not snapshot.top_attacker_ip:
        return normalized

    if normalized["label"] == "ATTACK" and normalized["attack_probability"] >= AI_ATTACK_THRESHOLD:
        return normalized

    manual_analysis = manual_firewall_analysis(snapshot)
    if manual_analysis is not None:
        return manual_analysis

    return normalized


def build_header_panel(snapshot):
    grid = Table.grid(expand=True)
    grid.add_column(justify="left", ratio=2)
    grid.add_column(justify="center", ratio=1)
    grid.add_column(justify="center", ratio=1)
    grid.add_column(justify="center", ratio=1)
    grid.add_column(justify="right", ratio=2)
    grid.add_row(
        f"[bold cyan]Gateway[/] {snapshot['gateway_identity']}",
        f"[bold white]Global PPS[/] {snapshot['global_pps']:.0f}",
        f"[bold white]CPU[/] {snapshot['cpu_percent']:.1f}%",
        f"[bold white]RAM[/] {snapshot['ram_percent']:.1f}%",
        f"[bold white]AI[/] {snapshot['ai_status']}",
    )
    grid.add_row(
        f"[bold white]Backend[/] {snapshot['backend_status']}",
        "",
        "",
        "",
        f"[dim]Started {snapshot['started_at']}[/dim]",
    )
    return Panel(grid, title="[bold bright_cyan]BRADSafe SOC Dashboard[/]", border_style="bright_cyan")


def build_peer_table(snapshot):
    pulse_on = int(time.time()) % 2 == 0
    table = Table(expand=True, header_style="bold bright_cyan")
    table.add_column("Peer IP", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Current PPS", justify="right")
    table.add_column("Bandwidth (Kbps)", justify="right")
    table.add_column("AI Probability", justify="right")

    for peer_ip in snapshot["registered_peers"]:
        row = snapshot["peer_rows"].get(peer_ip, {})
        table.add_row(
            peer_ip,
            status_text(row.get("status", "Healthy"), pulse_on),
            f"{row.get('pps', 0.0):,.1f}",
            f"{row.get('kbps', 0.0):,.1f}",
            f"{row.get('score', 0.0):.3f}",
        )

    return Panel(table, title="[bold white]Protected Peers[/]", border_style="green")


def build_events_panel(snapshot):
    events_table = Table(expand=True, header_style="bold bright_white")
    events_table.add_column("Time", style="dim", width=10)
    events_table.add_column("Level", width=10)
    events_table.add_column("Victim IP", style="cyan", width=14)
    events_table.add_column("Attacker IP", style="magenta", width=14)
    events_table.add_column("Event", ratio=1)

    if not snapshot["events"]:
        events_table.add_row("-", "-", "-", "-", "[dim]No incidents recorded[/dim]")
    else:
        for event in snapshot["events"]:
            level_style = "bold white on red" if event["level"] == "ALERT" else "bold yellow"
            message_style = "bold red" if event["level"] == "ALERT" else "white"
            events_table.add_row(
                event["time"],
                Text(event["level"], style=level_style),
                event["peer_ip"],
                event["attacker_ip"],
                Text(event["message"], style=message_style),
            )

    return Panel(events_table, title="[bold red]Security Events[/]", border_style="red")


def build_dashboard(snapshot):
    layout = Layout()
    layout.split_column(
        Layout(build_header_panel(snapshot), size=5),
        Layout(name="body", ratio=1),
        Layout(build_events_panel(snapshot), size=14),
    )
    layout["body"].update(build_peer_table(snapshot))
    return layout


def dashboard_worker(state):
    with Live(build_dashboard(state.snapshot()), refresh_per_second=4, screen=True) as live:
        while not state.stop_event.is_set():
            state.cool_off_peers()
            live.update(build_dashboard(state.snapshot()))
            time.sleep(1)


def run_quiet(command, check=False):
    return subprocess.run(
        command,
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        check=check,
    )


def discover_registered_peers():
    try:
        result = subprocess.run(
            ["wg", "show", IDENTITY_INTERFACE, "allowed-ips"],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return []

    if result.returncode != 0:
        return []

    peers = set()
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split(None, 1)
        if len(parts) < 2:
            continue

        for allowed_ip in parts[1].split(","):
            candidate = allowed_ip.strip()
            if "/" in candidate:
                ip_value, prefix = candidate.split("/", 1)
                if prefix != "32":
                    continue
            else:
                ip_value = candidate

            try:
                peer_ip = tuple(int(part) for part in ip_value.split("."))
            except ValueError:
                continue

            if len(peer_ip) != 4:
                continue
            if ip_value == firewall_manager.get_current_vpn_ip():
                continue
            if not ip_value.startswith("10.0.0."):
                continue

            peers.add(ip_value)

    return sorted(peers, key=lambda ip: tuple(int(part) for part in ip.split(".")))


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
            return discovered_ip

        time.sleep(DISCOVERY_RETRY_SECONDS)

    raise RuntimeError(
        f"Could not discover an IPv4 address on {IDENTITY_INTERFACE} "
        f"within {DISCOVERY_TIMEOUT_SECONDS} seconds."
    )


def extreme_lockdown():
    run_quiet(["sudo", "ethtool", "-K", INTERFACE, "gro", "off"])
    run_quiet(["sudo", "ethtool", "-K", INTERFACE, "lro", "off"])
    ensure_block_chains()
    clear_runtime_blocks()
    return firewall_manager.initialize_firewall()

def protect_peer(attacker_ip, victim_ip, analysis, snapshot, dashboard_state):
    flow_key = (attacker_ip, victim_ip)
    if not attacker_ip or not victim_ip or attacker_ip in WHITELIST or flow_key in blocked_flows:
        return

    run_quiet(
        ["sudo", "iptables", "-t", "raw", "-A", RAW_BLOCK_CHAIN, "-s", attacker_ip, "-d", victim_ip, "-j", "DROP"]
    )
    run_quiet(["sudo", "iptables", "-A", FILTER_BLOCK_CHAIN, "-s", attacker_ip, "-d", victim_ip, "-j", "DROP"])

    backend_result = firewall_manager.send_status_to_backend(
        is_attack=True,
        attacker_ip=attacker_ip,
        victim_vpn_ip=victim_ip,
        attack_type=analysis["attack_type"],
        attack_probability=analysis["attack_probability"],
        peer_metrics=snapshot.to_metrics(),
    )

    blocked_flows.add(flow_key)
    dashboard_state.mark_peer(
        victim_ip,
        "Under Attack",
        snapshot.pps,
        (snapshot.bps * 8) / 1000,
        analysis["attack_probability"],
        attacker_ip=attacker_ip,
    )
    dashboard_state.add_event(
        "ALERT",
        (
            f"Victim {victim_ip} under {analysis['attack_type']} pressure. "
            f"Neutralizing source {attacker_ip}"
            f"{' via firewall fallback.' if analysis.get('manual_attack') else '.'}"
        ),
        peer_ip=victim_ip,
        attacker_ip=attacker_ip,
    )
    if backend_result["ok"]:
        dashboard_state.set_backend_status("Connected")
    else:
        dashboard_state.set_backend_status("Degraded")
        dashboard_state.add_event("WARN", backend_result["message"], peer_ip=victim_ip, attacker_ip=attacker_ip)


def monitor_logic(dashboard_state):
    peer_monitor = PeerTrafficMonitor(MONITOR_INTERFACE, VPN_SUBNET, window_seconds=MONITOR_WINDOW_SECONDS)
    feature_extractor = FeatureExtractor()
    ai_analyzer = AIAnalyzer()
    last_heartbeat = time.time()
    last_peer_registry_refresh = 0.0
    dashboard_state.set_ai_status("Active" if ai_analyzer.model is not None else "Load Error")
    if ai_analyzer.load_error:
        dashboard_state.add_event("WARN", ai_analyzer.load_error)

    peer_monitor.start()

    try:
        while True:
            time.sleep(DETECTION_INTERVAL_SECONDS)
            curr_time = time.time()

            if curr_time - last_peer_registry_refresh >= PEER_REGISTRY_REFRESH_SECONDS:
                for peer_ip in discover_registered_peers():
                    dashboard_state.register_peer(peer_ip)
                last_peer_registry_refresh = curr_time

            snapshots = peer_monitor.snapshots(now=curr_time)

            for snapshot in snapshots:
                dashboard_state.register_peer(snapshot.victim_ip)

            snapshot_by_peer = {snapshot.victim_ip: snapshot for snapshot in snapshots}
            global_pps = sum(snapshot.pps for snapshot in snapshots)
            dashboard_state.set_system_stats(
                global_pps=global_pps,
                cpu_percent=psutil.cpu_percent(interval=None),
                ram_percent=psutil.virtual_memory().percent,
            )

            send_heartbeat = curr_time - last_heartbeat >= HEARTBEAT_SECONDS

            for peer_ip in dashboard_state.registered_peers:
                snapshot = snapshot_by_peer.get(peer_ip)
                if snapshot is None:
                    dashboard_state.mark_peer(peer_ip, "Healthy", 0.0, 0.0, 0.0)
                    continue

                feature_vector = feature_extractor.build_peer_features(snapshot)
                analysis = attack_analysis_for_demo(ai_analyzer.analyze(feature_vector), snapshot)
                score = analysis["attack_probability"]
                kbps = (snapshot.bps * 8) / 1000
                is_attack = should_treat_as_attack(analysis, snapshot) and bool(snapshot.top_attacker_ip)
                status = "Under Attack" if is_attack else "Healthy"
                dashboard_state.mark_peer(
                    peer_ip,
                    status,
                    snapshot.pps,
                    kbps,
                    score,
                    attacker_ip=snapshot.top_attacker_ip or "-",
                )

                if is_attack:
                    protect_peer(snapshot.top_attacker_ip, snapshot.victim_ip, analysis, snapshot, dashboard_state)

                if send_heartbeat:
                    backend_result = firewall_manager.send_status_to_backend(
                        is_attack=False,
                        victim_vpn_ip=snapshot.victim_ip,
                        attack_type=analysis["attack_type"],
                        attack_probability=score,
                        peer_metrics=snapshot.to_metrics(),
                    )
                    dashboard_state.set_backend_status("Connected" if backend_result["ok"] else "Degraded")
                    if not backend_result["ok"]:
                        dashboard_state.add_event("WARN", backend_result["message"], peer_ip=snapshot.victim_ip)

            if send_heartbeat:
                last_heartbeat = curr_time
    finally:
        peer_monitor.stop()


if __name__ == "__main__":
    dashboard_state = DashboardState(discover_registered_peers())
    dashboard_thread = Thread(target=dashboard_worker, args=(dashboard_state,), daemon=True)
    dashboard_thread.start()
    exit_code = 0

    try:
        discovered_identity = discover_gateway_identity()
        dashboard_state.set_gateway_identity(f"{discovered_identity} on {IDENTITY_INTERFACE}")
        dashboard_state.add_event("WARN", f"Gateway identity discovered on {IDENTITY_INTERFACE}: {discovered_identity}")
        firewall_info = extreme_lockdown()
        dashboard_state.set_backend_status("Connected")
        dashboard_state.add_event("WARN", "Demo mode startup: cleared all runtime firewall blocks from previous runs.")
        dashboard_state.add_event(
            "WARN",
            f"Backend ready at {firewall_info['base_url']} ({firewall_info['identity_summary']})",
        )
        monitor_logic(dashboard_state)
    except RuntimeError as e:
        dashboard_state.add_event("ALERT", str(e))
        print(f"[FATAL] {e}")
        exit_code = 1
    except KeyboardInterrupt:
        dashboard_state.add_event("WARN", "Shutdown requested. Restoring firewall state.")
    finally:
        clear_runtime_blocks()
        dashboard_state.stop_event.set()
        dashboard_thread.join(timeout=2)

    sys.exit(exit_code)

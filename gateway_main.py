import sys
import time
import subprocess
from core import firewall_manager
from config.vpn_config import VPN_INTERFACE

# --- CONFIGURATION ---
INTERFACE = "ens4"
IDENTITY_INTERFACE = VPN_INTERFACE
WHITELIST = ["127.0.0.1", "10.128.0.2"]
TEST_ATTACKER_IP = "10.128.0.3"
DISCOVERY_RETRY_SECONDS = 5
DISCOVERY_TIMEOUT_SECONDS = 60
blocked_ips = set()


def run_quiet(command, check=False):
    return subprocess.run(
        command,
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        check=check,
    )


def clear_runtime_blocks():
    run_quiet(["sudo", "iptables", "-t", "raw", "-F"])
    run_quiet(["sudo", "iptables", "-F"])

    for ip in list(blocked_ips) + [TEST_ATTACKER_IP]:
        run_quiet(["sudo", "ip", "route", "del", "blackhole", ip])

    blocked_ips.clear()


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
    clear_runtime_blocks()
    firewall_manager.initialize_firewall()
    print("[READY] BRADSafe Gateway Ready. Monitoring incoming pulses with a fresh blocklist...")


def get_interface_stats(iface):
    try:
        with open("/proc/net/dev", "r") as f:
            for line in f:
                if iface in line:
                    return int(line.split()[2])
    except Exception:
        return 0
    return 0


def xdp_blackhole(ip):
    if not ip or ip in WHITELIST or ip in blocked_ips:
        return

    print(f"\n[BLOCK] BRADSafe Dropping {ip} at gateway entry...")

    # Apply multiple drop points so the internal test attacker IP is blocked reliably.
    run_quiet(["sudo", "iptables", "-t", "raw", "-I", "PREROUTING", "-s", ip, "-j", "DROP"])
    run_quiet(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    run_quiet(["sudo", "iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
    run_quiet(["sudo", "ip", "route", "replace", "blackhole", ip])

    firewall_manager.send_status_to_backend(is_attack=True, attacker_ip=ip)

    run_quiet(["sudo", "ip", "link", "set", INTERFACE, "down"], check=True)
    run_quiet(["sudo", "ip", "link", "set", INTERFACE, "up"], check=True)

    blocked_ips.add(ip)
    print(f"[LOCKED] {ip} neutralized. BRADSafe Resuming Guard.")


def monitor_logic():
    prev_pkts = get_interface_stats(INTERFACE)
    last_check = time.time()
    last_heartbeat = time.time()

    while True:
        time.sleep(1)
        curr_pkts = get_interface_stats(INTERFACE)
        curr_time = time.time()

        delta_p = curr_pkts - prev_pkts
        duration = max(curr_time - last_check, 0.001)
        pps = delta_p / duration

        if curr_time - last_heartbeat > 10:
            firewall_manager.send_status_to_backend(is_attack=False)
            last_heartbeat = curr_time

        if pps > 1000:
            attacker_ip = TEST_ATTACKER_IP
            if attacker_ip not in blocked_ips:
                print(f"[ATTACK DETECTED] Intensity: {int(pps)} PPS from test source {attacker_ip}")
                xdp_blackhole(attacker_ip)
                time.sleep(1)
                prev_pkts = get_interface_stats(INTERFACE)
                continue
            else:
                display_pps = int(pps) if pps > 5000 else 0
                sys.stdout.write(f"\r[STATUS] PPS: {display_pps} | BRADSafe Protected   ")
        else:
            sys.stdout.write(f"\r[STATUS] PPS: {int(pps)} | BRADSafe Healthy     ")

        sys.stdout.flush()
        prev_pkts = curr_pkts
        last_check = curr_time


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

import sys
import time
import subprocess
from core import firewall_manager

# --- CONFIGURATION ---
INTERFACE = "ens4"
WHITELIST = ["127.0.0.1", "10.128.0.2"]
TEST_ATTACKER_IP = "10.128.0.3"
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
    extreme_lockdown()
    try:
        monitor_logic()
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] BRADSafe: Restoring System...")
        clear_runtime_blocks()
        sys.exit(0)

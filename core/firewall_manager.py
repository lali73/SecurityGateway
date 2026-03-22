import os

def block_ip(ip_address):
    """
    Blocks an IP using iptables on Linux.
    """
    print(f"🛡️  [KERNEL] Executing Block Rule for {ip_address}...")
    
    # Block on both INPUT (to this machine) and FORWARD (through this gateway)
    cmd_input = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    cmd_forward = f"sudo iptables -A FORWARD -s {ip_address} -j DROP"
    
    try:
        os.system(cmd_input)
        os.system(cmd_forward)
        print(f"✅ Firewall updated: Traffic from {ip_address} is now DROPPED.")
    except Exception as e:
        print(f"❌ Firewall Error: {e}")

def flush_rules():
    """
    Clears all iptables rules to ensure a clean state.
    """
    print("🧹 Cleaning and resetting firewall rules...")
    try:
        os.system("sudo iptables -F")
        print("✅ Firewall flushed successfully.")
    except Exception as e:
        print(f"❌ Error flushing firewall: {e}")

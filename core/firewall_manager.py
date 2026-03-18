import os

def block_ip(ip_address):
    """Adds iptables rules to both INPUT and FORWARD chains."""
    # -I inserts at the top (Index 1) to ensure it overrides other rules
    cmd_input = f"sudo iptables -I INPUT -s {ip_address} -j DROP"
    cmd_forward = f"sudo iptables -I FORWARD -s {ip_address} -j DROP"
    
    os.system(cmd_input)
    os.system(cmd_forward)
    
    print(f"🛡️  [FIREWALL] Blocked {ip_address} on INPUT and FORWARD chains.")

def unblock_all():
    """Flushes all rules to reset the gateway state."""
    os.system("sudo iptables -F")
    print("🔓 [FIREWALL] All IPs unblocked. System Reset.")    
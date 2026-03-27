import os
import requests

# --- CONFIGURATION ---
# Replace with the actual URL from your Backend/Frontend team
BACKEND_URL = "http://your-backend-api.com/api/alerts"

# Internal Infrastructure IPs that should NEVER be blocked
INFRA_WHITELIST = [
    "169.254.169.254",  # Google Metadata Server (Critical for VM health)
    "35.235.240.0/20",   # Google IAP Proxy (Console SSH)
    "10.128.0.1",        # Default Gateway
    "127.0.0.1"          # Localhost
]

# --- firewall_manager.py Changes ---

def initialize_firewall():
    print("🛡️  VectraFlow: Initializing Secure Gateway Layers...")
    try:
        os.system("sudo iptables -F")
        os.system("sudo iptables -X")
        # Fast Flush for nftables too
        os.system("sudo nft flush table netdev filter 2>/dev/null") 

        # 1. SSH Protection
        os.system("sudo iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT")
        
        # 2. IMPORTANT: Only allow established for NON-ATTACK ports
        # We remove the generic 'ESTABLISHED' rule to prevent flood "leakage"
        
        # 3. Infrastructure Whitelist
        for i, ip in enumerate(INFRA_WHITELIST, start=2):
            os.system(f"sudo iptables -I INPUT {i} -s {ip} -j ACCEPT")

        print(f"✅ Safety Net Engaged.")
    except Exception as e:
        print(f"❌ Initialization Error: {e}")
def block_ip(ip_address, threat_type="DDoS Attack", confidence=0.0):
    """
    The AI Engine calls this to drop traffic from a specific IP.
    """
    # Check if the AI is accidentally trying to block a protected IP
    if ip_address in INFRA_WHITELIST:
        print(f"⚠️  [POLICY] Block ignored for Whitelisted Infra IP: {ip_address}")
        return

    print(f"🔴 [MITIGATION] AI Confidence {confidence*100:.1f}% | Blocking: {ip_address}")
    
    try:
        # Block Ingress (Direct attacks on Gateway)
        os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
        
        # Block Forward (Attacks passing through VPN to other clients)
        os.system(f"sudo iptables -A FORWARD -s {ip_address} -j DROP")
        
        # Notify the Backend/Dashboard
        send_alert_to_backend(ip_address, threat_type, confidence)
        
    except Exception as e:
        print(f"❌ Firewall Execution Error: {e}")

def send_alert_to_backend(ip, threat, score):
    """
    Sends data to the Frontend team's API.
    """
    payload = {
        "attacker_ip": ip,
        "threat_type": threat,
        "confidence": round(float(score), 4),
        "timestamp": "now", # Backend usually handles the actual clock time
        "status": "Blocked"
    }
    
    try:
        # Timeout is 1s to ensure the AI isn't delayed by a slow API
        response = requests.post(BACKEND_URL, json=payload, timeout=1)
        if response.status_code == 201 or response.status_code == 200:
            print(f"📡 API Sync: Alert for {ip} pushed to dashboard.")
    except Exception:
        # Silently fail logging to console to keep the main loop fast
        print("⚠️  API Offline: Saving alert to local buffer.")

def flush_rules():
    """
    Cleans rules but immediately re-applies the Safety Net.
    """
    print("🧹 Cleaning and resetting firewall rules...")
    initialize_firewall()

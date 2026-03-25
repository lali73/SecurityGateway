import os
import json
import time
import threading
import requests

PEER_DIR = "/etc/wireguard/new_peers/"
BACKEND_URL = "http://your-backend-api.com/api/alerts" # Same as firewall_manager

def monitor_new_peers():
    if not os.path.exists(PEER_DIR):
        os.makedirs(PEER_DIR)
        
    print(f"📡 Peer Watcher Active: Monitoring {PEER_DIR}")
    
    while True:
        try:
            files = [f for f in os.listdir(PEER_DIR) if f.endswith('.json')]
            for file in files:
                filepath = os.path.join(PEER_DIR, file)
                
                with open(filepath, 'r') as f:
                    peer_data = json.load(f)
                
                pubkey = peer_data.get('public_key')
                assigned_ip = peer_data.get('assigned_ip')
                
                if pubkey and assigned_ip:
                    # Attempt to add
                    success, error_msg = add_wireguard_peer(pubkey, assigned_ip)
                    
                    if not success:
                        # Notify backend of the CONFIGURATION FAILURE
                        notify_backend_of_error(pubkey, assigned_ip, error_msg)
                    
                    # ALWAYS delete the file after one attempt to stop the loop
                    os.remove(filepath)
                
            time.sleep(5)
        except Exception as e:
            print(f"❌ Peer Watcher Error: {e}")
            time.sleep(5)

def add_wireguard_peer(pubkey, ip):
    print(f"👤 [AUTONOMOUS] Provisioning new peer: {ip}")
    # Capture the error output from the system command
    cmd = f"sudo wg set wg0 peer {pubkey} allowed-ips {ip} 2>&1"
    
    import subprocess
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    if process.returncode == 0:
        print(f"✅ Peer {ip} is now active.")
        return True, None
    else:
        error_msg = stdout.decode().strip()
        print(f"❌ WireGuard Error: {error_msg}")
        return False, error_msg

def notify_backend_of_error(pubkey, ip, error):
    """Tell the backend the user's key was rejected."""
    payload = {
        "event": "PROVISIONING_FAILURE",
        "ip": ip,
        "key_attempted": pubkey,
        "error_details": error,
        "status": "Failed"
    }
    try:
        requests.post(BACKEND_URL, json=payload, timeout=2)
    except:
        pass # Don't crash if backend is down

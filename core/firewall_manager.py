import requests

# --- BACKEND CONFIGURATION ---
BASE_URL = "https://ai-firewall-backend-dani-d3v8671-ooua5n91.leapcell.dev"
ALERT_ENDPOINT = f"{BASE_URL}/api/alerts"

# Ensure this matches the secret configured in your Leapcell Environment Variables
ALERT_SECRET = "BRADSafe_SECURE_2026_PROD"

# The VPN IP assigned to the user you are testing with
MY_VPN_IP = "10.0.0.12"


def format_backend_error(response):
    content_type = response.headers.get("Content-Type", "")

    if "text/html" in content_type:
        return "backend returned an HTML error page; the dashboard service is likely down or over its plan limits"

    body = response.text.strip().replace("\n", " ")
    return body[:140] + ("..." if len(body) > 140 else "")


def send_status_to_backend(is_attack=False, attacker_ip=None):
    """
    Coordinates with BRADSafe Backend Route 6.1.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Alert-Secret": ALERT_SECRET,
    }

    if is_attack:
        payload = {
            "victim_vpn_ip": MY_VPN_IP,
            "attacker_ip": attacker_ip,
        }
        log_msg = f"[ALERT] BRADSafe mitigation sent for {attacker_ip}"
    else:
        payload = {
            "victim_vpn_ip": MY_VPN_IP,
            "attacker_ip": "CLEAN",
        }
        log_msg = "[HEARTBEAT] BRADSafe System status: Healthy"

    try:
        response = requests.post(ALERT_ENDPOINT, json=payload, headers=headers, timeout=1.5)
        if response.status_code in [200, 201]:
            print(f"[BACKEND] {log_msg}")
        else:
            print(f"[BACKEND] API Error: {response.status_code} - {format_backend_error(response)}")
    except Exception as e:
        print(f"[BACKEND] Offline or unreachable: {str(e)[:80]}")


def initialize_firewall():
    print(f"[BACKEND] BRADSafe API Client: Connected to {BASE_URL}")

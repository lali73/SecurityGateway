import os
from pathlib import Path
from datetime import datetime, timezone

import requests


def load_env_file(env_path):
    values = {}

    if not env_path.exists():
        return values

    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()

    return values


ENV = load_env_file(Path(__file__).resolve().parent.parent / ".env")


def env_value(key, default=None):
    value = ENV.get(key)
    if value is None or value == "":
        value = os.getenv(key)
    if value is None or value == "":
        return default
    return value

# --- BACKEND CONFIGURATION ---
BASE_URL = env_value("BACKEND_BASE_URL", "https://ethics-hits-troubleshooting-sas.trycloudflare.com")
ALERT_ENDPOINT = f"{BASE_URL.rstrip('/')}/api/alerts"
ALERT_SECRET = env_value("ALERT_SECRET", "BRADSafe_SECURE_2026_PROD")
DISCOVERED_VPN_IP = None
PROTECTED_VPN_IP = env_value("PROTECTED_VPN_IP")
WIREGUARD_PUBLIC_KEY = env_value("WIREGUARD_PUBLIC_KEY")
GATEWAY_PEER_REF = env_value("GATEWAY_PEER_REF")
GATEWAY_ID = env_value("GATEWAY_ID", "gateway-dev-1")


def format_backend_error(response):
    content_type = response.headers.get("Content-Type", "")

    if "text/html" in content_type:
        return "backend returned an HTML error page; the dashboard service is likely down or over its plan limits"

    body = response.text.strip().replace("\n", " ")
    return body[:140] + ("..." if len(body) > 140 else "")


def set_discovered_vpn_ip(vpn_ip):
    global DISCOVERED_VPN_IP
    DISCOVERED_VPN_IP = vpn_ip


def get_current_vpn_ip():
    return DISCOVERED_VPN_IP


def resolve_effective_victim_vpn_ip(victim_vpn_ip=None):
    return victim_vpn_ip or PROTECTED_VPN_IP or get_current_vpn_ip()


def build_identity_payload(victim_vpn_ip=None):
    payload = {}
    effective_victim_vpn_ip = resolve_effective_victim_vpn_ip(victim_vpn_ip=victim_vpn_ip)
    if effective_victim_vpn_ip:
        payload["victim_vpn_ip"] = effective_victim_vpn_ip

    # Static profile identifiers from .env should only accompany the profile they belong to.
    identity_matches_configured_profile = (
        not effective_victim_vpn_ip
        or not PROTECTED_VPN_IP
        or effective_victim_vpn_ip == PROTECTED_VPN_IP
    )

    if identity_matches_configured_profile and WIREGUARD_PUBLIC_KEY:
        payload["wireguard_public_key"] = WIREGUARD_PUBLIC_KEY
    if identity_matches_configured_profile and GATEWAY_PEER_REF:
        payload["gateway_peer_ref"] = GATEWAY_PEER_REF

    return payload


def build_alert_payload(
    is_attack=False,
    attacker_ip=None,
    victim_vpn_ip=None,
    attack_type=None,
    attack_probability=None,
    peer_metrics=None,
):
    payload = build_identity_payload(victim_vpn_ip=victim_vpn_ip)

    if not payload:
        raise ValueError(
            "At least one protected identity must be configured: "
            "discovered wg0 IPv4, WIREGUARD_PUBLIC_KEY, or GATEWAY_PEER_REF."
        )

    effective_victim_vpn_ip = payload.get("victim_vpn_ip")
    if GATEWAY_ID and (
        not effective_victim_vpn_ip
        or not PROTECTED_VPN_IP
        or effective_victim_vpn_ip == PROTECTED_VPN_IP
    ):
        payload["gateway_id"] = GATEWAY_ID
    payload["event_type"] = "attack_detected" if is_attack else "heartbeat"
    payload["detected_at"] = datetime.now(timezone.utc).isoformat()
    payload["attacker_ip"] = attacker_ip if is_attack else "CLEAN"
    payload["attack_type"] = attack_type or ("Unknown" if is_attack else "Normal")

    if attack_probability is not None:
        payload["attack_probability"] = float(attack_probability)
    if peer_metrics:
        payload["peer_metrics"] = peer_metrics

    return payload


def send_status_to_backend(
    is_attack=False,
    attacker_ip=None,
    victim_vpn_ip=None,
    attack_type=None,
    attack_probability=None,
    peer_metrics=None,
):
    """
    Coordinates with BRADSafe Backend Route 6.1.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Alert-Secret": ALERT_SECRET,
    }

    try:
        payload = build_alert_payload(
            is_attack=is_attack,
            attacker_ip=attacker_ip,
            victim_vpn_ip=victim_vpn_ip,
            attack_type=attack_type,
            attack_probability=attack_probability,
            peer_metrics=peer_metrics,
        )
        if is_attack:
            log_msg = (
                f"[ALERT] BRADSafe mitigation sent for {attacker_ip} targeting "
                f"{payload.get('victim_vpn_ip', 'configured profile')} "
                f"({payload.get('attack_type', 'Unknown')}, score={payload.get('attack_probability', 'n/a')})"
            )
        else:
            log_msg = (
                f"[HEARTBEAT] BRADSafe system status: Healthy for "
                f"{payload.get('victim_vpn_ip', 'configured profile')} "
                f"(score={payload.get('attack_probability', 'n/a')})"
            )

        response = requests.post(ALERT_ENDPOINT, json=payload, headers=headers, timeout=1.5)
        if response.status_code in [200, 201]:
            return {
                "ok": True,
                "status_code": response.status_code,
                "message": log_msg,
                "payload": payload,
            }
        else:
            return {
                "ok": False,
                "status_code": response.status_code,
                "message": format_backend_error(response),
                "payload": payload,
            }
    except Exception as e:
        return {
            "ok": False,
            "status_code": None,
            "message": f"Offline or unreachable: {str(e)[:80]}",
            "payload": None,
        }


def initialize_firewall():
    identifiers = []
    effective_vpn_ip = PROTECTED_VPN_IP or get_current_vpn_ip()
    if effective_vpn_ip:
        identifiers.append(f"vpn_ip={effective_vpn_ip}")
    if WIREGUARD_PUBLIC_KEY:
        identifiers.append("wireguard_public_key=configured")
    if GATEWAY_PEER_REF:
        identifiers.append(f"gateway_peer_ref={GATEWAY_PEER_REF}")

    identity_summary = ", ".join(identifiers) if identifiers else "no protected identity configured"
    return {
        "base_url": BASE_URL,
        "identity_summary": identity_summary,
    }

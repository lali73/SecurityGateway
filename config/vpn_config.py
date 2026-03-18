import os

# WireGuard Interface Settings
VPN_INTERFACE = "wg0"  # The name of your VPN adapter in Kali
VPN_SUBNET = "10.0.0.0/24"  # The IP range of your protected clients

# Gateway Internal IP (The IP your Windows host pings)
GATEWAY_IP = "10.0.0.1"

# Port for WireGuard (Must match your Cloud Firewall/Router settings)
WG_PORT = 51820
from core.firewall_manager import block_ip, initialize_firewall

# Initialize the safety net
initialize_firewall()

# Test a fake block (use a safe dummy IP like 8.8.4.4)
block_ip("8.8.4.4", threat_type="Test Alert", confidence=0.99)

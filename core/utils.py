import requests
import ipaddress

def get_google_ips():
    """Fetches official Google Cloud and Services IPv4 ranges."""
    urls = [
        "https://www.gstatic.com/ipranges/goog.json",   # Google Services
        "https://www.gstatic.com/ipranges/cloud.json"  # Google Cloud Customers
    ]
    whitelist = set()
    print("🌐 Fetching official Google IP ranges...")
    try:
        for url in urls:
            data = requests.get(url).json()
            for prefix in data['prefixes']:
                if 'ipv4Prefix' in prefix:
                    whitelist.add(prefix['ipv4Prefix'])
        print(f"✅ Successfully whitelisted {len(whitelist)} Google CIDR blocks.")
        return list(whitelist)
    except Exception as e:
        print(f"⚠️  Whitelist Fetch Warning: {e}. Using basic defaults.")
        return ["169.254.169.254/32", "35.235.240.0/20"]

def is_whitelisted(ip_str, whitelist_cidrs):
    """Checks if a string IP belongs to any whitelisted CIDR."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for cidr in whitelist_cidrs:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
    except:
        pass
    return False

🛡️ AI Security Gateway: Maintenance & Operations GuideThis document outlines how to restart and maintain the Hybrid-Cloud Security Gateway after a system shutdown or reboot.🚀 1. Quick Start Protocol (The 3-Terminal Rule)To bring the system online, you must open three separate terminal tabs in Kali Linux and run the following commands in order:

Terminal 1: The AI Detection EngineThis is the "Brain" that sniffs traffic and detects attacks.Bashcd ~/Desktop/SecurityGateway_v1
sudo python3 gateway_main.py

Terminal 2: The API BridgeThis allows the Frontend/Dashboard to talk to your local machine.Bashcd ~/Desktop/SecurityGateway_v1
python3 api_bridge.py


Terminal 3: The Cloud TunnelThis creates the public link so your teammates can reach your machine.Bashcloudflared tunnel --url http://localhost:8000


⚠️ Note: Every time you restart the tunnel, Cloudflare may generate a new URL. You must send this new URL to your teammates so they can update their Dashboard settings.

🧹 2. System Reset (If Network is Blocked)If you were testing an attack and your Windows host can no longer ping the gateway, run the reset script to flush the firewall rules:Bashcd ~/Desktop/SecurityGateway_v1
python3 reset_gateway.py


📂 3. Project Architecturegateway_main.py: Core logic. Uses Scapy to sniff wg0 and AI to classify traffic.

api_bridge.py: Flask server that receives "Manual Block" commands from the web.

core/firewall_manager.py: Handles iptables commands to drop malicious IPs.

core/db_bridge.py: Manages the connection to MongoDB Atlas for remote logging.

.env: Contains sensitive credentials (MONGO_URI). Do not upload to GitHub.


🛠️ 4. TroubleshootingIssueSolution"
       Issue,                                          Solution
"Address already in use",     A previous script is still running. Run fuser -k 8000/tcp to kill it.
Tunnel link won't open,       Ensure api_bridge.py is running on port 8000.
No traffic detected,          Ensure the Windows host is connected to the WireGuard VPN.
MongoDB Auth Error,           Check your internet connection or verify the URI in the 
                                  .env file.    
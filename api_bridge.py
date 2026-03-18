from flask import Flask, request, jsonify
from core.firewall_manager import block_ip
import os

app = Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    return "🛡️ AI Security Gateway API is ONLINE via Cloudflare Tunnel."

@app.route('/manual-block', methods=['POST'])
def manual_block():
    data = request.json
    target_ip = data.get("ip")
    
    if target_ip:
        print(f"📡 [REMOTE] Received block request for: {target_ip}")
        block_ip(target_ip)
        return jsonify({"status": "success", "message": f"IP {target_ip} blocked."}), 200
    
    return jsonify({"status": "error", "message": "No IP provided."}), 400

if __name__ == "__main__":
    # We run on port 8000 because that's what your tunnel is looking for
    print("🚀 API Bridge starting on port 8000...")
    app.run(host='0.0.0.0', port=8000)
from config.mongo_config import get_db_connection
import datetime

# Initialize the connection once
db = get_db_connection()

def log_event(packet_info, status="Allowed", label="Normal"):
    """
    Sends the data to Atlas.
    packet_info: a dictionary of features or IP details
    status: 'Allowed' or 'Blocked'
    label: 'Normal', 'DDoS', 'PortScan', etc.
    """
    if db is not None:
        try:
            threat_logs = db["threat_logs"] # This is the collection name
            
            document = {
                "timestamp": datetime.datetime.now(),
                "source_ip": packet_info.get("src"),
                "dest_ip": packet_info.get("dst"),
                "status": status,
                "ai_prediction": label,
                "packet_size": packet_info.get("size", 0)
            }
            
            result = threat_logs.insert_one(document)
            print(f"[DB_BRIDGE] Successfully logged to Atlas. ID: {result.inserted_id}")
        except Exception as e:
            print(f"[!] Failed to write to Atlas: {e}")
    else:
        print("[!] DB_BRIDGE: No active database connection.")
import os
import sys

def reset_system():
    print("🧹 [CLEANING] Resetting Security Gateway...")
    
    # 1. Flush all iptables rules
    os.system("sudo iptables -F")
    
    # 2. (Optional) If you want to clear the MongoDB logs for a fresh demo:
    # Caution: This deletes your history! 
    # from core.db_bridge import DBBridge
    # db = DBBridge()
    # db.collection.delete_many({}) 

    print("🔓 [FIREWALL] All rules flushed. Network is open.")
    print("✅ [READY] System is back to baseline.")

if __name__ == "__main__":
    reset_system()
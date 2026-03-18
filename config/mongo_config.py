import os
import sys
from pymongo import MongoClient
from dotenv import load_dotenv

# Load the variables from the .env file
load_dotenv()

# Get the URI from the environment
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "AI_Gateway_DB")

def get_db_connection():
    if not MONGO_URI:
        print("❌ Error: MONGO_URI not found in environment variables!")
        return None

    try:
        client = MongoClient(
            MONGO_URI, 
            serverSelectionTimeoutMS=10000, 
            tlsAllowInvalidCertificates=True
        )
        
        # Verify connection
        client.admin.command('ping') 
        
        db = client[DB_NAME]
        print("✅ MongoDB Atlas: Authenticated Successfully via Environment")
        return db
    except Exception as e:
        print(f"[!] MongoDB Atlas Auth Error: {e}")
        return None
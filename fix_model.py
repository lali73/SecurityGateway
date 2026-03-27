import pickle
import sys

MODEL_PATH = "models/rf_ids_model.pkl"

try:
    print(f"🔄 Attempting to re-save {MODEL_PATH} for version compatibility...")
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    
    # Re-writing it using the version 1.7.2 installed on this VM
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    
    print("✅ Model successfully re-synced! No more version warnings should appear.")
except Exception as e:
    print(f"❌ Error during sync: {e}")

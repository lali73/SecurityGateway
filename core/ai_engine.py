import joblib
import os
import numpy as np
import pandas as pd
import warnings

# This hides the version compatibility warnings
warnings.filterwarnings("ignore", category=UserWarning)

class AIAnalyzer:
    def __init__(self):
        # --- DYNAMIC PATH FIX ---
        # This looks for the 'models' folder in the same directory where the script is running
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.model_path = os.path.join(base_dir, "models", "rf_ids_model.pkl")
        self.list_path = os.path.join(base_dir, "models", "feature_list.pkl")
        
        self.model = None
        self.feature_names = None

        try:
            # Check if files exist before trying to load them
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"Model not found at: {self.model_path}")
            
            self.model = joblib.load(self.model_path)
            self.feature_names = joblib.load(self.list_path)
            print("🧠 AI Engine: Model & Feature Names Loaded Successfully")
        except Exception as e:
            print(f"❌ AI Engine Error: {e}")

    def predict(self, feature_vector):
        if self.model is None or feature_vector is None:
            return "Normal"

        try:
            # Wrap the 1D list into a DataFrame with the correct headers
            input_df = pd.DataFrame([feature_vector], columns=self.feature_names)

            prediction = self.model.predict(input_df)
            # Assuming 1 is Attack and 0 is Normal
            return "ATTACK" if prediction[0] == 1 else "Normal"
        except Exception as e:
            print(f"Prediction Error: {e}")
            return "Error"

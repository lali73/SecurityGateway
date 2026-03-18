import joblib
import os
import numpy as np
import pandas as pd  # We use pandas to provide feature names
import warnings

# This hides the version compatibility warnings
warnings.filterwarnings("ignore", category=UserWarning)

class AIAnalyzer:
    def __init__(self):
        self.model_path = "/home/lali/Desktop/SecurityGateway_v1/models/custom_ids_model.pkl"
        self.list_path = "/home/lali/Desktop/SecurityGateway_v1/models/feature_list.pkl"
        self.model = None
        self.feature_names = None
        
        try:
            self.model = joblib.load(self.model_path)
            # Load the names we found earlier
            self.feature_names = joblib.load(self.list_path)
            print("🧠 AI Engine: Model & Feature Names Loaded")
        except Exception as e:
            print(f"❌ AI Engine Error: {e}")

    def predict(self, feature_vector):
        if self.model is None or feature_vector is None:
            return "Normal"
            
        try:
            # Wrap the 1D list into a DataFrame with the correct headers
            input_df = pd.DataFrame([feature_vector], columns=self.feature_names)
            
            prediction = self.model.predict(input_df)
            return "ATTACK" if prediction[0] == 1 else "Normal"
        except Exception as e:
            # If there is a mismatch, we'll see why here
            print(f"Prediction Error: {e}")
            return "Error"
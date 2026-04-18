import joblib
import os
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
        self.load_error = None
        self.last_error = None

        try:
            # Check if files exist before trying to load them
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"Model not found at: {self.model_path}")
            
            self.model = joblib.load(self.model_path)
            if hasattr(self.model, "n_jobs"):
                self.model.n_jobs = 1
            self.feature_names = joblib.load(self.list_path)
        except Exception as e:
            self.load_error = str(e)

    def predict(self, feature_vector):
        analysis = self.analyze(feature_vector)
        return analysis["label"]

    def analyze(self, feature_vector):
        if self.model is None or feature_vector is None:
            return {
                "label": "Normal",
                "attack_probability": 0.0,
                "attack_type": "Normal",
            }

        try:
            # Wrap the 1D list into a DataFrame with the correct headers
            input_df = pd.DataFrame([feature_vector], columns=self.feature_names)

            prediction = int(self.model.predict(input_df)[0])
            attack_probability = self._attack_probability(input_df, prediction)
            label = "ATTACK" if prediction == 1 else "Normal"
            attack_type = self._infer_attack_type(feature_vector, attack_probability, label)

            return {
                "label": label,
                "attack_probability": attack_probability,
                "attack_type": attack_type,
            }
        except Exception as e:
            self.last_error = str(e)
            return {
                "label": "Error",
                "attack_probability": 0.0,
                "attack_type": "Unknown",
            }

    def _attack_probability(self, input_df, prediction):
        if not hasattr(self.model, "predict_proba"):
            return 1.0 if prediction == 1 else 0.0

        probabilities = self.model.predict_proba(input_df)[0]
        classes = list(getattr(self.model, "classes_", []))
        if 1 in classes:
            return float(probabilities[classes.index(1)])

        return float(max(probabilities))

    def _infer_attack_type(self, feature_vector, attack_probability, label):
        if label != "ATTACK":
            return "Normal"

        protocol = int(feature_vector[0])
        pps = float(feature_vector[6])
        bps = float(feature_vector[7])
        std_packet_length = float(feature_vector[5])

        if protocol == 6 and pps >= 400 and std_packet_length <= 80:
            return "SynFlood"
        if protocol == 17 and pps >= 400:
            return "UDP Flood"
        if attack_probability >= 0.9 or bps >= 1_000_000:
            return "DDoS"
        return "Suspicious Flood"

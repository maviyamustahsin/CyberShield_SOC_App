import joblib
import pandas as pd
import numpy as np
import logging

logging.basicConfig(level=logging.INFO, format='[+] %(message)s')

class IntrusionDetectionEngine:
    def __init__(self, model_dir: str):
        self.model_dir = model_dir
        self.model = None
        self.scaler = None
        self.le = None
        self.feature_names = None
        self._load_artifacts()

    def _load_artifacts(self):
        try:
            self.model = joblib.load(f"{self.model_dir}/rf_model.pkl")
            self.scaler = joblib.load(f"{self.model_dir}/scaler.pkl")
            self.le = joblib.load(f"{self.model_dir}/label_encoder.pkl")
            self.feature_names = joblib.load(f"{self.model_dir}/feature_names.pkl")
            logging.info("Detection Engine: All model artifacts loaded successfully.")
        except Exception as e:
            logging.error(f"Detection Engine init failed: {e}")

    def predict_flow(self, flow_data: dict) -> dict:
        """
        Takes a dictionary representing a single network flow and predicts if it's an attack.
        """
        if not self.model:
            return {"error": "Model not loaded"}

        # Convert to DataFrame ensuring column order
        df_flow = pd.DataFrame([flow_data])
        
        # Add missing columns with 0 if necessary (robustness)
        for col in self.feature_names:
            if col not in df_flow.columns:
                df_flow[col] = 0.0

        # Enforce column order
        df_flow = df_flow[self.feature_names]

        # Handle any possible missing values that crept in
        df_flow.fillna(0, inplace=True)

        # Scale
        scaled_flow = self.scaler.transform(df_flow)

        # Predict
        pred_encoded = self.model.predict(scaled_flow)[0]
        pred_label = self.le.inverse_transform([pred_encoded])[0]

        # Calculate prediction probabilities
        proba = self.model.predict_proba(scaled_flow)[0]
        confidence = float(np.max(proba))

        is_attack = "BENIGN" not in str(pred_label).upper()

        # Compute Risk Score
        risk = self.compute_risk_score(pred_label, confidence, is_attack)

        return {
            "prediction": pred_label,
            "confidence": round(confidence, 4),
            "is_attack": is_attack,
            "risk_score": risk["score"],
            "threat_level": risk["level"],
            "recommended_action": risk["action"],
        }

    def compute_risk_score(self, attack_type: str, confidence: float, is_attack: bool) -> dict:
        """
        AI Threat Risk Scoring System.
        Calculates a 0–100 risk score based on:
          - Attack category severity weight
          - ML model confidence
          - Simulated behavioral factors
        """
        if not is_attack:
            return {"score": 0, "level": "INFO", "action": "Allow Traffic"}

        # Severity weights per attack category (based on MITRE ATT&CK impact)
        severity_map = {
            "DDoS":            0.95,   # Denial of Service — Critical infrastructure impact
            "DoS Hulk":        0.90,
            "DoS GoldenEye":   0.88,
            "DoS slowloris":   0.85,
            "DoS Slowhttptest":0.85,
            "PortScan":        0.60,   # Reconnaissance — precursor to attack
            "FTP-Patator":     0.80,   # Brute force — credential compromise
            "SSH-Patator":     0.82,
            "Web Attack":      0.88,   # Application layer — data breach risk
            "Bot":             0.75,   # C2 activity — lateral movement
            "Infiltration":    0.92,   # Advanced persistent threat indicator
            "Heartbleed":      0.97,   # Critical vulnerability exploit
        }

        # Find closest matching severity
        base_severity = 0.70  # Default for unknown attack types
        for key, weight in severity_map.items():
            if key.lower() in attack_type.lower():
                base_severity = weight
                break

        # Risk formula: weighted combination of severity + confidence
        raw_score = (base_severity * 0.6 + confidence * 0.4) * 100

        # Clamp to 0-100
        risk_score = int(min(100, max(0, raw_score)))

        # Map to threat level
        if risk_score >= 85:
            level = "CRITICAL"
            action = "Block Source IP + Alert SOC Team"
        elif risk_score >= 70:
            level = "HIGH"
            action = "Block Source IP"
        elif risk_score >= 50:
            level = "MEDIUM"
            action = "Rate-limit + Monitor"
        elif risk_score >= 25:
            level = "LOW"
            action = "Log + Monitor"
        else:
            level = "INFO"
            action = "Allow Traffic"

        return {"score": risk_score, "level": level, "action": action}

if __name__ == "__main__":
    # Quick test dummy
    engine = IntrusionDetectionEngine(r"c:\Users\Maaz\Desktop\cy\ai_ids_soc\models")
    print("Engine Ready.")

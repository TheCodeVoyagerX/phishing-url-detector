"""
Inference & Risk Analysis Engine for Phishing URL Detection
Loads the trained ML model, runs feature extraction, computes risk scores (0-100),
evaluates threat indicators, and provides actionable verdicts.
"""

import os
from typing import Any, Dict, List, Optional
import joblib
import pandas as pd

from src.feature_extractor import analyze_threat_indicators, extract_features
from src.train import train_and_evaluate

DEFAULT_MODEL_PATH = "models/phishing_detector_model.pkl"


class PhishingDetector:
    def __init__(self, model_path: str = DEFAULT_MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.feature_names = []
        self.metrics = {}
        self.feature_importances = {}
        self.metadata = {}
        self._ensure_model_loaded()

    def _ensure_model_loaded(self) -> None:
        """Loads the model from disk, or triggers training if model doesn't exist yet."""
        if not os.path.exists(self.model_path):
            print(f"Model file '{self.model_path}' not found. Training model now...")
            train_and_evaluate(output_model_path=self.model_path)

        artifact = joblib.load(self.model_path)
        self.model = artifact["model"]
        self.feature_names = artifact["feature_names"]
        self.metrics = artifact.get("metrics", {})
        self.feature_importances = artifact.get("feature_importances", {})
        self.metadata = {
            "model_name": artifact.get("model_name", "Random Forest"),
            "trained_at": artifact.get("trained_at", "N/A"),
            "total_samples": artifact.get("total_samples", 0),
            "all_models_metrics": artifact.get("all_models_metrics", {})
        }

    def predict(self, raw_url: str) -> Dict[str, Any]:
        """
        Analyzes a single URL and returns comprehensive prediction and threat breakdown.
        """
        if not raw_url or not raw_url.strip():
            raise ValueError("URL cannot be empty.")

        raw_url = raw_url.strip()
        features_dict = extract_features(raw_url)
        df_feats = pd.DataFrame([features_dict])[self.feature_names]

        # ML prediction & probability
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(df_feats)[0]
            phishing_prob = float(proba[1])
        else:
            pred = int(self.model.predict(df_feats)[0])
            phishing_prob = 1.0 if pred == 1 else 0.0

        # Baseline heuristic adjustments for clear-cut danger signals
        heuristic_boost = 0.0
        if features_dict.get("is_ip") == 1:
            heuristic_boost += 0.20
        if features_dict.get("brand_spoofing") == 1:
            heuristic_boost += 0.35
        if features_dict.get("num_at_symbols", 0) > 0:
            heuristic_boost += 0.25

        final_score = min(max(phishing_prob + heuristic_boost, 0.0), 1.0)
        risk_score = int(round(final_score * 100))

        # Categorize risk level
        if risk_score < 25:
            risk_level = "Safe"
            risk_color = "#22c55e"  # Emerald green
            badge_class = "safe"
            verdict_summary = "This URL exhibits standard legitimate traits with no major anomalies detected."
            action_advice = "Safe to visit. Always ensure HTTPS lock icon is active in browser."
            is_phishing = False
        elif risk_score < 50:
            risk_level = "Low Risk / Caution"
            risk_color = "#eab308"  # Yellow
            badge_class = "caution"
            verdict_summary = "Minor structural oddities detected, but high likelihood of legitimate origin."
            action_advice = "Proceed with caution. Verify the domain spelling matches the intended destination."
            is_phishing = False
        elif risk_score < 75:
            risk_level = "Suspicious"
            risk_color = "#f97316"  # Orange
            badge_class = "suspicious"
            verdict_summary = "Elevated risk signals detected (e.g. sensitive keywords, multiple subdomains, or abuse TLD)."
            action_advice = "Avoid entering sensitive personal information, passwords, or seed phrases."
            is_phishing = True
        else:
            risk_level = "Critical Phishing Threat"
            risk_color = "#ef4444"  # Red
            badge_class = "danger"
            verdict_summary = "High probability of malicious intent. Deceptive brand spoofing or direct IP hosting pattern."
            action_advice = "DO NOT PROCEED. Block access and report this URL to your security team."
            is_phishing = True

        # Extract top risk factors
        top_risk_factors = []
        for feat, imp in list(self.feature_importances.items())[:8]:
            val = features_dict.get(feat, 0)
            if val > 0:
                top_risk_factors.append({
                    "feature": feat.replace("_", " ").title(),
                    "value": val,
                    "importance_weight": imp
                })

        # Deep threat indicators
        threat_indicators = analyze_threat_indicators(raw_url)

        return {
            "url": raw_url,
            "prediction": "Phishing" if is_phishing else "Legitimate",
            "is_phishing": is_phishing,
            "confidence_pct": round(final_score * 100, 1),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_color": risk_color,
            "badge_class": badge_class,
            "verdict_summary": verdict_summary,
            "action_advice": action_advice,
            "features": features_dict,
            "top_risk_factors": top_risk_factors,
            "threat_indicators": threat_indicators,
            "model_used": self.metadata.get("model_name", "Random Forest")
        }

    def predict_batch(self, urls: List[str]) -> pd.DataFrame:
        """
        Scans a list of URLs and returns a summary DataFrame.
        """
        records = []
        for u in urls:
            u_clean = str(u).strip()
            if not u_clean:
                continue
            res = self.predict(u_clean)
            records.append({
                "URL": res["url"],
                "Verdict": res["prediction"],
                "Risk Score": res["risk_score"],
                "Risk Level": res["risk_level"],
                "Confidence (%)": res["confidence_pct"],
                "Action Advice": res["action_advice"]
            })
        return pd.DataFrame(records)

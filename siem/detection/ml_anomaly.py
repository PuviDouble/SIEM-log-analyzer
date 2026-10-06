import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest

class MLAnomalyDetector:
    """
    Unsupervised Machine Learning Anomaly Detection Engine using Isolation Forest.
    Detects zero-day, low-and-slow, and statistical outlier attacks bypassing static rules.
    """

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42
        )
        self.is_trained = False
        self.ip_window = defaultdict(list)  # Sliding window timestamps per IP
        self.training_history: List[Dict[str, float]] = []

    def extract_features(self, event: Dict[str, Any]) -> List[float]:
        """Extracts numerical features from normalized log event."""
        ip = event.get("source_ip", "0.0.0.0")
        now = datetime.utcnow()

        # Update sliding window request count for IP (last 60 seconds)
        self.ip_window[ip].append(now)
        self.ip_window[ip] = [t for t in self.ip_window[ip] if now - t <= timedelta(seconds=60)]
        request_freq = len(self.ip_window[ip])

        features = [
            float(event.get("request_length", 0)),
            float(event.get("bytes_sent", 0)),
            float(event.get("param_entropy", 0.0)),
            float(request_freq),
            1.0 if event.get("is_off_hours", False) else 0.0,
            float(event.get("status_code", 200))
        ]
        return features

    def train_baseline(self, events: List[Dict[str, Any]]):
        """Trains Isolation Forest model on historical or baseline events."""
        if len(events) < 10:
            print("[MLAnomalyDetector] Insufficient samples to train ML model (min 10 required).")
            return

        feature_matrix = [self.extract_features(e) for e in events]
        X = np.array(feature_matrix)
        self.model.fit(X)
        self.is_trained = True
        self.training_history = [
            {
                "request_length": f[0],
                "bytes_sent": f[1],
                "param_entropy": f[2],
                "request_freq": f[3],
                "is_off_hours": f[4],
                "status_code": f[5]
            }
            for f in feature_matrix
        ]

    def evaluate_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluates single event against trained Isolation Forest baseline.
        Returns alert dict if event is predicted as an anomaly (-1).
        """
        features = self.extract_features(event)
        
        # Auto-train on initial events if model not yet trained
        if not self.is_trained:
            self.training_history.append({
                "request_length": features[0],
                "bytes_sent": features[1],
                "param_entropy": features[2],
                "request_freq": features[3],
                "is_off_hours": features[4],
                "status_code": features[5]
            })
            if len(self.training_history) >= 20:
                X = np.array([[h[k] for k in ["request_length", "bytes_sent", "param_entropy", "request_freq", "is_off_hours", "status_code"]] for h in self.training_history])
                self.model.fit(X)
                self.is_trained = True
            return None

        X = np.array([features])
        prediction = self.model.predict(X)[0]  # -1 for anomaly, 1 for normal
        score = float(self.model.score_samples(X)[0])  # Lower score = higher anomaly probability

        if prediction == -1:
            anomaly_confidence = min(100, int(abs(score) * 100))
            explanations = self._explain_anomaly(features)

            return {
                "rule_id": "ML-ANOMALY-001",
                "rule_title": "Unsupervised ML Anomaly Detected (Isolation Forest)",
                "detection_type": "ML_ANOMALY",
                "severity": "CRITICAL" if score < -0.35 else "HIGH",
                "mitre_technique": "T1078",
                "source_ip": event.get("source_ip", "0.0.0.0"),
                "user": event.get("user", "unknown"),
                "details": {
                    "anomaly_score": round(score, 4),
                    "confidence_score": f"{anomaly_confidence}%",
                    "extracted_features": {
                        "request_length": features[0],
                        "bytes_sent": features[1],
                        "param_entropy": features[2],
                        "request_freq_per_min": features[3],
                        "is_off_hours": bool(features[4]),
                        "status_code": features[5]
                    },
                    "anomaly_reasons": explanations
                }
            }

        return None

    def _explain_anomaly(self, features: List[float]) -> List[str]:
        """Provides human-readable explainability for ML anomaly detections."""
        reasons = []
        if features[2] > 4.2:
            reasons.append(f"Abnormally high Shannon entropy ({features[2]}), indicating obfuscated payload / SQLi / shellcode.")
        if features[3] > 15:
            reasons.append(f"High request velocity ({int(features[3])} req/min), indicating automated scan or brute force.")
        if features[0] > 200:
            reasons.append(f"Unusual HTTP request length ({int(features[0])} bytes).")
        if features[4] == 1.0:
            reasons.append("Activity detected outside normal business operating hours.")
        if features[5] in [401, 403, 500]:
            reasons.append(f"Suspicious HTTP response status code ({int(features[5])}).")
        
        if not reasons:
            reasons.append("Multi-dimensional statistical outlier in request frequency and size.")
        return reasons

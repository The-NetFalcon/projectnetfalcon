"""
AI ANOMALY DETECTION - Detects weird traffic in real-time
"""

import joblib
import numpy as np

class AIAnomalyDetector:
    """Simple AI detector - tells you if traffic is weird"""
    
    def __init__(self, model_path="ai_model.pkl"):
        # Load the trained model
        try:
            self.model = joblib.load(model_path)
            self.alerts = []
            print("[+] AI Detector ready!")
        except:
            print("[!] Model not found! Run ai_train.py first.")
            self.model = None
            self.alerts = []
    
    def extract_features(self, flow):
        """Turn a flow into numbers"""
        return [
            flow.get('fwd_packets', 0),
            flow.get('rev_packets', 0),
            flow.get('fwd_bytes', 0),
            flow.get('rev_bytes', 0),
            flow.get('duration', 0),
            flow.get('fwd_packets', 0) / max(flow.get('duration', 1), 0.001),
            flow.get('rev_packets', 0) / max(flow.get('duration', 1), 0.001),
            flow.get('fwd_bytes', 0) / max(flow.get('fwd_packets', 1), 1),
            flow.get('rev_bytes', 0) / max(flow.get('rev_packets', 1), 1),
        ]
    
    def check_flow(self, flow):
        """Check ONE flow - returns alert if it's weird"""
        
        if self.model is None:
            return None
        
        try:
            # Convert flow to numbers
            features = np.array([self.extract_features(flow)])
            
            # Ask the model: Is this normal?
            prediction = self.model.predict(features)[0]
            
            if prediction == -1:
                # It's weird! Create an alert
                alert = {
                    "type": "AI_ANOMALY",
                    "severity": "HIGH",
                    "src_ip": flow.get('src_ip', 'unknown'),
                    "dst_ip": flow.get('dst_ip', 'unknown'),
                    "protocol": flow.get('protocol', 'unknown'),
                    "fwd_packets": flow.get('fwd_packets', 0),
                    "rev_packets": flow.get('rev_packets', 0),
                    "fwd_bytes": flow.get('fwd_bytes', 0),
                    "duration": flow.get('duration', 0),
                    "reason": "Unusual traffic pattern detected by AI"
                }
                self.alerts.append(alert)
                return alert
            
        except Exception as e:
            print(f"[!] Error in AI detection: {e}")
        
        return None
    
    def get_alerts(self):
        """Get all alerts so far"""
        return self.alerts
    
    def clear_alerts(self):
        """Clear stored alerts"""
        self.alerts = []
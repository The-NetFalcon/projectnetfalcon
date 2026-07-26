"""
AI ANOMALY DETECTION - Enhanced Version
Uses the improved model with more features
"""

import joblib
import numpy as np
from pathlib import Path

class AIAnomalyDetector:
    """Enhanced AI detector with more features and better accuracy"""
    
    def __init__(self, model_path="ai_model_enhanced.pkl", scaler_path="scaler.pkl"):
        # Load the trained model
        print("[+] Loading enhanced AI model...")
        
        if not Path(model_path).exists():
            print(f"[!] Model {model_path} not found! Training required.")
            self.model = None
            self.scaler = None
            self.alerts = []
            return
        
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.alerts = []
        self.anomaly_scores = []
        print("[+] Enhanced AI Detector ready!")
    
    def extract_features(self, flow):
        """Extract the same features used in training"""
        
        fwd_packets = flow.get('fwd_packets', 0)
        rev_packets = flow.get('rev_packets', 0)
        fwd_bytes = flow.get('fwd_bytes', 0)
        rev_bytes = flow.get('rev_bytes', 0)
        duration = max(flow.get('duration', 0.001), 0.001)
        
        total_packets = fwd_packets + rev_packets
        total_bytes = fwd_bytes + rev_bytes
        
        fwd_packet_rate = fwd_packets / duration
        rev_packet_rate = rev_packets / duration
        total_packet_rate = total_packets / duration
        
        fwd_byte_rate = fwd_bytes / duration
        rev_byte_rate = rev_bytes / duration
        total_byte_rate = total_bytes / duration
        
        avg_fwd_packet_size = fwd_bytes / max(fwd_packets, 1)
        avg_rev_packet_size = rev_bytes / max(rev_packets, 1)
        avg_packet_size = total_bytes / max(total_packets, 1)
        
        bytes_per_packet_fwd = fwd_bytes / max(fwd_packets, 1)
        bytes_per_packet_rev = rev_bytes / max(rev_packets, 1)
        
        if total_packets > 0:
            fwd_ratio = fwd_packets / total_packets
            rev_ratio = rev_packets / total_packets
            byte_ratio = fwd_bytes / max(total_bytes, 1)
        else:
            fwd_ratio = 0.5
            rev_ratio = 0.5
            byte_ratio = 0.5
        
        return [
            fwd_packets, rev_packets, fwd_bytes, rev_bytes, duration,
            fwd_packet_rate, rev_packet_rate, total_packet_rate,
            fwd_byte_rate, rev_byte_rate, total_byte_rate,
            avg_fwd_packet_size, avg_rev_packet_size, avg_packet_size,
            bytes_per_packet_fwd, bytes_per_packet_rev,
            fwd_ratio, rev_ratio, byte_ratio,
            total_packets, total_bytes,
        ]
    
    def check_flow(self, flow):
        """Check a flow for anomalies"""
        
        if self.model is None:
            return None
        
        try:
            # Extract features
            features = np.array([self.extract_features(flow)])
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Get prediction and score
            prediction = self.model.predict(features_scaled)[0]
            anomaly_score = self.model.score_samples(features_scaled)[0]
            
            self.anomaly_scores.append(anomaly_score)
            
            if prediction == -1:
                # Anomaly detected
                alert = {
                    "type": "AI_ANOMALY",
                    "severity": "HIGH",
                    "timestamp": flow.get('start_time', ''),
                    "src_ip": flow.get('src_ip', 'unknown'),
                    "dst_ip": flow.get('dst_ip', 'unknown'),
                    "protocol": flow.get('protocol', 'unknown'),
                    "fwd_packets": flow.get('fwd_packets', 0),
                    "rev_packets": flow.get('rev_packets', 0),
                    "fwd_bytes": flow.get('fwd_bytes', 0),
                    "duration": flow.get('duration', 0),
                    "anomaly_score": float(anomaly_score),
                    "reason": f"Unusual traffic pattern detected (score: {anomaly_score:.3f})",
                    "features": {
                        "packet_rate": flow.get('fwd_packets', 0) / max(flow.get('duration', 1), 0.001),
                        "bytes_per_packet": flow.get('fwd_bytes', 0) / max(flow.get('fwd_packets', 1), 1),
                        "direction_ratio": "forward" if flow.get('fwd_packets', 0) > flow.get('rev_packets', 0) else "reverse"
                    }
                }
                self.alerts.append(alert)
                return alert
                
        except Exception as e:
            print(f"[!] Error in AI detection: {e}")
        
        return None
    
    def get_alerts(self):
        """Return all detected anomalies"""
        return self.alerts
    
    def clear_alerts(self):
        """Clear stored alerts"""
        self.alerts = []
        self.anomaly_scores = []
    
    def get_statistics(self):
        """Get detection statistics"""
        if self.anomaly_scores:
            return {
                "total_flows_checked": len(self.anomaly_scores),
                "anomalies_detected": len(self.alerts),
                "avg_anomaly_score": float(np.mean(self.anomaly_scores)),
                "min_score": float(np.min(self.anomaly_scores)),
                "max_score": float(np.max(self.anomaly_scores))
            }
        return {}

# Test function
def test_detector():
    """Test the enhanced detector"""
    print("[+] Testing Enhanced AI Detector...")
    detector = AIAnomalyDetector()
    
    if detector.model is None:
        print("[!] Model not found. Run detection.ai_train first.")
        return
    
    # Test flows
    test_flows = [
        {
            'src_ip': '192.168.1.5',
            'dst_ip': '8.8.8.8',
            'protocol': 'TCP',
            'fwd_packets': 10,
            'rev_packets': 15,
            'fwd_bytes': 1000,
            'rev_bytes': 1500,
            'duration': 5.0,
        },
        {
            'src_ip': '192.168.1.45',
            'dst_ip': '185.220.101.9',
            'protocol': 'TCP',
            'fwd_packets': 10000,
            'rev_packets': 50,
            'fwd_bytes': 1000000,
            'rev_bytes': 1000,
            'duration': 0.5,
        }
    ]
    
    for flow in test_flows:
        result = detector.check_flow(flow)
        if result:
            print(f"[AI] Anomaly: {flow['src_ip']} -> {flow['dst_ip']} (score: {result['anomaly_score']:.3f})")
        else:
            print(f"[AI] Normal: {flow['src_ip']} -> {flow['dst_ip']}")

if __name__ == "__main__":
    test_detector()
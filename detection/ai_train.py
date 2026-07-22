"""
TRAIN AI MODEL - Run this once!
"""

import json
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

def extract_features(flow):
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

def train_model(flows_file="out/flows.jsonl", output_model="ai_model.pkl"):
    """Train the AI model"""
    
    print("[+] Loading flows from", flows_file)
    
    flows = []
    with open(flows_file, 'r') as f:
        for line in f:
            try:
                flows.append(json.loads(line))
            except:
                continue
    
    print(f"[+] Loaded {len(flows)} flows")
    
    features = []
    for flow in flows:
        features.append(extract_features(flow))
    
    features = np.array(features)
    
    print("[+] Training Isolation Forest...")
    model = IsolationForest(
        contamination=0.05,
        random_state=42
    )
    model.fit(features)
    
    joblib.dump(model, output_model)
    print(f"[+] Model saved to {output_model}")
    
    predictions = model.predict(features)
    anomalies = sum(1 for p in predictions if p == -1)
    print(f"[+] Found {anomalies} anomalies in training data ({anomalies/len(features)*100:.1f}%)")
    print("[+] Training complete!")
    
    return model

if __name__ == "__main__":
    train_model(flows_file="out/flows.jsonl", output_model="ai_model.pkl")
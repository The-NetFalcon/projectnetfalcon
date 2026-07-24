"""
TRAIN AI MODEL - Enhanced Version
Uses more features for better anomaly detection
"""

import json
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import os

def extract_enhanced_features(flow):
    """Extract more features for better detection"""
    
    # Basic features
    fwd_packets = flow.get('fwd_packets', 0)
    rev_packets = flow.get('rev_packets', 0)
    fwd_bytes = flow.get('fwd_bytes', 0)
    rev_bytes = flow.get('rev_bytes', 0)
    duration = max(flow.get('duration', 0.001), 0.001)
    
    # Calculate derived features
    total_packets = fwd_packets + rev_packets
    total_bytes = fwd_bytes + rev_bytes
    
    # Packet rates (packets per second)
    fwd_packet_rate = fwd_packets / duration
    rev_packet_rate = rev_packets / duration
    total_packet_rate = total_packets / duration
    
    # Byte rates (bytes per second)
    fwd_byte_rate = fwd_bytes / duration
    rev_byte_rate = rev_bytes / duration
    total_byte_rate = total_bytes / duration
    
    # Average packet sizes
    avg_fwd_packet_size = fwd_bytes / max(fwd_packets, 1)
    avg_rev_packet_size = rev_bytes / max(rev_packets, 1)
    avg_packet_size = total_bytes / max(total_packets, 1)
    
    # Packet-to-byte ratios (indicates packet efficiency)
    bytes_per_packet_fwd = fwd_bytes / max(fwd_packets, 1)
    bytes_per_packet_rev = rev_bytes / max(rev_packets, 1)
    
    # Asymmetry features (detects unusual direction patterns)
    if total_packets > 0:
        fwd_ratio = fwd_packets / total_packets
        rev_ratio = rev_packets / total_packets
        byte_ratio = fwd_bytes / max(total_bytes, 1)
    else:
        fwd_ratio = 0.5
        rev_ratio = 0.5
        byte_ratio = 0.5
    
    # Return comprehensive feature set
    return [
        # Basic counts
        fwd_packets,
        rev_packets,
        fwd_bytes,
        rev_bytes,
        duration,
        
        # Rates
        fwd_packet_rate,
        rev_packet_rate,
        total_packet_rate,
        fwd_byte_rate,
        rev_byte_rate,
        total_byte_rate,
        
        # Packet sizes
        avg_fwd_packet_size,
        avg_rev_packet_size,
        avg_packet_size,
        bytes_per_packet_fwd,
        bytes_per_packet_rev,
        
        # Ratios
        fwd_ratio,
        rev_ratio,
        byte_ratio,
        
        # Total summary
        total_packets,
        total_bytes,
    ]

def train_enhanced_model(flows_file="out/flows.jsonl", output_model="ai_model_enhanced.pkl"):
    """Train enhanced Isolation Forest model"""
    
    print("=" * 50)
    print("TRAINING ENHANCED AI ANOMALY DETECTION MODEL")
    print("=" * 50)
    
    print(f"[+] Loading flows from: {flows_file}")
    
    # Load flows
    flows = []
    with open(flows_file, 'r') as f:
        for line in f:
            try:
                flows.append(json.loads(line.strip()))
            except:
                continue
    
    if not flows:
        print("[!] No flows found! Make sure the flows file exists.")
        return None
    
    print(f"[+] Loaded {len(flows)} flows")
    
    # Extract enhanced features
    print("[+] Extracting features...")
    features = []
    for flow in flows:
        features.append(extract_enhanced_features(flow))
    
    features = np.array(features)
    print(f"[+] Feature shape: {features.shape}")
    
    # Standardize features (important for Isolation Forest)
    print("[+] Standardizing features...")
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    # Train Isolation Forest
    print("[+] Training Isolation Forest with enhanced features...")
    model = IsolationForest(
        contamination=0.03,      # Expect ~3% anomalies
        random_state=42,        # For reproducibility
        n_estimators=200,       # More trees = better detection
        max_samples='auto',
        bootstrap=True
    )
    model.fit(features_scaled)
    
    # Save both the model and the scaler
    print("[+] Saving model and scaler...")
    joblib.dump(model, output_model)
    joblib.dump(scaler, "scaler.pkl")
    print(f"[+] Model saved to: {output_model}")
    print(f"[+] Scaler saved to: scaler.pkl")
    
    # Statistics
    predictions = model.predict(features_scaled)
    anomalies = sum(1 for p in predictions if p == -1)
    print(f"[+] Anomalies detected in training: {anomalies} ({anomalies/len(flows)*100:.2f}%)")
    
    # Show sample features
    print("\n[+] Sample features from a normal flow:")
    sample_idx = 0
    print(f"    Fwd Packets: {features[sample_idx][0]}")
    print(f"    Rev Packets: {features[sample_idx][1]}")
    print(f"    Duration: {features[sample_idx][4]:.2f}s")
    print(f"    Packet Rate: {features[sample_idx][5]:.2f} pkts/s")
    print(f"    Avg Packet Size: {features[sample_idx][12]:.0f} bytes")
    
    print("\n[+] Training complete!")
    return model, scaler

if __name__ == "__main__":
    # Train on normal traffic
    train_enhanced_model()
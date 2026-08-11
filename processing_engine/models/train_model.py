"""
Train Isolation Forest model for Midnight Protocol
"""

import os
import joblib
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# -----------------------------
# Create synthetic normal traffic
# -----------------------------

np.random.seed(42)

rows = 5000

X = np.column_stack([

    np.random.normal(30, 5, rows),        # packet_count

    np.random.normal(25000, 8000, rows),  # total_bytes

    np.random.normal(15, 3, rows),        # duration

    np.random.normal(2.0, 0.8, rows),     # packets_per_second

    np.random.normal(800, 150, rows),     # avg_packet_size

    np.random.choice([6,17], rows),       # protocol

    np.random.randint(1024,65535,rows),   # src_port

    np.random.choice(
        [53,80,110,143,443],
        rows
    ),                                    # dst_port

    np.random.normal(64,5,rows),          # ttl

    np.random.normal(4.2,0.4,rows)        # entropy

])

# -----------------------------
# Normalize
# -----------------------------

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)

# -----------------------------
# Train model
# -----------------------------

model = IsolationForest(

    n_estimators=200,

    contamination=0.02,

    random_state=42

)

model.fit(X_scaled)

bundle = {

    "model": model,

    "scaler": scaler,

    "trained_on_rows": len(X)

}

output_path = os.path.join(

    os.path.dirname(__file__),

    "anomaly_model.pkl"

)

joblib.dump(bundle, output_path)

print("Model saved to")

print(output_path)
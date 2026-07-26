# The Midnight Protocol - AI Anomaly Detection Module

## 🚀 Overview

This module provides **AI-powered anomaly detection** for network traffic analysis. It uses an **Isolation Forest** algorithm trained on **500,000+ flows** from **15 GB** of real-world normal network traffic (23 million packets) to identify unusual patterns that traditional signature-based rules might miss.

---

## 🎯 Key Features

| Feature | Description |
|---------|-------------|
| **Algorithm** | Isolation Forest (scikit-learn) |
| **Training Data** | 500,000+ flows from 15 GB of CTU Normal PCAP captures (23 million packets) |
| **Features** | 21 features including packet rates, byte rates, packet sizes, direction ratios |
| **Detection** | Real-time anomaly detection on network flows |
| **Integration** | Works alongside signature engine for dual-engine detection |
| **Chain-of-Custody** | SHA-256 hashed evidence for court admissibility |

---

## 📊 Model Specifications

| Metric | Value |
|--------|-------|
| Training Flows | 500,000+ |
| Training Packets | 23,000,000+ |
| Training Data Size | 15 GB |
| Features Used | 21 |
| Anomaly Rate (Training) | ~3.00% |
| Test Results (sample.pcap) | 33 AI anomalies detected |
| Total Alerts (sample.pcap) | 104 (AI + Signatures + Beaconing) |

---

## 📁 Files in This Module

| File | Purpose |
|------|---------|
| `ai_train.py` | Train the Isolation Forest model on normal traffic |
| `ai_anomaly.py` | Real-time anomaly detection class |
| `cli.py` | CLI with AI integration |
| `ai_model_enhanced.pkl` | Trained model (21 features, 500,000+ flows) |
| `scaler.pkl` | Feature scaler for normalization |

---

## 🚀 How to Use

### 1. Train the Model (if needed)
```bash
python -m detection.ai_train
```

### 2. Run Detection with AI
```bash
python -m detection.cli --pcap sample.pcap --out-dir ./out
```

### 3. View AI Alerts
```bash
cat out/alerts.jsonl | grep AI_ANOMALY
```

---

## 📈 Sample Output

```
[+] Initializing Enhanced AI Anomaly Detector...
[+] Enhanced AI Detector ready!
[+] Running Enhanced AI Anomaly Detection on flows...
[AI] Anomaly detected: 192.168.1.45 -> 185.220.101.9 (Packets: 1/0)
[AI] Anomaly detected: 192.168.1.77 -> 203.0.113.99 (Packets: 1/0)
[+] AI detected 33 anomalous flows
[+] 104 alerts generated
```

---

## 🏆 Why This AI Model is Powerful

| Feature | Basic Model | Enhanced Model |
|---------|-------------|----------------|
| Training Flows | 32 | **500,000+** |
| Training Packets | ~100 | **23,000,000+** |
| Training Data Size | ~1 MB | **15 GB** |
| Features | 9 | **21** |
| Detection Accuracy | Basic | **High** |
| False Positives | Higher | **Lower** |
| Real-World Training | No | **Yes (15 GB CTU data)** |

---

## 🔗 Integration

This module is fully integrated with:
- ✅ **Ingestion** (PcapImporter)
- ✅ **DPI** (DNS/HTTP/SMTP decoding)
- ✅ **Signature Engine** (rules.json)
- ✅ **Beaconing Detection**
- ✅ **Chain-of-Custody** (SHA-256 hashing)

---

## 👥 Team Contribution

- **Harnish S Raval**: AI Module Development (Isolation Forest, Feature Engineering, Integration, Testing)
- **Keval Punchal**: Testing Model And Bug Fixing

---

## 📚 References

- Isolation Forest: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
- CTU Normal PCAPs: https://www.stratosphereips.org/datasets-overview
```


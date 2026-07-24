# The Midnight Protocol - AI Anomaly Detection Module

## 🚀 Overview

This module provides **AI-powered anomaly detection** for network traffic analysis. It uses an **Isolation Forest** algorithm trained on **36,916 flows** of real normal network traffic to identify unusual patterns that traditional signature-based rules might miss.

---

## 🎯 Key Features

| Feature | Description |
|---------|-------------|
| **Algorithm** | Isolation Forest (scikit-learn) |
| **Training Data** | 36,916 flows from CTU Normal PCAP captures (1.6 GB) |
| **Features** | 21 features including packet rates, byte rates, packet sizes, direction ratios |
| **Detection** | Real-time anomaly detection on network flows |
| **Integration** | Works alongside signature engine for dual-engine detection |
| **Chain-of-Custody** | SHA-256 hashed evidence for court admissibility |

---

## 📊 Model Specifications

| Metric | Value |
|--------|-------|
| Training Flows | 36,916 |
| Features Used | 21 |
| Anomaly Rate (Training) | 3.00% (1,108 anomalies) |
| Test Results (sample.pcap) | 33 AI anomalies detected |
| Total Alerts (sample.pcap) | 104 (AI + Signatures + Beaconing) |

---

## 📁 Files in This Module

| File | Purpose |
|------|---------|
| `ai_train.py` | Train the Isolation Forest model on normal traffic |
| `ai_anomaly.py` | Real-time anomaly detection class |
| `cli.py` | CLI with AI integration |
| `ai_model_enhanced.pkl` | Trained model (21 features, 36,916 flows) |
| `scaler.pkl` | Feature scaler for normalization |

---

## 🚀 How to Use

### 1. Train the Model (if needed)

python -m detection.ai_train


### 2. Run Detection with AI

python -m detection.cli --pcap sample.pcap --out-dir ./out


### 3. View AI Alerts

cat out/alerts.jsonl | grep AI_ANOMALY


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



## 🏆 Why This AI Model is Powerful

| Feature | Basic Model | Enhanced Model |
|---------|-------------|----------------|
| Training Flows | 32 | **36,916** |
| Features | 9 | **21** |
| Detection Accuracy | Basic | **High** |
| False Positives | Higher | **Lower** |
| Real-World Training | No | **Yes (1.6 GB CTU data)** |

---

## 🔗 Integration

This module is fully integrated with:
- ✅ **Ingestion** (PcapImporter)
- ✅ **DPI** (DNS/HTTP/SMTP decoding)
- ✅ **Signature Engine** (rules.json)
- ✅ **Beaconing Detection**
- ✅ **Chain-of-Custody** (SHA-256 hashing)

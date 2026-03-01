# HiddenCamDetect

> AI-driven network anomaly detection to identify covert IP cameras on the local network by learning their traffic patterns.

Unauthorized IP cameras on a local network pose serious privacy and security risks. This project captures network traffic, extracts flow-level features, and trains an **SVM classifier** to distinguish between normal traffic and IP camera streaming traffic — enabling automated detection of hidden cameras.

---

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
  - [1. Feature Extraction](#1-feature-extraction)
  - [2. Model Training](#2-model-training)
  - [3. Inference](#3-inference)
  - [4. Live Capture + Inference](#4-live-capture--inference)
- [Dataset](#dataset)
- [Findings & Results](#findings--results)
  - [Classification Performance](#classification-performance)
  - [Per-Device Evaluation (Leave-One-Out)](#per-device-evaluation-leave-one-out)
  - [Feature Importance](#feature-importance)
  - [Capture Summary](#capture-summary)
- [Configuration](#configuration)
- [Requirements](#requirements)
- [License](#license)

---

## Overview

The detection pipeline consists of four stages:

1. **Packet Capture** — Sniff live traffic (upload-only, public-destination packets) using Scapy or tcpdump.
2. **Feature Extraction** — Aggregate raw packets into network flows and compute statistical features (bytes/sec, inter-arrival times, packet sizes, uplink/downlink ratio, etc.).
3. **SVM Training** — Train an SVM classifier with standard scaling and grid search over C/γ to separate streaming vs. non-streaming traffic.
4. **Inference & Reporting** — Score each flow, compute per-device threat levels, and generate human-readable reports.

---

## Project Structure

```
├── README.md
├── requirements.txt
├── use_model.py                          # Run inference or live capture + detection
├── capture/
│   └── capture_pcap.py                   # Live packet capture with upload-only filtering
├── config/
│   ├── capture_config.yaml               # Capture parameters (interface, duration, etc.)
│   └── model_config.yaml                 # Model parameters (reserved)
├── data/
│   ├── pcap_data/                        # Raw JSONL packet data (no-streaming)
│   ├── pcap_streaming/                   # Raw JSONL packet data (streaming)
│   └── processed/                        # Extracted flow feature CSVs
│       ├── flows_features_no_streaming.csv
│       └── flows_features_streaming.csv
└── src/
    ├── model/
    │   ├── train_svm.py                  # SVM training with grid search
    │   ├── eval_per_device.py            # Leave-one-device-out evaluation
    │   ├── permutation_importance.py     # Feature importance analysis
    │   ├── bytes_per_second.py           # Per-device bandwidth analysis
    │   └── svm_pipeline.joblib           # Saved trained model (after training)
    └── preprocessing/
        ├── extract_features.py           # Flow feature extraction from pcap files
        └── tools/
            ├── extract_streaming.py      # JSONL → feature CSV (streaming label)
            └── extract_no_streaming.py   # JSONL → feature CSV (no-streaming label)
```

---

## Installation

**1. Clone the repository:**

```bash
git clone https://github.com/<your-username>/CSE476-HiddenCamDetect.git
cd CSE476-HiddenCamDetect
```

**2. Create and activate a virtual environment (recommended):**

```bash
python -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows
```

**3. Install dependencies:**

```bash
pip install -r requirements.txt
```

**4. (Optional) For live capture:** Ensure `tcpdump` or `tshark` is available, and run with elevated privileges (`sudo`).

---

## Usage

All scripts use **project-relative paths** by default (via `Path(__file__).resolve()`), so they work correctly regardless of your current working directory.

### 1. Feature Extraction

Extract flow-level features from raw pcap files:

```bash
python src/preprocessing/extract_features.py \
  --input-dir data/raw_pcap \
  --output-csv data/processed/flow_features.csv
```

Or extract from JSONL files (streaming / no-streaming):

```bash
# Streaming traffic (label=0)
python src/preprocessing/tools/extract_streaming.py \
  --input data/pcap_streaming/packets_stream.jsonl \
  --output data/processed/flows_features_streaming.csv \
  --label 0

# Normal traffic (label=1)
python src/preprocessing/tools/extract_no_streaming.py \
  --input data/pcap_data/packets_no_stream.jsonl \
  --output data/processed/flows_features_no_streaming.csv \
  --label 1
```

### 2. Model Training

Train the SVM classifier:

```bash
python src/model/train_svm.py \
  --no-streaming data/processed/flows_features_no_streaming.csv \
  --streaming data/processed/flows_features_streaming.csv \
  --output-dir src/model \
  --model-name svm_pipeline.joblib
```

### 3. Inference

Run inference on pre-extracted feature CSVs:

```bash
python use_model.py \
  --input data/processed/flows_features_streaming.csv \
  --model src/model/svm_pipeline.joblib \
  --outdir outputs
```

**Outputs:**
- `outputs/predictions_with_confidence.csv` — per-flow predictions with confidence scores
- `outputs/device_threats.csv` — per-device threat summary
- `outputs/device_threats.txt` — human-readable threat report

### 4. Live Capture + Inference

Capture live network traffic and classify in real-time:

```bash
sudo python use_model.py \
  --live --iface en0 --duration 60 \
  --capture-method scapy \
  --model src/model/svm_pipeline.joblib \
  --outdir outputs
```

---

## Dataset

The dataset was generated by simulating IP camera streaming and normal network activity across **30 streaming devices** and **50 normal devices** on a local network.

| Split | Flows | Label |
|---|---|---|
| Streaming (camera traffic) | 3,128 | `no_streaming=0` |
| No-streaming (normal traffic) | 40,280 | `no_streaming=1` |
| **Total** | **43,408** | |

### Features per Flow

Each flow is described by the following numerical features:

| Feature | Description |
|---|---|
| `flow_duration` | Duration of the flow in seconds |
| `bytes_sent` | Total bytes sent by the initiator |
| `bytes_received` | Total bytes received from the responder |
| `bytes_per_second` | Transfer rate (bytes/sec) |
| `packets_per_second` | Packet rate |
| `packet_count` | Total number of packets in the flow |
| `mean_packet_size` | Average packet size (bytes) |
| `std_packet_size` | Standard deviation of packet sizes |
| `max_packet_size` | Largest packet in the flow |
| `min_packet_size` | Smallest packet in the flow |
| `inter_arrival_time_mean` | Mean time between consecutive packets |
| `inter_arrival_time_std` | Variability of inter-arrival times |

---

## Findings & Results

### Classification Performance

The SVM classifier (RBF kernel, `class_weight='balanced'`) was trained with 5-fold stratified cross-validation and grid search over `C ∈ {0.1, 1, 10}` and `γ ∈ {scale, auto}`.

**Test Set Results (80/20 split):**

| Metric | Class 0 (Streaming) | Class 1 (No-Streaming) | Macro Avg |
|---|---|---|---|
| **Precision** | 0.99 | 1.00 | 0.99 |
| **Recall** | 0.98 | 1.00 | 0.99 |
| **F1-Score** | 0.98 | 1.00 | 0.99 |

- **Test Accuracy:** ~99%
- The model achieves near-perfect separation between streaming and non-streaming traffic, with very few false positives or false negatives.

### Per-Device Evaluation (Leave-One-Out)

To test generalization to unseen devices, a **leave-one-device-out** cross-validation was performed: for each device, the model is trained on all other devices and tested on the held-out device.

| Metric | Value |
|---|---|
| Weighted average accuracy across devices | **~0.99** |

This confirms the model generalizes well to devices it has never seen during training.

### Feature Importance

Permutation importance analysis reveals the most discriminative features for detecting camera traffic:

| Rank | Feature | Importance |
|---|---|---|
| 1 | `bytes_per_second` | Highest |
| 2 | `packets_per_second` | High |
| 3 | `mean_packet_size` | High |
| 4 | `bytes_sent` | Moderate |
| 5 | `inter_arrival_time_mean` | Moderate |
| 6 | `std_packet_size` | Moderate |

**Key insight:** IP cameras produce a consistently high upload rate (`bytes_per_second`) with large, regularly-spaced packets — a distinctive signature that separates them from normal browsing, messaging, or download-heavy traffic.

### Capture Summary

During the streaming capture session (1 hour, 30 devices):

| Metric | Value |
|---|---|
| Total upload packets captured | 656,210 |
| Total upload bytes | 761 MB |
| Number of streaming devices | 30 |
| Average upload per device | ~25.4 MB |
| Dominant protocols | UDP, TCP |
| Top destination ports | 554 (RTSP), 443 (HTTPS), 80 (HTTP) |

The prevalence of port **554 (RTSP)** confirms typical IP camera streaming behavior, while ports 443/80 indicate cloud-upload and remote viewing services.

### Threat Level Classification

The inference pipeline assigns a threat level to each device based on the maximum streaming probability across its flows:

| Threat Level | Score Range | Meaning |
|---|---|---|
| **High** | ≥ 90% | Very likely an active streaming camera |
| **Medium** | 60–89% | Suspicious — may be streaming intermittently |
| **Low** | 30–59% | Low confidence — could be normal high-bandwidth device |
| **Info** | < 30% | Likely normal traffic |

---

## Configuration

### `config/capture_config.yaml`

```yaml
capture:
  interface: null       # null = auto-detect; set to e.g. "en0" or "eth0"
  duration: 30          # capture duration in seconds
  output_dir: "data/raw_pcap"
  max_devices: 5        # track at most N devices (0 = unlimited)
  promiscuous: true
```

### `config/model_config.yaml`

Reserved for future model hyperparameter configuration.

---

## Requirements

- **Python 3.9+**
- `scapy`, `pandas`, `numpy`, `scikit-learn`, `joblib`, `pyyaml`
- For live capture: **root privileges** and optionally `tshark`/`tcpdump`

Install all dependencies:

```bash
pip install -r requirements.txt
```

---

## License

This project was developed as part of **CSE 476 — Network Security** coursework.
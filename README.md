# HiddenCamDetect

AI-driven network anomaly detection to spot covert IP cameras on the local network by learning their traffic patterns.

## Project structure

- `capture/` — live packet capture and upload-only filtering (see [`capture.capture_pcap.PacketCapture`](capture/capture_pcap.py)).
- `src/preprocessing/` — flow feature extraction from pcaps (see [`preprocessing.extract_features.extract_features_from_pcaps`](src/preprocessing/extract_features.py)).
- `src/model/` — SVM training/evaluation scripts and saved pipeline (see [`model.train_svm.main`](src/model/train_svm.py)).
- `tools/` — helpers for converting JSONL/pcap to feature CSVs.
- `use_model.py` — run inference on processed CSVs or live capture.

## Quick start

```bash
# 1) Extract flow features from raw pcaps
python src/preprocessing/extract_features.py \
  --input_dir data/raw_pcap \
  --output_csv data/processed/flow_features.csv

# 2) Train SVM (expects labeled no-streaming vs streaming CSVs)
python src/model/train_svm.py \
  --no-streaming data/processed/flows_features_no_streaming.csv \
  --streaming data/processed/flows_features_streaming.csv \
  --output-dir src/model \
  --model-name svm_pipeline.joblib

# 3) Inference on existing features
python use_model.py \
  --input data/processed/flows_features_streaming.csv \
  --model src/model/svm_pipeline.joblib \
  --outdir outputs

# 4) Live capture + inference (requires root for scapy/tcpdump)
sudo python use_model.py \
  --live --iface en0 --duration 60 \
  --capture-method scapy \
  --model src/model/svm_pipeline.joblib \
  --outdir outputs
```

## Live capture (upload-only filter)

The capture path keeps only outbound/public-destination packets and summarizes per device. Entry point: [`capture.capture_pcap.PacketCapture.start_capture`](capture/capture_pcap.py).

## Feature extraction

Flows are built with a direction-agnostic 5-tuple and aggregated stats (bytes, rates, inter-arrivals, uplink/downlink ratio). See [`preprocessing.extract_features.extract_features_from_pcaps`](src/preprocessing/extract_features.py).

## Model training

SVM pipeline with standard scaling and grid search over C/γ. See [`model.train_svm.main`](src/model/train_svm.py). Saved model: `src/model/svm_pipeline.joblib`.

## Inference & reporting

`use_model.py` loads features, computes threat probability for class 0 (streaming/threat) via [`compute_prob_stream`](use_model.py) and summarizes per device with hashed MACs via [`summarize_by_device`](use_model.py). Outputs:
- `outputs/device_threats.csv`
- `outputs/device_threats.txt`
- live run also writes `outputs/features_live.csv`.

## Requirements

- Python 3.9+
- `scapy`, `pandas`, `numpy`, `scikit-learn`, `joblib`, `pyyaml`
- For live capture: root privileges; optional `tshark/tcpdump` for pcap conversion.

## Notes

- Vendor OUI mapping optional (`--vendor-map` CSV: `OUI,Vendor`).
- Max devices and capture options are configurable in `config/capture_config.yaml`.
# Network Intrusion Detection System (NIDS) - Complete Project Reference

## Project Overview

This is a real-time **Network Intrusion Detection System** that uses machine learning to detect and adapt to network attacks. It implements a hybrid approach combining:
- **MLP (Multi-Layer Perceptron)** neural network for high-confidence predictions
- **ARF (Adaptive Random Forest)** with **ADWIN** drift detection for handling concept drift and unknown attack patterns

The system is designed around the **CICDDoS2019 dataset** and can classify **11 attack types** (4 known + 7 unknown/drift).

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Attacker      │────▶│   Target (Nginx) │────▶│   Detector     │
│   (hping3,      │     │   Port 80/8081   │     │   Port 8080    │
│    nmap, iperf3)│     └──────────────────┘     │   MLP + ARF    │
└─────────────────┘                               └─────────────────┘
        │                                                   ▲
        └───────────────────────────────────────────────────┘
                   traffic_reporter.py queries /predict
```

### How It Works (5 Phases)

1. **Training Phase** - MLP learns from 4 known attack types (Syn, UDPLag, DrDoS_UDP, DrDoS_NTP)
2. **Detection Phase** - Incoming flows classified by MLP (if confidence >= 0.7) or ARF fallback
3. **Drift Monitoring** - ARF compares predictions with MLP, detects concept drift via ADWIN
4. **Adaptation** - When drift detected, ARF continues learning new patterns autonomously
5. **Alerting** - Suspicious flows trigger alerts via REST API or SSE stream

---

## Complete File Structure

```
minor/01-12/
│
├── README.md                          # Project overview and quick start guide
├── LICENSE                            # MIT License
├── requirements.txt                   # Python dependencies (pandas, numpy, scikit-learn, river)
├── .gitignore                         # Ignores CSVs, __pycache__, data/processed/, IDE files
│
├── data/
│   ├── raw/                           # Original CICDDoS2019 CSV datasets (NOT tracked in git)
│   │   ├── Syn.csv                    # Known attack - Syn Flood
│   │   ├── UDPLag.csv                 # Known attack - UDP Lag
│   │   ├── DrDoS_UDP.csv              # Known attack - Distributed Reflection DoS UDP
│   │   ├── DrDoS_NTP.csv              # Known attack - Distributed Reflection DoS NTP
│   │   ├── DrDoS_DNS.csv              # Unknown/drift attack
│   │   ├── DrDoS_SNMP.csv             # Unknown/drift attack
│   │   ├── DrDoS_MSSQL.csv            # Unknown/drift attack
│   │   ├── DrDoS_NetBIOS.csv          # Unknown/drift attack
│   │   ├── DrDoS_SSDP.csv             # Unknown/drift attack
│   │   ├── DrDoS_LDAP.csv             # Unknown/drift attack
│   │   └── TFTP.csv                   # Unknown/drift attack
│   │
│   └── processed/                     # Generated model artifacts (NOT tracked in git)
│       ├── combined_train.csv         # Merged + cleaned training data
│       ├── processed_train.pkl        # Preprocessed train/test split (X_train, X_test, y_train, y_test)
│       ├── scaler.pkl                 # StandardScaler for feature normalization
│       ├── label_encoder.pkl          # LabelEncoder for attack class names
│       ├── feature_names.pkl          # List of retained feature names after selection
│       ├── mlp_weights.npz            # MLP model weights (numpy format)
│       ├── mlp_architecture.json      # MLP architecture metadata
│       ├── training_metrics.json      # Training evaluation metrics
│       ├── model_info.json            # Model metadata (type, features, classes)
│       ├── drift_history.jsonl        # Runtime drift detection log
│       ├── unknown_attack_evaluation.json   # MLP eval on unknown attacks
│       └── arf_drift_evaluation.json  # ARF + ADWIN drift detection evaluation
│
├── src/
│   ├── __init__.py                    # Makes src a Python package
│   ├── config.py                      # CENTRAL CONFIGURATION (paths, features, hyperparameters)
│   ├── run_pipeline.py                # ORCHESTRATOR - runs full training pipeline
│   │
│   ├── training/
│   │   ├── __init__.py
│   │   ├── combine_and_clean.py       # STEP 1: Merges CSVs, cleans data, samples to target rows
│   │   ├── preprocess.py              # STEP 2: Feature selection, scaling, train/test split
│   │   └── train_model.py             # STEP 3: Trains MLP, evaluates, saves artifacts
│   │
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── realtime_detector.py       # HTTP API server (MLP + ARF), classification logic
│   │   ├── traffic_reporter.py        # Monitors /proc/net/*, sends flows to detector
│   │   └── target_monitor.sh          # Bash script for target-side connection monitoring
│   │
│   └── evaluation/
│       ├── __init__.py
│       ├── evaluate_unknown.py        # Evaluates MLP confidence on unknown attack types
│       └── arf_drift_detection.py     # Evaluates ARF + ADWIN drift detection capability
│
└── docker/
    ├── docker-compose.yml             # Defines 3 services: detector, nginx, attacker
    ├── Dockerfile.detector            # Python container for realtime_detector.py
    ├── Dockerfile.target              # Nginx + target_monitor.sh container
    ├── Dockerfile.attacker            # Attack tools container (hping3, nmap, iperf3)
    └── nginx.conf                     # Nginx config for target server
```

---

## File-by-File Breakdown

### `src/config.py` (253 lines)
**Purpose:** Central configuration file. All paths, hyperparameters, and feature definitions live here.

**Key exports:**
- `DATA_DIR` - Path to `data/raw/`
- `OUTPUT_DIR` - Path to `data/processed/`
- `INITIAL_TRAIN_FILES` - Dict mapping 4 known attack CSVs to labels
- `DRIFT_FILES` - Dict mapping 7 unknown attack CSVs to labels
- `DROP_COLUMNS` - Columns to remove (Flow ID, IPs, Timestamp, etc.)
- `NUMERIC_FEATURES` - List of 80 numeric network flow features
- `HIGH_SIGNAL_FEATURE_GROUPS` - Features grouped by category (flow_rates, packet_lengths, iat_stats, tcp_flags, bulk_transfer, etc.)
- `MLP_PARAMS` - MLP hyperparameters: hidden layers (256, 128, 64), ReLU, Adam, alpha=0.001, batch_size=256, early_stopping=True
- `CHUNK_SIZE` - 100,000 rows for chunked CSV reading
- `TRAIN_TEST_SPLIT` - 0.8 (80/20 split)
- `RANDOM_STATE` - 42
- `CORRELATION_THRESHOLD` - 0.95 (features above this are removed)
- `VARIANCE_THRESHOLD` - 0.01 (near-zero variance features removed)

---

### `src/run_pipeline.py` (48 lines)
**Purpose:** Orchestrates the 3-step training pipeline.

**Usage:** `python src/run_pipeline.py [target_rows]` (default: 1,500,000)

**Steps:**
1. Runs `training/combine_and_clean.py` with target_rows argument
2. Runs `training/preprocess.py`
3. Runs `training/train_model.py`

Exits on any step failure.

---

### `src/training/combine_and_clean.py` (140 lines)
**Purpose:** Loads, cleans, and merges CSV datasets into a single training file.

**Process:**
1. Scans all CSV files in `INITIAL_TRAIN_FILES` to count rows
2. Computes proportional sample allocation to reach `target_total` rows
3. For each file: reads in chunks (CHUNK_SIZE), cleans column names, drops unwanted columns, replaces inf with NaN, coerces to numeric, assigns label
4. Concatenates all data, saves to `data/processed/combined_train.csv`

**Key functions:**
- `compute_sample_allocation()` - Proportional sampling across files
- `process_file()` - Chunked reading + cleaning per file
- `clean_column_names()` - Strips whitespace from column names
- `basic_cleaning()` - Handles inf/-inf, coerces to numeric
- `drop_unwanted_columns()` - Removes DROP_COLUMNS

---

### `src/training/preprocess.py` (175 lines)
**Purpose:** Feature selection, scaling, and train/test split.

**Process:**
1. Loads `combined_train.csv`
2. Fills missing values with median per column
3. Drops categorical columns
4. Applies VarianceThreshold (removes near-zero variance features)
5. Removes highly correlated features (correlation > 0.95)
6. Encodes labels with LabelEncoder
7. Splits 80/20 train/test with stratification
8. Applies StandardScaler
9. Saves: `processed_train.pkl`, `scaler.pkl`, `label_encoder.pkl`, `feature_names.pkl`

---

### `src/training/train_model.py` (250 lines)
**Purpose:** Trains MLP classifier, evaluates, and saves model artifacts.

**Process:**
1. Loads preprocessed data, scaler, label encoder, feature names
2. Optionally balances classes (BALANCE_CLASSES = False by default)
3. Trains MLPClassifier with params from config.py
4. Evaluates: accuracy, precision, recall, F1, ROC AUC, confusion matrix, classification report
5. Saves artifacts:
   - `mlp_weights.npz` - Model weights and biases
   - `mlp_architecture.json` - Architecture metadata
   - `training_metrics.json` - Full evaluation metrics
   - `model_info.json` - Model type, features, classes info

**MLP Architecture:** Input -> 256 -> 128 -> 64 -> 4 outputs (DrDoS_NTP, DrDoS_UDP, Syn, UDPLag)

---

### `src/detection/realtime_detector.py` (495 lines)
**Purpose:** HTTP API server that performs real-time classification using MLP + ARF hybrid.

**Key class: `ModelManager`**
- `load_mlp()` - Loads MLP weights from .npz file, scaler, label encoder, feature names
- `mlp_predict_proba()` - Manual forward pass through MLP (avoids sklearn dependency issues)
- `mlp_predict()` - Returns predicted class label
- `init_arf()` - Initializes AdaptiveRandomForest with 10 trees, ADWIN drift detector (delta=0.01), warning detector (delta=0.05)
- `prepare_features()` - Transforms raw dict into model-ready features
- `classify()` - **Core logic:**
  - If MLP confidence >= 0.7: use MLP prediction, check ARF for drift detection
  - If MLP confidence < 0.7: use ARF prediction, ARF learns from the sample
  - Generates alerts when drift detected or prediction is UNKNOWN

**HTTP Endpoints (port 8080):**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check with uptime |
| `/predict` | GET/POST | Classify a network flow (GET: query param `flow=`, POST: JSON body) |
| `/stats` | GET | Model usage statistics (mlp_count, arf_count, drifts, alerts) |
| `/alerts` | GET | Recent alerts (last 50, optional `alerts_only` filter) |
| `/alerts/stream` | GET | Live SSE (Server-Sent Events) alert feed |
| `/drift` | GET | Drift detection history |
| `/retrain` | POST | Retrain ARF with new labeled samples (JSON: `{"samples": [...]}`) |

**Startup sequence:**
1. Load MLP model and artifacts
2. Initialize ARF
3. Pre-train ARF on known attack data (20,000 samples per class)
4. Start ThreadingHTTPServer on port 8080

---

### `src/detection/traffic_reporter.py` (179 lines)
**Purpose:** Monitors live network connections via `/proc/net/tcp` and `/proc/net/udp`, builds feature vectors, and sends them to the detector API.

**Process:**
1. Parses `/proc/net/tcp` - extracts remote IP, port, connection state (SYN_SENT, ESTABLISHED, TIME_WAIT, etc.)
2. Parses `/proc/net/udp` - extracts remote IP, port
3. Groups connections by (remote_ip, remote_port, protocol)
4. Builds approximate feature vectors based on connection patterns (syn_ratio, established ratio, etc.)
5. Sends features to detector at `http://nids-detector:8080/predict`
6. Prints alerts for suspicious traffic

**Runs in attacker container**, polls every 1 second, minimum 3 connections to report.

---

### `src/detection/target_monitor.sh` (75 lines)
**Purpose:** Bash script running on the target (nginx) container. Monitors connections and sends pre-built attack signatures to the detector.

**Process:**
1. Reads `/proc/net/tcp` and `/proc/net/udp` for connection counts and states
2. Checks nginx access log rate
3. Checks network interface packet rates (`/sys/class/net/eth0/statistics/`)
4. Rule-based attack detection:
   - SYN flood: syn_recv > 2 or rx packets/s > 500
   - HTTP flood: log_rate > 10 or established > 3 or time_wait > 5
   - UDP flood: total_udp > 5
5. Sends hardcoded JSON payloads to detector for matching attack types

Runs every 2 seconds in background alongside nginx.

---

### `src/evaluation/evaluate_unknown.py` (183 lines)
**Purpose:** Evaluates MLP's confidence and accuracy on unknown attack types (the 7 DRIFT_FILES).

**Process:**
1. Loads trained MLP, scaler, label encoder, feature names
2. For each unknown attack CSV:
   - Loads and cleans data (up to 100,000 samples)
   - Runs through MLP
   - Measures confidence distribution (low <0.5, medium 0.5-0.8, high >=0.8)
   - Records what classes the MLP predicts these unknown attacks as
3. Saves results to `data/processed/unknown_attack_evaluation.json`

**Key insight:** Unknown attacks should produce low MLP confidence, triggering ARF fallback.

---

### `src/evaluation/arf_drift_detection.py` (225 lines)
**Purpose:** Evaluates ARF + ADWIN's ability to detect and adapt to concept drift.

**Process:**
1. Loads initial training data (50,000 samples per known class)
2. Pre-trains ARF on known attacks
3. Streams unknown attack data (30,000 samples per drift class) through ARF one-by-one
4. For each unknown attack type, measures:
   - Accuracy over the stream
   - Number of drift detections (ADWIN)
   - Number of warning detections
   - Prediction distribution (what ARF classifies them as)
5. Saves results to `data/processed/arf_drift_evaluation.json`

---

## Docker Setup

### Services (docker-compose.yml)

| Service | Container Name | Image | Ports | Description |
|---------|---------------|-------|-------|-------------|
| detector | nids-detector | python:3.12-slim | 8080:80 | MLP + ARF detection server |
| nginx | target-server | nginx:alpine | 8081:80 | Target web server + target_monitor.sh |
| attacker | attacker-shell | python:3.12-slim | none | Attack tools (hping3, nmap, iperf3) + traffic_reporter.py |

All services on `nids-network` bridge network.

### Dockerfile.detector
- Python 3.12 slim base
- Installs requirements.txt dependencies
- Runs `realtime_detector.py` on port 8080
- Mounts data/raw (read-only), data/processed, and source files

### Dockerfile.target
- Nginx Alpine base with bash and curl
- Runs `target_monitor.sh` in background + nginx in foreground

### Dockerfile.attacker
- Python 3.12 slim with attack tools: hping3, nmap, iperf3, iputils-ping, curl
- Python packages: requests, scapy
- Default command: `tail -f /dev/null` (interactive shell)
- Capabilities: NET_ADMIN, NET_RAW (needed for raw packet crafting)

---

## Key Configuration Values

| Parameter | Value | Location |
|-----------|-------|----------|
| MLP hidden layers | (256, 128, 64) | config.py |
| MLP activation | relu | config.py |
| MLP solver | adam | config.py |
| MLP alpha (L2 reg) | 0.001 | config.py |
| MLP batch size | 256 | config.py |
| MLP confidence threshold | 0.7 | realtime_detector.py |
| ARF trees | 10 | realtime_detector.py |
| ADWIN drift delta | 0.01 | realtime_detector.py |
| ADWIN warning delta | 0.05 | realtime_detector.py |
| ARF pretrain samples/class | 20,000 | realtime_detector.py |
| Training target rows | 1,500,000 | run_pipeline.py default |
| Train/test split | 80/20 | config.py |
| Correlation threshold | 0.95 | config.py |
| Variance threshold | 0.01 | config.py |
| CSV chunk size | 100,000 | config.py |

---

## Attack Types

### Known Attacks (Training - 4 classes)
1. **Syn** - SYN Flood attack
2. **UDPLag** - UDP Lag attack
3. **DrDoS_UDP** - Distributed Reflection DoS via UDP
4. **DrDoS_NTP** - Distributed Reflection DoS via NTP

### Unknown/Drift Attacks (Testing - 7 classes)
1. **DrDoS_DNS** - Distributed Reflection DoS via DNS
2. **DrDoS_SNMP** - Distributed Reflection DoS via SNMP
3. **DrDoS_MSSQL** - Distributed Reflection DoS via MSSQL
4. **DrDoS_NetBIOS** - Distributed Reflection DoS via NetBIOS
5. **DrDoS_SSDP** - Distributed Reflection DoS via SSDP
6. **DrDoS_LDAP** - Distributed Reflection DoS via LDAP
7. **TFTP** - TFTP-based attack

---

## Features (80 numeric features after cleaning)

Grouped by category in config.py `HIGH_SIGNAL_FEATURE_GROUPS`:
- **flow_rates** (4): Flow Bytes/s, Flow Packets/s, Fwd/Bwd Packets/s
- **packet_lengths** (15): Max/Min/Mean/Std for fwd/bwd packets, average sizes
- **iat_stats** (15): Inter-Arrival Time statistics (Mean/Std/Max/Min for flow/fwd/bwd)
- **tcp_flags** (12): FIN, SYN, RST, PSH, ACK, URG, CWE, ECE flag counts
- **bulk_transfer** (6): Average bytes/packets/rate for bulk transfers
- **flow_timing** (5): Duration, total packets, total lengths
- **subflow** (4): Subflow fwd/bwd packets and bytes
- **active_idle** (8): Active/Idle Mean/Std/Max/Min
- **network** (5): Source/Dest Port, Protocol, Inbound, Down/Up Ratio
- **window_segment** (6): Init window bytes, segment sizes, header lengths

Dropped columns: Unnamed: 0, Flow ID, Source IP, Destination IP, Timestamp, SimillarHTTP, Fwd Header Length.1

---

## Dependencies

```
numpy>=2.3.4
river==0.24.2          # Online ML (ARF, ADWIN)
pandas==2.2.3
scikit-learn==1.5.2    # MLP, scaler, label encoder, metrics
```

---

## Quick Commands

### Training
```bash
python3 src/run_pipeline.py 1500000    # Full pipeline (default 1.5M rows)
```

### Detection
```bash
python3 src/detection/realtime_detector.py   # Direct execution
docker compose up --build                     # Full Docker deployment
```

### Evaluation
```bash
python3 src/evaluation/evaluate_unknown.py      # MLP on unknown attacks
python3 src/evaluation/arf_drift_detection.py   # ARF + ADWIN drift detection
```

### API Usage
```bash
# Health check
curl http://localhost:8080/health

# Predict (POST with JSON body)
curl -X POST http://localhost:8080/predict \
  -H "Content-Type: application/json" \
  -d '{"Source Port": 53058, "Destination Port": 80, "Protocol": 6, ...}'

# Predict (GET with query param)
curl "http://localhost:8080/predict?flow=$(echo '{"Source Port": 53058, ...}' | jq -cR .)"

# Stats
curl http://localhost:8080/stats

# Recent alerts
curl "http://localhost:8080/alerts?limit=50"

# Live alert stream (SSE)
curl http://localhost:8080/alerts/stream

# Drift history
curl http://localhost:8080/drift

# Retrain ARF
curl -X POST http://localhost:8080/retrain \
  -H "Content-Type: application/json" \
  -d '{"samples": [{"feature1": val, ..., "label": "DrDoS_DNS"}]}'
```

---

## Data Flow Summary

```
CSV files (data/raw/)
    │
    ▼ combine_and_clean.py
combined_train.csv (data/processed/)
    │
    ▼ preprocess.py
processed_train.pkl + scaler.pkl + label_encoder.pkl + feature_names.pkl
    │
    ▼ train_model.py
mlp_weights.npz + training_metrics.json + model_info.json
    │
    ▼ realtime_detector.py (loads all artifacts)
HTTP API on :8080
    │
    ├── traffic_reporter.py → monitors /proc/net/* → sends to /predict
    ├── target_monitor.sh → monitors connections → sends to /predict
    └── external clients → send flow JSON → receive prediction
```

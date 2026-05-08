# Network Intrusion Detection System (NIDS)

A real-time Network Intrusion Detection System that uses machine learning to detect and adapt to network attacks. Implements a hybrid approach combining MLP neural networks with Adaptive Random Forest (ARF) and ADWIN drift detection.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Attacker      │────▶│   Target (Nginx) │────▶│   Detector     │
│   (hping3,      │     │   Port 80        │     │   Port 8080    │
│    nmap, iperf3)│     └──────────────────┘     │   MLP + ARF     │
└─────────────────┘                               └─────────────────┘
        │                                                   ▲
        └───────────────────────────────────────────────────┘
                           traffic_reporter.py queries /predict
```

### Docker Services

| Service | Description | Port |
|---------|-------------|------|
| **detector** | HTTP API with MLP + ARF models | 8080 |
| **nginx** | Target web server under protection | 80 |
| **attacker** | Simulated attack environment | - |

## Features

- **64 network flow features** - Packet lengths, flow rates, IAT stats, TCP flags, bulk transfer metrics
- **Hybrid detection** - MLP (high confidence) + ARF (fallback + drift detection)
- **Concept drift adaptation** - ADWIN drift detector with Automatic Retraining
- **Real-time monitoring** - SSE alert stream, REST API, connection tracking via `/proc/net/*`
- **Multi-class classification** - Detects 11 attack types

## Quick Start

### Prerequisites

- Python 3.9+
- Docker & Docker Compose (for full system)
- CSV datasets in project directory

### Run Training Pipeline

```bash
cd minor/01-12
python3 src/run_pipeline.py 1500000
```

This executes:
1. `src/training/combine_and_clean.py` - Merges 4 initial training CSV files
2. `src/training/preprocess.py` - Feature selection, scaling, train/test split
3. `src/training/train_model.py` - Trains MLP (256-128-64 architecture)

### Launch Detection System

**Option 1: Direct execution (testing)**
```bash
python3 realtime_detector.py
```

**Option 2: Docker deployment (full system)**
```bash
docker-compose up --build
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/predict` | GET/POST | Classify network flow |
| `/stats` | GET | Model usage statistics |
| `/alerts` | GET | Recent alerts (last 50) |
| `/alerts/stream` | GET | Live SSE alert feed |
| `/drift` | GET | Drift detection history |
| `/retrain` | POST | Retrain ARF with new samples |

### Example Prediction

```bash
curl -X POST http://localhost:8080/predict \
  -H "Content-Type: application/json" \
  -d '{
    "Source Port": 53058,
    "Destination Port": 80,
    "Protocol": 6,
    "Flow Duration": 115799309,
    "Total Fwd Packets": 19,
    ...
  }'
```

### Run Detection Server (Direct)

```bash
python3 src/detection/realtime_detector.py
```

Response:
```json
{
  "prediction": "Syn",
  "confidence": 0.95,
  "model_used": "mlp",
  "drift_detected": false,
  "is_alert": false
}
```

## Dataset

Download the CICDDoS2019 dataset from: https://cicresearch.ca//CICDDoS2019/

### Known Attacks (Training)
- Syn Flood
- UDPLag
- DrDoS_UDP
- DrDoS_NTP

### Unknown Attacks (Drift Detection)
- DrDoS_DNS
- DrDoS_SNMP
- DrDoS_MSSQL
- DrDoS_NetBIOS
- DrDoS_SSDP
- DrDoS_LDAP
- TFTP

### CSV Format

Place dataset files in the project root:
- `Syn.csv`, `UDPLag.csv`, `DrDoS_UDP.csv`, `DrDoS_NTP.csv`
- `DrDoS_DNS.csv`, `DrDoS_SNMP.csv`, `DrDoS_MSSQL.csv`, etc.

## Models

### MLP Classifier
- **Architecture**: 256-128-64 hidden layers
- **Activation**: ReLU
- **Solver**: Adam
- **Confidence threshold**: 0.8 (switches to ARF below this)

### ARF + ADWIN
- **Type**: Adaptive Random Forest with 10 trees
- **Drift detector**: ADWIN (δ=0.01)
- **Warning detector**: ADWIN (δ=0.05)
- **Purpose**: Handles concept drift, adapts to new attack patterns

## Evaluation

### Evaluate on Unknown Attacks
```bash
python3 src/evaluation/evaluate_unknown.py
```
Tests MLP confidence and accuracy on unseen attack types.

### ARF Drift Detection Evaluation
```bash
python3 src/evaluation/arf_drift_detection.py
```
Streams unknown attack data through ARF and measures drift adaptation.

## Configuration

Edit `config.py` to modify:
- `MLP_PARAMS` - Neural network hyperparameters
- `INITIAL_TRAIN_FILES` / `DRIFT_FILES` - Dataset mapping
- `NUMERIC_FEATURES` - Feature list (64 features)
- `MLP_CONFIDENCE_THRESHOLD` - Threshold in `realtime_detector.py` (default: 0.8)

## Project Structure

```
├── src/
│   ├── config.py                 # Configuration & hyperparameters
│   ├── run_pipeline.py           # Orchestrates training pipeline
│   ├── training/
│   │   ├── combine_and_clean.py  # Merges & cleans CSV datasets
│   │   ├── preprocess.py         # Feature selection & scaling
│   │   └── train_model.py        # MLP training & evaluation
│   ├── detection/
│   │   ├── realtime_detector.py  # HTTP API server (MLP + ARF)
│   │   ├── traffic_reporter.py   # Monitors /proc/net/*, reports to detector
│   │   └── target_monitor.sh     # Target-side connection monitoring
│   └── evaluation/
│       ├── arf_drift_detection.py # ARF + ADWIN evaluation
│       └── evaluate_unknown.py   # MLP evaluation on unknown attacks
├── docker/
│   ├── docker-compose.yml       # Docker services orchestration
│   ├── Dockerfile.detector      # Detector container
│   ├── Dockerfile.target        # Nginx target container
│   ├── Dockerfile.attacker      # Attacker tools container
│   └── nginx.conf               # Nginx configuration
├── data/
│   ├── raw/                      # Original CSV datasets (not tracked)
│   └── processed/                # Generated artifacts (not tracked)
│       ├── mlp_model.pkl         # Trained MLP
│       ├── mlp_weights.npz       # Model weights
│       ├── scaler.pkl            # Feature scaler
│       ├── label_encoder.pkl     # Label encoder
│       ├── feature_names.pkl     # Feature list
│       └── *.json                # Metrics & evaluations
├── requirements.txt              # Python dependencies
├── README.md
└── LICENSE
```

## Dependencies

```
pandas==2.2.3
numpy==1.26.4
scikit-learn==1.5.2
river==0.21.2
```

## How It Works

1. **Training Phase** - MLP learns from 4 known attack types
2. **Detection Phase** - Incoming flows classified by MLP (if confidence ≥ 0.8) or ARF
3. **Drift Monitoring** - ARF compares predictions with MLP, detects concept drift
4. **Adaptation** - When drift detected, ARF continues learning new patterns
5. **Alerting** - Suspicious flows trigger alerts via REST API or SSE stream

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

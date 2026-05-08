"""
Stream actual DrDoS CSV samples to the detector to test drift detection.
Usage (from attacker container):
    python3 scripts/stream_drift_csv.py [attack_type] [n_samples]

Examples:
    python3 scripts/stream_drift_csv.py dns        # 500 DrDoS_DNS samples
    python3 scripts/stream_drift_csv.py snmp 200   # 200 DrDoS_SNMP samples
    python3 scripts/stream_drift_csv.py all 50     # 50 of each type
"""
import requests
import csv
import time
import sys
import os
import json

DETECTOR_URL = "http://nids-detector:8080/predict"
DATA_DIR = "/app/data/raw"

DRIFT_FILES = {
    "dns":     "DrDoS_DNS.csv",
    "snmp":    "DrDoS_SNMP.csv",
    "mssql":   "DrDoS_MSSQL.csv",
    "netbios": "DrDoS_NetBIOS.csv",
    "ssdp":    "DrDoS_SSDP.csv",
    "ldap":    "DrDoS_LDAP.csv",
    "tftp":    "TFTP.csv",
}

DROP_COLS = {
    "Unnamed: 0", "Flow ID", "Source IP", "Destination IP",
    "Timestamp", "SimillarHTTP", "Fwd Header Length.1", "Label"
}


def clean_row(row):
    d = {}
    for k, v in row.items():
        k = k.strip()
        if k in DROP_COLS:
            continue
        try:
            d[k] = float(v)
        except (ValueError, TypeError):
            d[k] = 0.0
    return d


def stream(name, filepath, n=500, delay=0.02):
    print(f"\nStreaming {n} samples from {name} ({filepath})...\n")

    with open(filepath) as f:
        reader = csv.DictReader(f)
        sent = 0
        drift_count = 0
        arf_count = 0
        mlp_count = 0
        predictions = {}

        for row in reader:
            if sent >= n:
                break
            flow = clean_row(row)
            try:
                resp = requests.post(DETECTOR_URL, json=flow, timeout=5)
                d = resp.json()
                pred = d.get("prediction", "?")
                conf = d.get("confidence", 0)
                model = d.get("model_used", "?")
                drift = d.get("drift_detected", False)

                predictions[pred] = predictions.get(pred, 0) + 1
                if model == "arf":
                    arf_count += 1
                else:
                    mlp_count += 1
                if drift:
                    drift_count += 1

                print(f"  [{sent+1:4}] pred={pred:20} conf={conf:.3f} "
                      f"model={model}{'  *** DRIFT ***' if drift else ''}")

                sent += 1
                time.sleep(delay)
            except Exception as e:
                print(f"  [{sent+1}] Error: {e}")
                sent += 1

    print(f"\n{'='*60}")
    print(f"Results for {name}:")
    print(f"  Samples:     {sent}")
    print(f"  MLP used:    {mlp_count}")
    print(f"  ARF used:    {arf_count}")
    print(f"  Drift events:{drift_count}")
    print(f"  Predictions: {json.dumps(predictions, indent=2)}")
    print(f"{'='*60}\n")


def probe_all(n=50):
    print(f"\n{'='*60}")
    print(f"Probing all 7 drift types ({n} samples each)")
    print(f"{'='*60}\n")
    for name, fn in DRIFT_FILES.items():
        filepath = os.path.join(DATA_DIR, fn)
        if not os.path.exists(filepath):
            print(f"  Skipping {name}: {filepath} not found")
            continue
        stream(name, filepath, n=n, delay=0.01)


if __name__ == "__main__":
    args = sys.argv[1:]
    profile = args[0] if args else "all"
    n = int(args[1]) if len(args) > 1 else 500

    if profile == "all":
        probe_all(n=min(n, 100))
    elif profile in DRIFT_FILES:
        filepath = os.path.join(DATA_DIR, DRIFT_FILES[profile])
        if os.path.exists(filepath):
            stream(profile, filepath, n=n)
        else:
            print(f"File not found: {filepath}")
    else:
        print(f"Unknown profile '{profile}'. Choose: {list(DRIFT_FILES.keys()) + ['all']}")

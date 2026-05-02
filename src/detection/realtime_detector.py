import os
import sys
import pickle
import json
import time
import logging
import threading
from collections import deque, defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import pandas as pd
import numpy as np
from sklearn.neural_network import MLPClassifier
from river import forest
from river import drift
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    OUTPUT_DIR,
    SCALER_PATH,
    LABEL_ENCODER_PATH,
    FEATURE_NAMES_PATH,
    MODEL_PATH,
    DROP_COLUMNS,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MLP_CONFIDENCE_THRESHOLD = 0.8
ARF_PRETRAIN_SAMPLES_PER_CLASS = 20000
PORT = 8080
DRIFT_HISTORY_PATH = os.path.join(OUTPUT_DIR, "drift_history.jsonl")


class ModelManager:
    def __init__(self):
        self.mlp = None
        self.scaler = None
        self.le = None
        self.feature_names = None
        self.arf = None
        self.arf_label_map = None
        self.arf_reverse_map = None
        self.drift_buffer = deque(maxlen=10000)
        self.drift_log = []
        self.initial_drifts = 0
        self.total_predictions = 0
        self.mlp_count = 0
        self.arf_count = 0
        self.unknown_count = 0
        self.drift_count = 0
        self.alerts = deque(maxlen=1000)
        self.alert_callbacks = []

    def load_mlp(self):
        logger.info("Loading MLP model and artifacts...")

        weights_path = os.path.join(OUTPUT_DIR, "mlp_weights.npz")
        arch_path = os.path.join(OUTPUT_DIR, "mlp_architecture.json")
        with open(arch_path, "r") as f:
            arch = json.load(f)

        w = np.load(weights_path)
        self.mlp_coefs = [w["coefs_0"], w["coefs_1"], w["coefs_2"], w["coefs_3"]]
        self.mlp_intercepts = [w["intercepts_0"], w["intercepts_1"], w["intercepts_2"], w["intercepts_3"]]
        self.mlp_classes = np.arange(arch["n_outputs"])

        with open(SCALER_PATH, "rb") as f:
            self.scaler = pickle.load(f)
        self.scaler_mean = self.scaler.mean_
        self.scaler_std = self.scaler.scale_
        with open(LABEL_ENCODER_PATH, "rb") as f:
            self.le = pickle.load(f)
        with open(FEATURE_NAMES_PATH, "rb") as f:
            self.feature_names = pickle.load(f)
        logger.info(f"MLP loaded: {len(self.feature_names)} features, {len(self.le.classes_)} classes")

    def mlp_predict_proba(self, X_scaled):
        x = X_scaled
        n_layers = len(self.mlp_coefs)
        for i, (coef, intercept) in enumerate(zip(self.mlp_coefs, self.mlp_intercepts)):
            x = x @ coef + intercept
            if i < n_layers - 1:
                x = np.maximum(x, 0)
            else:
                exp_x = np.exp(x - np.max(x, axis=1, keepdims=True))
                x = exp_x / exp_x.sum(axis=1, keepdims=True)
        return x

    def mlp_predict(self, X_scaled):
        proba = self.mlp_predict_proba(X_scaled)
        return self.mlp_classes[np.argmax(proba, axis=1)]

    def init_arf(self):
        self.arf = forest.ARFClassifier(
            seed=42,
            n_models=10,
            drift_detector=drift.ADWIN(delta=0.01),
            warning_detector=drift.ADWIN(delta=0.05),
        )
        known_classes = ["DrDoS_NTP", "DrDoS_UDP", "Syn", "UDPLag"]
        drift_classes = ["DrDoS_DNS", "DrDoS_SNMP", "DrDoS_MSSQL", "DrDoS_NetBIOS", "DrDoS_SSDP", "DrDoS_LDAP", "TFTP"]
        all_classes = known_classes + drift_classes
        self.arf_label_map = {name: i for i, name in enumerate(all_classes)}
        self.arf_reverse_map = {i: name for name, i in self.arf_label_map.items()}
        self.initial_drifts = self.arf.n_drifts_detected()
        logger.info(f"ARF initialized with {len(all_classes)} classes")

    def prepare_features(self, raw_data: dict) -> dict:
        df = pd.DataFrame([raw_data])
        df.columns = df.columns.str.strip()
        for c in DROP_COLUMNS:
            if c in df.columns:
                df = df.drop(columns=[c])
        if "Label" in df.columns:
            df = df.drop(columns=["Label"])
        df = df.replace([np.inf, -np.inf], np.nan)
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].apply(pd.to_numeric, errors="coerce")
        df = df.fillna(0)
        for f in self.feature_names:
            if f not in df.columns:
                df[f] = 0
        df = df[self.feature_names]
        return {f: float(df[f].iloc[0]) for f in self.feature_names}

    def prepare_arf_features(self, raw_data: dict) -> dict:
        df = pd.DataFrame([raw_data])
        df.columns = df.columns.str.strip()
        for c in DROP_COLUMNS:
            if c in df.columns:
                df = df.drop(columns=[c])
        if "Label" in df.columns:
            df = df.drop(columns=["Label"])
        df = df.replace([np.inf, -np.inf], np.nan)
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].apply(pd.to_numeric, errors="coerce")
        df = df.fillna(0)
        arf_features = list(self.arf_label_map.keys())
        arf_features.remove("Label") if "Label" in arf_features else None
        raw_feature_names = [f for f in df.columns if f != "Label"]
        return {f: float(df[f].iloc[0]) for f in raw_feature_names}

    def classify(self, raw_data: dict):
        self.total_predictions += 1

        try:
            features = self.prepare_features(raw_data)
        except Exception as e:
            return {"error": f"Feature extraction failed: {str(e)}", "model_used": "none"}

        try:
            X_scaled = self.scaler.transform([list(features.values())])
            mlp_probs = self.mlp_predict_proba(X_scaled)[0]
            mlp_pred_encoded = self.mlp_predict(X_scaled)[0]
            mlp_confidence = float(max(mlp_probs))
            mlp_label = self.le.inverse_transform([mlp_pred_encoded])[0]
        except Exception as e:
            return {"error": f"MLP prediction failed: {str(e)}", "model_used": "none"}

        if mlp_confidence >= MLP_CONFIDENCE_THRESHOLD:
            self.mlp_count += 1
            arf_features = self.prepare_arf_features(raw_data)
            arf_pred = self.arf.predict_one(arf_features)
            arf_label = self.arf_reverse_map.get(arf_pred, "Unknown")
            mlp_to_arf_map = {"DrDoS_NTP": 0, "DrDoS_UDP": 1, "Syn": 2, "UDPLag": 3}
            arf_mlp_equiv = mlp_to_arf_map.get(mlp_label, -1)
            drift_detected = False
            if arf_pred != arf_mlp_equiv:
                current_drifts = self.arf.n_drifts_detected() - self.initial_drifts
                if current_drifts > 0:
                    drift_detected = True
                    self.drift_count += 1
                    self.initial_drifts = self.arf.n_drifts_detected()
                    entry = {
                        "timestamp": time.time(),
                        "mlp_prediction": mlp_label,
                        "arf_prediction": arf_label,
                        "confidence": mlp_confidence,
                        "total_drifts": current_drifts,
                    }
                    self.drift_log.append(entry)
                    with open(DRIFT_HISTORY_PATH, "a") as f:
                        f.write(json.dumps(entry) + "\n")
            self.arf.learn_one(arf_features, arf_mlp_equiv if arf_mlp_equiv >= 0 else arf_pred)
            result = {
                "prediction": mlp_label,
                "confidence": round(mlp_confidence, 4),
                "model_used": "mlp",
                "drift_detected": drift_detected,
                "arf_prediction": arf_label,
            }
        else:
            self.arf_count += 1

            try:
                arf_features = self.prepare_arf_features(raw_data)
                arf_pred = self.arf.predict_one(arf_features)
                arf_label = self.arf_reverse_map.get(arf_pred, "Unknown")

                arf_probs = self.arf.predict_proba_one(arf_features)
                arf_confidence = float(arf_probs.get(arf_pred, 0))

                self.arf.learn_one(arf_features, arf_pred)

                current_drifts = self.arf.n_drifts_detected() - self.initial_drifts
                drift_detected = current_drifts > 0

                if drift_detected:
                    self.drift_count += 1
                    self.initial_drifts = self.arf.n_drifts_detected()
                    entry = {
                        "timestamp": time.time(),
                        "prediction": arf_label,
                        "confidence": arf_confidence,
                        "total_drifts": current_drifts,
                    }
                    self.drift_log.append(entry)
                    with open(DRIFT_HISTORY_PATH, "a") as f:
                        f.write(json.dumps(entry) + "\n")

                result = {
                    "prediction": arf_label,
                    "confidence": round(arf_confidence, 4),
                    "model_used": "arf",
                    "mlp_confidence": round(mlp_confidence, 4),
                    "mlp_prediction": mlp_label,
                    "drift_detected": drift_detected,
                    "total_drifts_detected": current_drifts,
                }

            except Exception as e:
                self.unknown_count += 1
                result = {
                    "prediction": "UNKNOWN",
                    "confidence": 0.0,
                    "model_used": "fallback",
                    "mlp_prediction": mlp_label,
                    "mlp_confidence": round(mlp_confidence, 4),
                    "error": str(e),
                }

        result["timestamp"] = time.time()
        is_alert = result.get("drift_detected") or result.get("prediction") in ["UNKNOWN"] or \
                   (result["model_used"] == "mlp" and result.get("arf_prediction") != result["prediction"])
        result["is_alert"] = is_alert
        if is_alert:
            result["severity"] = "HIGH" if result.get("prediction") == "UNKNOWN" or result.get("drift_detected") else "MEDIUM"
        self.add_alert(result)
        return result

    def add_alert(self, alert):
        self.alerts.append(alert)
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except:
                pass

    def get_stats(self):
        return {
            "total_predictions": self.total_predictions,
            "mlp_predictions": self.mlp_count,
            "arf_predictions": self.arf_count,
            "unknown_predictions": self.unknown_count,
            "drift_detections": self.drift_count,
            "arf_total_drifts": self.arf.n_drifts_detected() - self.initial_drifts,
            "mlp_confidence_threshold": MLP_CONFIDENCE_THRESHOLD,
            "total_alerts": len([a for a in self.alerts if a.get("is_alert")]),
        }


models = ModelManager()


class DetectorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self.send_json(200, {"status": "ok", "uptime": time.time() - start_time})

        elif parsed.path == "/predict":
            params = parse_qs(parsed.query)
            if "flow" not in params:
                self.send_json(400, {"error": "Missing flow parameter"})
                return
            try:
                flow_data = json.loads(params["flow"][0])
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Invalid JSON in flow parameter"})
                return

            result = models.classify(flow_data)
            self.send_json(200, result)

        elif parsed.path == "/stats":
            self.send_json(200, models.get_stats())

        elif parsed.path == "/drift":
            self.send_json(200, {
                "drift_log": models.drift_log[-50:],
                "total_drifts": models.drift_count,
            })

        elif parsed.path == "/alerts":
            params = parse_qs(parsed.query)
            limit = int(params.get("limit", ["50"])[0])
            alerts_only = params.get("alerts_only", ["false"])[0].lower() == "true"
            alerts = list(models.alerts)[-limit:]
            if alerts_only:
                alerts = [a for a in alerts if a.get("is_alert")]
            self.send_json(200, {"alerts": alerts, "total": len(alerts)})

        elif parsed.path == "/alerts/stream":
            self._stream_alerts()

        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/predict":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                flow_data = json.loads(body)
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Invalid JSON"})
                return

            result = models.classify(flow_data)
            self.send_json(200, result)

        elif parsed.path == "/retrain":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Invalid JSON"})
                return

            count = 0
            for sample in data.get("samples", []):
                try:
                    features = models.prepare_arf_features(sample)
                    label = models.arf_label_map.get(sample.get("label"), 0)
                    models.arf.learn_one(features, label)
                    count += 1
                except Exception:
                    pass

            self.send_json(200, {"retrained_samples": count})

        else:
            self.send_json(404, {"error": "Not found"})

    def send_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _stream_alerts(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        queue = deque(maxlen=100)
        def cb(alert):
            queue.append(alert)
        models.alert_callbacks.append(cb)
        try:
            while True:
                while queue:
                    alert = queue.popleft()
                    data = f"data: {json.dumps(alert)}\n\n"
                    try:
                        self.wfile.write(data.encode())
                        self.wfile.flush()
                    except:
                        return
                time.sleep(0.5)
        except:
            pass
        finally:
            if cb in models.alert_callbacks:
                models.alert_callbacks.remove(cb)

    def log_message(self, format, *args):
        logger.debug(f"{self.client_address[0]} - {format % args}")


def pretrain_arf():
    logger.info("Pre-training ARF on known attack data...")
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import INITIAL_TRAIN_FILES, CHUNK_SIZE

    csv_dir = os.environ.get("CSV_DIR", "/app/data")

    samples = []
    for filename, label in INITIAL_TRAIN_FILES.items():
        filepath = os.path.join(csv_dir, filename)
        try:
            chunk_iter = pd.read_csv(filepath, chunksize=CHUNK_SIZE, low_memory=False)
            count = 0
            for chunk in chunk_iter:
                chunk.columns = chunk.columns.str.strip()
                for c in DROP_COLUMNS:
                    if c in chunk.columns:
                        chunk = chunk.drop(columns=[c])
                chunk = chunk.replace([np.inf, -np.inf], np.nan)
                numeric_cols = chunk.select_dtypes(include=[np.number]).columns
                chunk[numeric_cols] = chunk[numeric_cols].apply(pd.to_numeric, errors="coerce")
                chunk = chunk.fillna(0)
                for _, row in chunk.iterrows():
                    sample = {f: float(row[f]) for f in chunk.columns if f != "Label"}
                    samples.append((sample, label))
                    count += 1
                    if count >= ARF_PRETRAIN_SAMPLES_PER_CLASS:
                        break
                if count >= ARF_PRETRAIN_SAMPLES_PER_CLASS:
                    break
            logger.info(f"  Loaded {count:,} samples from {filename}")
        except Exception as e:
            logger.warning(f"  Failed to load {filename}: {e}")

    logger.info(f"Training ARF on {len(samples):,} samples...")
    for i, (sample, label) in enumerate(samples):
        y = models.arf_label_map[label]
        models.arf.learn_one(sample, y)
        if (i + 1) % 20000 == 0:
            logger.info(f"  Trained on {i+1:,} samples...")

    models.initial_drifts = models.arf.n_drifts_detected()
    logger.info("ARF pre-training complete.")


if __name__ == "__main__":
    start_time = time.time()

    logger.info("=" * 60)
    logger.info("REAL-TIME NETWORK INTRUSION DETECTION SYSTEM")
    logger.info("=" * 60)

    models.load_mlp()
    models.init_arf()
    pretrain_arf()

    logger.info(f"Starting HTTP server on port {PORT}...")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), DetectorHandler)

    logger.info(f"Server running on http://0.0.0.0:{PORT}")
    logger.info(f"Endpoints:")
    logger.info(f"  GET  /health          - Health check")
    logger.info(f"  POST /predict          - Classify a flow (JSON body)")
    logger.info(f"  GET  /predict?flow=... - Classify a flow (query param)")
    logger.info(f"  GET  /stats            - Model usage statistics")
    logger.info(f"  GET  /alerts           - Recent alerts (last 50)")
    logger.info(f"  GET  /alerts/stream    - Live SSE alert feed")
    logger.info(f"  GET  /drift            - Drift detection history")
    logger.info(f"  POST /retrain          - Retrain ARF with new labeled samples")
    logger.info("=" * 60)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()

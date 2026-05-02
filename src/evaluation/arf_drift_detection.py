import os
import sys
import pickle
import json
import pandas as pd
import numpy as np
from collections import defaultdict
from river import forest
from river import drift
from river import metrics
from river import preprocessing
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    DATA_DIR,
    OUTPUT_DIR,
    DRIFT_FILES,
    INITIAL_TRAIN_FILES,
    CHUNK_SIZE,
    DROP_COLUMNS,
    SCALER_PATH,
    LABEL_ENCODER_PATH,
    FEATURE_NAMES_PATH,
    MODEL_PATH,
)


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = df.columns.str.strip()
    return df


def drop_unwanted_columns(df: pd.DataFrame) -> pd.DataFrame:
    cols_to_drop = [c for c in DROP_COLUMNS if c in df.columns]
    if cols_to_drop:
        df = df.drop(columns=cols_to_drop)
    return df


def basic_cleaning(df: pd.DataFrame) -> pd.DataFrame:
    df = df.replace([np.inf, -np.inf], np.nan)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].apply(pd.to_numeric, errors="coerce")
    return df


def load_data_for_river(filepath, label, feature_names, max_samples=None):
    chunks = []
    total_read = 0
    reader = pd.read_csv(filepath, chunksize=CHUNK_SIZE, low_memory=False)

    for chunk in reader:
        chunk = clean_column_names(chunk)
        chunk = drop_unwanted_columns(chunk)
        chunk = basic_cleaning(chunk)
        chunks.append(chunk)
        total_read += len(chunk)
        if max_samples and total_read >= max_samples:
            break

    df = pd.concat(chunks, ignore_index=True)
    if max_samples and len(df) > max_samples:
        df = df.sample(n=max_samples, random_state=42).reset_index(drop=True)

    X = df.drop(columns=["Label"]) if "Label" in df.columns else df
    X = X.fillna(X.median(numeric_only=True))

    missing_features = set(feature_names) - set(X.columns)
    for f in missing_features:
        X[f] = 0

    X = X[feature_names]
    return X, label


def load_initial_training_data(feature_names, max_samples_per_file=50000):
    samples = []
    labels = []

    for filename, label in INITIAL_TRAIN_FILES.items():
        filepath = os.path.join(DATA_DIR, filename)
        X, lbl = load_data_for_river(filepath, label, feature_names, max_samples_per_file)

        for _, row in X.iterrows():
            sample = {feat: float(row[feat]) for feat in feature_names}
            samples.append(sample)
            labels.append(lbl)

    return samples, labels


def build_river_label_encoder():
    label_map = {
        "DrDoS_NTP": 0,
        "DrDoS_UDP": 1,
        "Syn": 2,
        "UDPLag": 3,
        "DrDoS_DNS": 4,
        "DrDoS_SNMP": 5,
        "DrDoS_MSSQL": 6,
        "DrDoS_NetBIOS": 7,
        "DrDoS_SSDP": 8,
        "DrDoS_LDAP": 9,
        "TFTP": 10,
    }
    reverse_map = {v: k for k, v in label_map.items()}
    return label_map, reverse_map


def main():
    max_initial_per_file = 50000
    max_drift_per_file = 30000

    print("=" * 60)
    print("ARF + ADWIN CONCEPT DRIFT DETECTION")
    print("=" * 60)

    with open(FEATURE_NAMES_PATH, "rb") as f:
        feature_names = pickle.load(f)

    label_map, reverse_map = build_river_label_encoder()

    print(f"\nFeatures: {len(feature_names)}")
    print(f"Known classes: {list(INITIAL_TRAIN_FILES.values())}")
    print(f"Drift classes: {list(DRIFT_FILES.values())}")

    print("\nLoading initial training data...")
    samples, labels = load_initial_training_data(feature_names, max_initial_per_file)
    print(f"Loaded {len(samples):,} samples")

    print("\nInitializing Adaptive Random Forest + ADWIN...")
    model = forest.ARFClassifier(
        seed=42,
        n_models=10,
        drift_detector=drift.ADWIN(delta=0.01),
        warning_detector=drift.ADWIN(delta=0.05),
    )

    print("Pre-training on known attacks...")
    for i, (sample, label) in enumerate(zip(samples, labels)):
        y = label_map[label]
        model.learn_one(sample, y)

        if (i + 1) % 50000 == 0:
            print(f"  Trained on {i+1:,} samples...")

    print(f"Pre-training complete.")

    results = []

    for filename, label in DRIFT_FILES.items():
        filepath = os.path.join(DATA_DIR, filename)
        print(f"\n{'=' * 60}")
        print(f"Streaming: {filename} (unknown attack: {label})")
        print(f"{'=' * 60}")

        X_df, _ = load_data_for_river(filepath, label, feature_names, max_drift_per_file)

        true_label = label_map[label]

        stream_metrics = metrics.Accuracy()
        confusion = metrics.ConfusionMatrix(list(range(11)))

        initial_drifts = model.n_drifts_detected()
        initial_warnings = model.n_warnings_detected()

        for i, (_, sample) in enumerate(X_df.iterrows()):
            x = {feat: float(sample[feat]) for feat in feature_names}

            y_pred = model.predict_one(x)
            stream_metrics.update(y_pred, true_label)
            confusion.update(y_pred, true_label)

            y_prob = model.predict_proba_one(x)
            pred_confidence = y_prob.get(y_pred, 0) if y_prob else 0

            model.learn_one(x, true_label)

        final_accuracy = stream_metrics.get()

        total_drifts = model.n_drifts_detected() - initial_drifts
        total_warnings = model.n_warnings_detected() - initial_warnings

        pred_counts = defaultdict(int)
        for row_label_idx in confusion.classes:
            for pred_label_idx in confusion.classes:
                count = confusion.data.get(row_label_idx, {}).get(pred_label_idx, 0)
                if count > 0:
                    pred_counts[reverse_map.get(pred_label_idx, "Unknown")] += count

        sorted_preds = sorted(pred_counts.items(), key=lambda x: x[1], reverse=True)

        print(f"  Samples processed: {len(X_df):,}")
        print(f"  Accuracy: {final_accuracy:.4f}")
        print(f"  Drift detections: {total_drifts}")
        print(f"  Warning detections: {total_warnings}")
        print(f"  Top predictions: {dict(sorted_preds[:5])}")

        results.append({
            "file": filename,
            "label": label,
            "samples": len(X_df),
            "accuracy": float(final_accuracy),
            "drift_detections": total_drifts,
            "warning_detections": total_warnings,
            "predictions": dict(sorted_preds[:5]),
        })

    results_path = os.path.join(OUTPUT_DIR, "arf_drift_evaluation.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n\nResults saved to: {results_path}")

    print("\n" + "=" * 60)
    print("SUMMARY: ARF + ADWIN Drift Detection")
    print("=" * 60)
    print(f"{'File':<20} {'Samples':>8} {'Accuracy':>9} {'Drifts':>7} {'Top Prediction':>15}")
    print("-" * 65)
    for r in results:
        top_pred = list(r['predictions'].keys())[0] if r['predictions'] else "N/A"
        print(f"{r['label']:<20} {r['samples']:>8,} {r['accuracy']:>9.4f} {r['drift_detections']:>7} {top_pred:>15}")


if __name__ == "__main__":
    main()

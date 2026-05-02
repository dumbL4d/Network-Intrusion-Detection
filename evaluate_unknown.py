import os
import pickle
import json
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)
from config import (
    DATA_DIR,
    OUTPUT_DIR,
    DRIFT_FILES,
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


def load_model_artifacts():
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    with open(LABEL_ENCODER_PATH, "rb") as f:
        le = pickle.load(f)
    with open(FEATURE_NAMES_PATH, "rb") as f:
        feature_names = pickle.load(f)
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    return scaler, le, feature_names, model


def evaluate_confidence(model, X, y_true, le, label_name):
    y_pred = model.predict(X)
    y_prob = model.predict_proba(X)
    max_prob = np.max(y_prob, axis=1)

    accuracy = accuracy_score(y_true, y_pred)

    n_low_confidence = np.sum(max_prob < 0.5)
    n_medium_confidence = np.sum((max_prob >= 0.5) & (max_prob < 0.8))
    n_high_confidence = np.sum(max_prob >= 0.8)

    low_conf_mask = max_prob < 0.5
    low_conf_acc = accuracy_score(y_true[low_conf_mask], y_pred[low_conf_mask]) if low_conf_mask.sum() > 0 else 0

    return {
        "label": label_name,
        "samples": len(y_true),
        "accuracy": float(accuracy),
        "predicted_classes": dict(zip(*np.unique(y_pred, return_counts=True))),
        "true_class_distribution": dict(zip(*np.unique(y_true, return_counts=True))),
        "confidence": {
            "low (<0.5)": int(n_low_confidence),
            "low_pct": float(n_low_confidence / len(y_true) * 100),
            "medium (0.5-0.8)": int(n_medium_confidence),
            "medium_pct": float(n_medium_confidence / len(y_true) * 100),
            "high (>=0.8)": int(n_high_confidence),
            "high_pct": float(n_high_confidence / len(y_true) * 100),
        },
        "low_confidence_accuracy": float(low_conf_acc),
    }


def evaluate_file(filepath, label, scaler, le, feature_names, model, max_samples=None):
    print(f"\n{'=' * 60}")
    print(f"File: {os.path.basename(filepath)}")
    print(f"{'=' * 60}")

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

    y_raw = df["Label"] if "Label" in df.columns else pd.Series([label] * len(df))
    X = df.drop(columns=["Label"]) if "Label" in df.columns else df

    X = X.fillna(X.median(numeric_only=True))

    missing_features = set(feature_names) - set(X.columns)
    for f in missing_features:
        X[f] = 0

    X = X[feature_names]

    X_scaled = scaler.transform(X)
    y_encoded = le.transform(y_raw) if label in le.classes_ else np.zeros(len(y_raw), dtype=int)

    return evaluate_confidence(model, X_scaled, y_encoded, le, label), df


def main():
    max_samples = 100000

    print("=" * 60)
    print("EVALUATING MLP ON UNKNOWN ATTACKS (DRIFT FILES)")
    print("=" * 60)
    print(f"\nKnown classes: {['DrDoS_NTP', 'DrDoS_UDP', 'Syn', 'UDPLag']}")
    print(f"Unknown files: {list(DRIFT_FILES.keys())}")
    print(f"Max samples per file: {max_samples:,}")

    scaler, le, feature_names, model = load_model_artifacts()

    all_results = []

    for filename, label in DRIFT_FILES.items():
        filepath = os.path.join(DATA_DIR, filename)
        result, df = evaluate_file(filepath, label, scaler, le, feature_names, model, max_samples)
        all_results.append(result)

        print(f"\n  Samples: {result['samples']:,}")
        print(f"  Accuracy: {result['accuracy']:.4f}")
        print(f"  Confidence: Low={result['confidence']['low_pct']:.1f}%  Medium={result['confidence']['medium_pct']:.1f}%  High={result['confidence']['high_pct']:.1f}%")
        print(f"  Low-conf accuracy: {result['low_confidence_accuracy']:.4f}")

        pred_classes = result['predicted_classes']
        pred_names = {le.inverse_transform([int(k)])[0]: int(v) for k, v in pred_classes.items()}
        print(f"  Predicted as: {pred_names}")

    results_path = os.path.join(OUTPUT_DIR, "unknown_attack_evaluation.json")
    serializable_results = []
    for r in all_results:
        sr = dict(r)
        sr['predicted_classes'] = {str(k): int(v) for k, v in sr['predicted_classes'].items()}
        sr['true_class_distribution'] = {str(k): int(v) for k, v in sr['true_class_distribution'].items()}
        serializable_results.append(sr)
    with open(results_path, "w") as f:
        json.dump(serializable_results, f, indent=2)
    print(f"\n\nResults saved to: {results_path}")

    print("\n" + "=" * 60)
    print("SUMMARY: Unknown Attack Detection")
    print("=" * 60)
    print(f"{'File':<20} {'Samples':>8} {'Accuracy':>9} {'Low-Conf%':>10} {'Pred Dominant':>15}")
    print("-" * 65)
    for r in all_results:
        pred_counts = r['predicted_classes']
        dominant = max(pred_counts, key=pred_counts.get)
        dominant_name = le.inverse_transform([dominant])[0]
        print(f"{r['label']:<20} {r['samples']:>8,} {r['accuracy']:>9.4f} {r['confidence']['low_pct']:>10.1f}% {dominant_name:>15}")


if __name__ == "__main__":
    main()

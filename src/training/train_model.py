import os
import sys
import pickle
import json
import time
import numpy as np
import pandas as pd
from collections import Counter
from sklearn.neural_network import MLPClassifier
from sklearn.utils import resample
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    OUTPUT_DIR,
    PROCESSED_TRAIN_PATH,
    SCALER_PATH,
    LABEL_ENCODER_PATH,
    FEATURE_NAMES_PATH,
    MODEL_PATH,
    OOD_STATS_PATH,
    MLP_PARAMS,
    RANDOM_STATE,
    BALANCE_CLASSES,
)


def load_processed_data():
    with open(PROCESSED_TRAIN_PATH, "rb") as f:
        data = pickle.load(f)

    with open(LABEL_ENCODER_PATH, "rb") as f:
        le = pickle.load(f)

    with open(FEATURE_NAMES_PATH, "rb") as f:
        feature_names = pickle.load(f)

    return data, le, feature_names


def balance_classes(X, y, le):
    counter = Counter(y)
    min_samples = min(counter.values())
    base_target = min(min_samples, BALANCE_TARGET_PER_CLASS)

    X_balanced, y_balanced = [], []
    for cls in counter:
        label_name = le.inverse_transform([cls])[0]
        is_udplag = label_name == "UDPLag"
        target = int(base_target * UDPLAG_OVERSAMPLE_FACTOR) if is_udplag else base_target

        mask = y == cls
        available = mask.sum()

        if available >= target:
            X_cls, y_cls = resample(
                X[mask], y[mask],
                n_samples=target,
                random_state=RANDOM_STATE,
            )
        else:
            X_cls, y_cls = resample(
                X[mask], y[mask],
                n_samples=available,
                random_state=RANDOM_STATE,
                replace=True,
            )
            extra = target - available
            X_extra, y_extra = resample(
                X[mask], y[mask],
                n_samples=extra,
                random_state=RANDOM_STATE,
                replace=True,
            )
            X_cls = np.vstack([X_cls, X_extra])
            y_cls = np.concatenate([y_cls, y_extra])

        X_balanced.append(X_cls)
        y_balanced.append(y_cls)

    X_balanced = np.vstack(X_balanced)
    y_balanced = np.concatenate(y_balanced)
    return X_balanced, y_balanced


def train_model(X_train, y_train, le):
    print("\nTraining MLP Classifier...")
    print(f"  Architecture: {MLP_PARAMS['hidden_layer_sizes']}")
    print(f"  Activation: {MLP_PARAMS['activation']}")
    print(f"  Solver: {MLP_PARAMS['solver']}")
    print(f"  Alpha (L2): {MLP_PARAMS['alpha']}")
    print(f"  Batch size: {MLP_PARAMS['batch_size']}")
    print(f"  Max iterations: {MLP_PARAMS['max_iter']}")
    print(f"  Balance classes: {BALANCE_CLASSES}")
    print(f"  Training samples: {len(X_train):,}")

    if BALANCE_CLASSES:
        class_counts_orig = np.bincount(y_train)
        print(f"\n  Original class distribution: {dict(enumerate(class_counts_orig))}")

        X_train, y_train = balance_classes(X_train, y_train, le)
        class_counts = np.bincount(y_train)
        print(f"  Balanced class distribution: {dict(enumerate(class_counts))}")
        print(f"  Training samples (after balancing): {len(X_train):,}")

    start_time = time.time()
    model = MLPClassifier(**MLP_PARAMS)
    model.fit(X_train, y_train)
    training_time = time.time() - start_time

    print(f"\n  Training completed in {training_time:.1f}s")
    print(f"  Iterations: {model.n_iter_}")
    print(f"  Loss: {model.loss_:.4f}")

    return model, training_time


def evaluate_model(model, X_test, y_test, le, training_time):
    print("\n" + "=" * 60)
    print("EVALUATION")
    print("=" * 60)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted")
    recall = recall_score(y_test, y_pred, average="weighted")
    f1 = f1_score(y_test, y_pred, average="weighted")

    try:
        auc = roc_auc_score(y_test, y_prob, multi_class="ovr", average="weighted")
    except ValueError:
        auc = None

    print(f"\nOverall Metrics:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    if auc:
        print(f"  ROC AUC:   {auc:.4f}")

    print(f"\nPer-Class Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    cm = confusion_matrix(y_test, y_pred)
    print(f"\nConfusion Matrix:")
    header = "Predicted: " + "  ".join(f"{c:>12}" for c in le.classes_)
    print(f"{'Actual:':<12} {header}")
    for i, row in enumerate(cm):
        row_str = "  ".join(f"{v:>12}" for v in row)
        print(f"{le.classes_[i]:<12} {row_str}")

    metrics = {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(auc) if auc else None,
        "training_time": float(training_time),
        "training_samples": int(len(y_pred)),
        "classes": list(le.classes_),
        "confusion_matrix": cm.tolist(),
        "classification_report": classification_report(
            y_test, y_pred, target_names=le.classes_, output_dict=True
        ),
    }

    return metrics


def save_artifacts(model, metrics, feature_names):
    MODEL_WEIGHTS_PATH = os.path.join(OUTPUT_DIR, "mlp_weights.npz")
    save_dict = {}
    for i, c in enumerate(model.coefs_):
        save_dict[f"coefs_{i}"] = c
    for i, c in enumerate(model.intercepts_):
        save_dict[f"intercepts_{i}"] = c
    np.savez(MODEL_WEIGHTS_PATH, **save_dict)
    print(f"\nSaved model weights ({len(model.coefs_)} layers): {MODEL_WEIGHTS_PATH}")

    model_arch = {
        "hidden_layer_sizes": MLP_PARAMS["hidden_layer_sizes"],
        "activation": MLP_PARAMS["activation"],
        "n_features": model.n_features_in_,
        "n_outputs": len(model.classes_),
    }
    arch_path = os.path.join(OUTPUT_DIR, "mlp_architecture.json")
    with open(arch_path, "w") as f:
        json.dump(model_arch, f, indent=2)
    print(f"Saved architecture: {arch_path}")

    metrics_path = os.path.join(OUTPUT_DIR, "training_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2, default=str)
    print(f"Saved metrics: {metrics_path}")

    model_info = {
        "model_type": "MLPClassifier",
        "architecture": MLP_PARAMS["hidden_layer_sizes"],
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "classes": list(metrics["classes"]),
        "training_time": metrics["training_time"],
        "scaler_path": SCALER_PATH,
        "label_encoder_path": LABEL_ENCODER_PATH,
    }

    info_path = os.path.join(OUTPUT_DIR, "model_info.json")
    with open(info_path, "w") as f:
        json.dump(model_info, f, indent=2)
    print(f"Saved model info: {info_path}")


def penultimate_forward(X, model):
    x = X
    for i in range(len(model.coefs_) - 1):
        x = x @ model.coefs_[i] + model.intercepts_[i]
        x = np.maximum(x, 0)
    return x


def compute_ood_stats(X, y, le):
    n_classes = len(le.classes_)
    d = X.shape[1]

    class_means = np.zeros((n_classes, d))
    for cls in range(n_classes):
        mask = y == cls
        class_means[cls] = np.mean(X[mask], axis=0)

    cov = np.zeros((d, d))
    for cls in range(n_classes):
        mask = y == cls
        centered = X[mask] - class_means[cls]
        cov += centered.T @ centered

    cov /= len(X)
    cov += 0.01 * np.eye(d)
    cov_inv = np.linalg.inv(cov)

    return class_means, cov_inv


def main():
    print("=" * 60)
    print("TRAINING: MLP Base Model")
    print("=" * 60)

    data, le, feature_names = load_processed_data()

    X_train = data["X_train"]
    X_test = data["X_test"]
    y_train = data["y_train"]
    y_test = data["y_test"]

    model, training_time = train_model(X_train, y_train, le)

    print("\nComputing OOD detection statistics from training data...")
    penultimate_acts = penultimate_forward(X_train, model)
    class_means, cov_inv = compute_ood_stats(penultimate_acts, y_train, le)
    with open(OOD_STATS_PATH, "wb") as f:
        pickle.dump({"class_means": class_means, "cov_inv": cov_inv}, f)
    print(f"Saved OOD stats ({len(class_means)} classes, {cov_inv.shape[0]} dims): {OOD_STATS_PATH}")

    metrics = evaluate_model(model, X_test, y_test, le, training_time)

    save_artifacts(model, metrics, feature_names)

    print("\n" + "=" * 60)
    print("Training pipeline complete!")
    print(f"Model artifacts saved to: {OUTPUT_DIR}")
    print("=" * 60)


if __name__ == "__main__":
    main()

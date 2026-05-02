import os
import pickle
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import VarianceThreshold
from config import (
    COMBINED_TRAIN_PATH,
    OUTPUT_DIR,
    PROCESSED_TRAIN_PATH,
    SCALER_PATH,
    LABEL_ENCODER_PATH,
    FEATURE_NAMES_PATH,
    NUMERIC_FEATURES,
    TRAIN_TEST_SPLIT,
    RANDOM_STATE,
    VARIANCE_THRESHOLD,
    CORRELATION_THRESHOLD,
)


def load_data(filepath: str) -> pd.DataFrame:
    print(f"Loading: {filepath}")
    df = pd.read_csv(filepath)
    print(f"  Shape: {df.shape}")
    return df


def fill_missing_values(df: pd.DataFrame) -> pd.DataFrame:
    numeric_cols = df.select_dtypes(include=[np.number]).columns

    for col in numeric_cols:
        missing_pct = df[col].isnull().sum() / len(df) * 100
        if missing_pct > 0:
            median_val = df[col].median()
            df[col] = df[col].fillna(median_val)

    return df


def remove_zero_variance_features(df: pd.DataFrame, threshold: float = None) -> list:
    print("\nApplying variance threshold filter...")
    if threshold is None:
        threshold = VARIANCE_THRESHOLD

    selector = VarianceThreshold(threshold=threshold)
    selector.fit(df)

    kept_mask = selector.get_support()
    removed_features = [col for col, kept in zip(df.columns, kept_mask) if not kept]

    if removed_features:
        print(f"  Removed {len(removed_features)} near-zero-variance features:")
        for f in removed_features:
            print(f"    - {f}")
    else:
        print("  No features removed.")

    return df.columns[kept_mask].tolist()


def remove_highly_correlated_features(
    df: pd.DataFrame, threshold: float = 0.95
) -> list:
    print(f"\nRemoving features with correlation > {threshold}...")

    corr_matrix = df.corr().abs()
    upper_triangle = corr_matrix.where(
        np.triu(np.ones(corr_matrix.shape, dtype=bool), k=1)
    )

    to_drop = [col for col in upper_triangle.columns if any(upper_triangle[col] > threshold)]

    if to_drop:
        print(f"  Removed {len(to_drop)} highly correlated features:")
        for f in to_drop:
            print(f"    - {f}")
    else:
        print("  No features removed.")

    kept = [col for col in df.columns if col not in to_drop]
    return kept


def preprocess_pipeline():
    print("=" * 60)
    print("PREPROCESSING: Feature Selection, Scaling, Splitting")
    print("=" * 60)

    df = load_data(COMBINED_TRAIN_PATH)

    if "Label" not in df.columns:
        raise ValueError("Label column not found in combined data")

    y_raw = df["Label"]
    X = df.drop(columns=["Label"])

    X = fill_missing_values(X)

    numeric_cols = X.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = X.select_dtypes(include=["object"]).columns.tolist()

    if categorical_cols:
        print(f"\nDropping {len(categorical_cols)} categorical columns: {categorical_cols}")
        X = X.drop(columns=categorical_cols)

    print(f"\nFeatures after dropping categorical: {X.shape[1]}")

    variance_kept = remove_zero_variance_features(X[numeric_cols])
    X = X[variance_kept]

    correlation_kept = remove_highly_correlated_features(X, threshold=CORRELATION_THRESHOLD)
    X = X[correlation_kept]

    print(f"\nFinal feature count: {X.shape[1]}")

    le = LabelEncoder()
    y = le.fit_transform(y_raw)

    print(f"\nClasses: {list(le.classes_)}")
    print(f"Encoded labels: {list(range(len(le.classes_)))}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=1 - TRAIN_TEST_SPLIT, random_state=RANDOM_STATE, stratify=y
    )

    print(f"\nTrain set: {X_train.shape[0]} samples")
    print(f"Test set:  {X_test.shape[0]} samples")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    feature_names = list(X.columns)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    train_data = {
        "X_train": X_train_scaled,
        "X_test": X_test_scaled,
        "y_train": y_train,
        "y_test": y_test,
    }

    with open(PROCESSED_TRAIN_PATH, "wb") as f:
        pickle.dump(train_data, f)
    print(f"\nSaved processed data: {PROCESSED_TRAIN_PATH}")

    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)
    print(f"Saved scaler: {SCALER_PATH}")

    with open(LABEL_ENCODER_PATH, "wb") as f:
        pickle.dump(le, f)
    print(f"Saved label encoder: {LABEL_ENCODER_PATH}")

    with open(FEATURE_NAMES_PATH, "wb") as f:
        pickle.dump(feature_names, f)
    print(f"Saved feature names ({len(feature_names)}): {FEATURE_NAMES_PATH}")

    print("\n" + "=" * 60)
    print("Preprocessing complete!")
    print(f"Features retained: {len(feature_names)}")
    print(f"Classes: {list(le.classes_)}")
    print(f"Train/Test split: {TRAIN_TEST_SPLIT:.0%}/{1-TRAIN_TEST_SPLIT:.0%}")
    print("=" * 60)

    return feature_names, le


if __name__ == "__main__":
    preprocess_pipeline()

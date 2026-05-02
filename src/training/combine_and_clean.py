import os
import sys
import pandas as pd
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    DATA_DIR,
    OUTPUT_DIR,
    INITIAL_TRAIN_FILES,
    COMBINED_TRAIN_PATH,
    CHUNK_SIZE,
    DROP_COLUMNS,
)


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = df.columns.str.strip()
    return df


def basic_cleaning(df: pd.DataFrame) -> pd.DataFrame:
    df = df.replace([np.inf, -np.inf], np.nan)

    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].apply(pd.to_numeric, errors="coerce")

    return df


def drop_unwanted_columns(df: pd.DataFrame) -> pd.DataFrame:
    cols_to_drop = [c for c in DROP_COLUMNS if c in df.columns]
    if cols_to_drop:
        df = df.drop(columns=cols_to_drop)
    return df


def sample_chunk(chunk: pd.DataFrame, max_rows: int) -> pd.DataFrame:
    if len(chunk) > max_rows:
        return chunk.sample(n=max_rows, random_state=42)
    return chunk


def process_file(filepath: str, label: str, max_rows: int) -> pd.DataFrame:
    print(f"\nProcessing: {os.path.basename(filepath)} (target: {max_rows} rows)")

    chunks = []
    total_read = 0
    reader = pd.read_csv(filepath, chunksize=CHUNK_SIZE, low_memory=False)

    for i, chunk in enumerate(reader):
        chunk = clean_column_names(chunk)
        chunk = drop_unwanted_columns(chunk)
        chunk = basic_cleaning(chunk)
        chunk["Label"] = label

        chunks.append(chunk)
        total_read += len(chunk)

        print(f"  Chunk {i+1}: {len(chunk)} rows (total: {total_read})")

        if total_read >= max_rows:
            break

    df = pd.concat(chunks, ignore_index=True)

    if len(df) > max_rows:
        df = df.sample(n=max_rows, random_state=42).reset_index(drop=True)

    print(f"  Final: {len(df)} rows")
    return df


def compute_sample_allocation(files: dict, target_total: int) -> dict:
    file_sizes = {}
    print("\nScanning file sizes...")

    for filename in files:
        filepath = os.path.join(DATA_DIR, filename)
        with open(filepath, "r") as f:
            line_count = sum(1 for _ in f) - 1
        file_sizes[filename] = line_count
        print(f"  {filename}: {line_count:,} rows")

    total_rows = sum(file_sizes.values())
    allocation = {}

    for filename, size in file_sizes.items():
        proportion = size / total_rows
        allocated = int(target_total * proportion)
        allocation[filename] = min(allocated, size)

    excess = target_total - sum(allocation.values())
    if excess > 0:
        largest_file = max(allocation, key=allocation.get)
        allocation[largest_file] += excess

    print(f"\nSample allocation (target: {target_total:,}):")
    for fname, count in allocation.items():
        print(f"  {fname}: {count:,} rows ({count/total_rows*100:.1f}%)")

    return allocation


def main():
    target_total = int(sys.argv[1]) if len(sys.argv) > 1 else 1500000

    print("=" * 60)
    print("COMBINE AND CLEAN: Initial Training Data")
    print("=" * 60)

    allocation = compute_sample_allocation(INITIAL_TRAIN_FILES, target_total)

    all_data = []

    for filename, label in INITIAL_TRAIN_FILES.items():
        filepath = os.path.join(DATA_DIR, filename)
        max_rows = allocation[filename]

        df = process_file(filepath, label, max_rows)
        all_data.append(df)

    print("\nCombining all data...")
    combined = pd.concat(all_data, ignore_index=True)

    print(f"\nCombined dataset shape: {combined.shape}")
    print(f"Columns: {len(combined.columns)}")
    print(f"\nLabel distribution:")
    print(combined["Label"].value_counts())

    print(f"\nNull values per column:")
    null_counts = combined.isnull().sum()
    print(null_counts[null_counts > 0] if null_counts.sum() > 0 else "  None")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    combined.to_csv(COMBINED_TRAIN_PATH, index=False)
    print(f"\nSaved to: {COMBINED_TRAIN_PATH} ({os.path.getsize(COMBINED_TRAIN_PATH) / (1024**2):.1f} MB)")


if __name__ == "__main__":
    main()

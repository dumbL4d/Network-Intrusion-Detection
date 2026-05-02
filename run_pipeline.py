#!/usr/bin/env python3
"""
Run the full training pipeline:
  1. Combine and clean CSV files
  2. Preprocess, feature selection, scaling
  3. Train MLP base model

Usage:
  python run_pipeline.py [target_rows]

  target_rows: Total rows to sample for training (default: 1500000)
"""
import sys
import subprocess


def run_step(script: str, description: str, *args):
    print(f"\n{'=' * 60}")
    print(f"STEP: {description}")
    print(f"{'=' * 60}")

    cmd = [sys.executable, script] + list(args)
    result = subprocess.run(cmd, capture_output=False)

    if result.returncode != 0:
        print(f"\nFAILED: {description}")
        sys.exit(1)


def main():
    target_rows = sys.argv[1] if len(sys.argv) > 1 else "1500000"

    print("Network Intrusion Detection - Training Pipeline")
    print(f"Target training rows: {int(target_rows):,}")

    run_step("combine_and_clean.py", "Combine & Clean Data", target_rows)
    run_step("preprocess.py", "Preprocess & Feature Selection")
    run_step("train_model.py", "Train MLP Model")

    print("\n\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()

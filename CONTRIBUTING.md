# Contributing to NIDS

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/Network-Intrusion-Detection.git
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Place CICDDoS2019 CSV files in `data/raw/`
5. Run the training pipeline:
   ```bash
   python3 src/run_pipeline.py 1500000
   ```

## Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/your-feature
   ```
2. Make changes and commit with clear messages
3. Push and open a pull request

## Code Conventions

- **Python**: Follow PEP 8. Use descriptive names for variables and functions.
- **Bash**: Use `#!/bin/bash` shebang, quote variables, prefer `[[ ]]` over `[ ]`.
- **Imports**: Standard library → third-party → local, separated by blank lines.
- **Type hints**: Use Python type hints for function signatures.
- **Config**: Never hardcode paths or hyperparameters — use `src/config.py`.

## What to Contribute

- **Bug fixes** — MLP misclassifications, ARF drift detection, preprocessing edge cases
- **New attack types** — Add new CSV mappings to `config.py`'s `INITIAL_TRAIN_FILES` or `DRIFT_FILES`
- **Feature engineering** — New CICDDoS2019 feature groups in `HIGH_SIGNAL_FEATURE_GROUPS`
- **Evaluations** — Additional metrics, visualization scripts in `src/evaluation/`
- **Deployment** — Helm charts, Kubernetes manifests, CI/CD pipelines
- **Documentation** — API docs, tutorials, architecture diagrams

## Testing

- Test the detector directly:
  ```bash
  python3 src/detection/realtime_detector.py
  curl http://localhost:8080/health
  ```
- Evaluate on unknown attacks:
  ```bash
  python3 src/evaluation/evaluate_unknown.py
  python3 src/evaluation/arf_drift_detection.py
  ```
- Docker end-to-end test:
  ```bash
  docker compose -f docker/docker-compose.yml up --build
  ```

## Pull Request Process

1. Ensure the training pipeline runs without errors
2. Update `README.md` if your change affects the API, config, or workflow
3. Keep PRs focused — one feature or fix per PR
4. Link related issues in the PR description

## Reporting Issues

Include:
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error output
- Docker or execution environment details

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

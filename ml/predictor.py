"""
ML Predictor Module

Real-time attack classification service.
"""

from __future__ import annotations

import asyncio
import logging
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd

from ml.models import AnomalyDetector, AttackClassifier
from ml.preprocessor import AttackPreprocessor

logger = logging.getLogger(__name__)


class AttackPredictor:
    """
    Real-time attack classification service.
    
    Provides async prediction endpoints for the honeypot system.
    """

    def __init__(
        self,
        model_dir: str | Path = "ml/models",
        confidence_threshold: float = 0.7,
    ):
        self._model_dir = Path(model_dir)
        self._confidence_threshold = confidence_threshold

        self._preprocessor: Optional[AttackPreprocessor] = None
        self._classifier: Optional[AttackClassifier] = None
        self._anomaly_detector: Optional[AnomalyDetector] = None

        self._loaded = False
        self._lock = asyncio.Lock()

        # Prediction cache for repeated attacks
        self._cache: dict[str, dict] = {}
        self._cache_ttl = 300  # 5 minutes

    async def load_models(self, version: str = "latest") -> bool:
        """
        Load trained models from disk.
        
        Args:
            version: Model version to load ('latest' for most recent)
            
        Returns:
            True if successful
        """
        async with self._lock:
            try:
                # Find model files
                if version == "latest":
                    classifier_files = sorted(
                        self._model_dir.glob("classifier_*.pkl"),
                        reverse=True,
                    )
                    anomaly_files = sorted(
                        self._model_dir.glob("anomaly_detector_*.pkl"),
                        reverse=True,
                    )
                    preprocessor_files = sorted(
                        self._model_dir.glob("preprocessor_*.pkl"),
                        reverse=True,
                    )
                else:
                    classifier_files = list(
                        self._model_dir.glob(f"classifier_{version}_*.pkl")
                    )
                    anomaly_files = list(
                        self._model_dir.glob(f"anomaly_detector_{version}_*.pkl")
                    )
                    preprocessor_files = list(
                        self._model_dir.glob(f"preprocessor_{version}_*.pkl")
                    )

                if not classifier_files:
                    logger.warning("No classifier model found")
                    return False

                # Load classifier
                self._classifier = AttackClassifier.load(classifier_files[0])
                logger.info(f"Loaded classifier from {classifier_files[0]}")

                # Load anomaly detector
                if anomaly_files:
                    self._anomaly_detector = AnomalyDetector.load(anomaly_files[0])
                    logger.info(f"Loaded anomaly detector from {anomaly_files[0]}")

                # Load preprocessor
                if preprocessor_files:
                    with open(preprocessor_files[0], 'rb') as f:
                        self._preprocessor = pickle.load(f)
                    logger.info(f"Loaded preprocessor from {preprocessor_files[0]}")
                else:
                    self._preprocessor = AttackPreprocessor()

                self._loaded = True
                return True

            except Exception as e:
                logger.error(f"Failed to load models: {e}")
                return False

    async def predict(
        self,
        attack_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Classify a single attack.
        
        Args:
            attack_data: Dictionary with attack attributes
            
        Returns:
            Prediction results with classification and confidence
        """
        if not self._loaded:
            return {
                'error': 'Models not loaded',
                'attack_type': 'unknown',
                'confidence': 0.0,
            }

        # Check cache
        cache_key = self._get_cache_key(attack_data)
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if (datetime.utcnow() - cached['timestamp']).seconds < self._cache_ttl:
                return cached['result']

        # Convert to DataFrame
        df = pd.DataFrame([attack_data])

        try:
            # Preprocess
            X = self._preprocessor.transform(df)

            # Classify
            predictions = self._classifier.predict_with_confidence(X)
            attack_type, confidence = predictions[0]

            result = {
                'attack_type': attack_type,
                'confidence': confidence,
                'is_confident': confidence >= self._confidence_threshold,
            }

            # Check for anomaly
            if self._anomaly_detector:
                anomaly_results = self._anomaly_detector.get_anomaly_scores(X)
                result['is_anomaly'] = anomaly_results[0]['is_anomaly']
                result['anomaly_score'] = anomaly_results[0]['anomaly_score']

            # Decode label if needed
            if hasattr(self._preprocessor, 'decode_labels'):
                decoded = self._preprocessor.decode_labels([int(attack_type)])
                if decoded:
                    result['attack_type'] = decoded[0]

            # Cache result
            self._cache[cache_key] = {
                'result': result,
                'timestamp': datetime.utcnow(),
            }

            return result

        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {
                'error': str(e),
                'attack_type': 'unknown',
                'confidence': 0.0,
            }

    async def predict_batch(
        self,
        attacks: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Classify multiple attacks.
        
        Args:
            attacks: List of attack data dictionaries
            
        Returns:
            List of prediction results
        """
        if not self._loaded:
            return [{'error': 'Models not loaded', 'attack_type': 'unknown', 'confidence': 0.0}
                    for _ in attacks]

        # Convert to DataFrame
        df = pd.DataFrame(attacks)

        try:
            # Preprocess
            X = self._preprocessor.transform(df)

            # Classify
            predictions = self._classifier.predict_with_confidence(X)

            results = []
            for i, (attack_type, confidence) in enumerate(predictions):
                result = {
                    'attack_type': attack_type,
                    'confidence': confidence,
                    'is_confident': confidence >= self._confidence_threshold,
                }

                # Check for anomaly
                if self._anomaly_detector:
                    anomaly_results = self._anomaly_detector.get_anomaly_scores(
                        X[i:i+1]
                    )
                    result['is_anomaly'] = anomaly_results[0]['is_anomaly']
                    result['anomaly_score'] = anomaly_results[0]['anomaly_score']

                results.append(result)

            return results

        except Exception as e:
            logger.error(f"Batch prediction error: {e}")
            return [{'error': str(e), 'attack_type': 'unknown', 'confidence': 0.0}
                    for _ in attacks]

    async def get_threat_score(
        self,
        attack_data: dict[str, Any],
    ) -> float:
        """
        Calculate overall threat score (0-10).
        
        Combines classification confidence and anomaly detection.
        """
        prediction = await self.predict(attack_data)

        base_score = 5.0  # Default

        # Adjust based on attack type
        severity_map = {
            'reconnaissance': 2,
            'brute_force': 4,
            'credential_theft': 6,
            'sql_injection': 7,
            'xss': 5,
            'rce': 9,
            'path_traversal': 6,
            'malware_deployment': 10,
            'data_exfiltration': 8,
        }

        attack_type = prediction.get('attack_type', 'unknown')
        base_score = severity_map.get(attack_type, 5)

        # Adjust for confidence
        confidence = prediction.get('confidence', 0.5)
        if confidence < 0.5:
            base_score *= 0.8
        elif confidence > 0.8:
            base_score *= 1.1

        # Boost for anomalies
        if prediction.get('is_anomaly', False):
            base_score = min(base_score * 1.2, 10)

        return min(max(base_score, 1), 10)

    def _get_cache_key(self, attack_data: dict) -> str:
        """Generate cache key from attack data."""
        key_parts = [
            str(attack_data.get('source_ip', '')),
            str(attack_data.get('service_type', '')),
            str(attack_data.get('command', ''))[:100],
            str(attack_data.get('path', ''))[:100],
        ]
        return '|'.join(key_parts)

    async def clear_cache(self) -> None:
        """Clear the prediction cache."""
        self._cache.clear()

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def classes(self) -> list[str]:
        if self._classifier:
            return self._classifier.classes
        return []


# Global predictor instance
_predictor: Optional[AttackPredictor] = None


async def get_predictor() -> AttackPredictor:
    """Get the global predictor instance."""
    global _predictor
    if _predictor is None:
        _predictor = AttackPredictor()
    return _predictor


async def init_predictor(
    model_dir: str | Path = "ml/models",
    confidence_threshold: float = 0.7,
) -> AttackPredictor:
    """Initialize the global predictor."""
    global _predictor
    _predictor = AttackPredictor(
        model_dir=model_dir,
        confidence_threshold=confidence_threshold,
    )
    await _predictor.load_models()
    return _predictor

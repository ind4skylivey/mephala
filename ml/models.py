"""
ML Models Module

Machine learning models for attack classification and anomaly detection.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GridSearchCV, cross_val_score


@dataclass
class ModelMetrics:
    """Metrics for model evaluation."""
    accuracy: float
    precision: float
    recall: float
    f1: float
    confusion_matrix: Optional[np.ndarray] = None
    classification_report: Optional[str] = None


class AttackClassifier:
    """
    Random Forest classifier for attack type classification.
    
    Classifies attacks into categories:
    - reconnaissance
    - brute_force
    - exploitation
    - malware_deployment
    - credential_theft
    - data_exfiltration
    """

    DEFAULT_PARAMS = {
        'n_estimators': 100,
        'max_depth': 20,
        'min_samples_split': 5,
        'min_samples_leaf': 2,
        'class_weight': 'balanced',
        'random_state': 42,
        'n_jobs': -1,
    }

    def __init__(self, **kwargs):
        params = {**self.DEFAULT_PARAMS, **kwargs}
        self._model = RandomForestClassifier(**params)
        self._trained = False
        self._feature_names: list[str] = []
        self._classes: list[str] = []
        self._metrics: Optional[ModelMetrics] = None

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        feature_names: Optional[list[str]] = None,
    ) -> "AttackClassifier":
        """
        Train the classifier.
        
        Args:
            X: Feature matrix
            y: Target labels
            feature_names: Optional list of feature names
            
        Returns:
            Self for chaining
        """
        self._model.fit(X, y)
        self._trained = True
        self._feature_names = feature_names or []
        self._classes = list(self._model.classes_)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict attack types."""
        if not self._trained:
            raise RuntimeError("Model not trained")
        return self._model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities."""
        if not self._trained:
            raise RuntimeError("Model not trained")
        return self._model.predict_proba(X)

    def predict_with_confidence(
        self,
        X: np.ndarray,
    ) -> list[tuple[str, float]]:
        """
        Predict with confidence scores.
        
        Returns:
            List of (predicted_class, confidence) tuples
        """
        predictions = self.predict(X)
        probabilities = self.predict_proba(X)

        results = []
        for i, pred in enumerate(predictions):
            confidence = float(np.max(probabilities[i]))
            results.append((str(pred), confidence))

        return results

    def evaluate(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> ModelMetrics:
        """
        Evaluate model performance.
        
        Args:
            X: Feature matrix
            y: True labels
            
        Returns:
            ModelMetrics with evaluation results
        """
        predictions = self.predict(X)

        self._metrics = ModelMetrics(
            accuracy=accuracy_score(y, predictions),
            precision=precision_score(y, predictions, average='weighted', zero_division=0),
            recall=recall_score(y, predictions, average='weighted', zero_division=0),
            f1=f1_score(y, predictions, average='weighted', zero_division=0),
            confusion_matrix=confusion_matrix(y, predictions),
            classification_report=classification_report(y, predictions, zero_division=0),
        )

        return self._metrics

    def cross_validate(
        self,
        X: np.ndarray,
        y: np.ndarray,
        cv: int = 5,
    ) -> dict[str, float]:
        """
        Perform cross-validation.
        
        Returns:
            Dictionary with mean and std of scores
        """
        scores = cross_val_score(self._model, X, y, cv=cv, scoring='f1_weighted')
        return {
            'mean_f1': float(np.mean(scores)),
            'std_f1': float(np.std(scores)),
            'scores': scores.tolist(),
        }

    def get_feature_importance(self) -> list[tuple[str, float]]:
        """Get feature importance rankings."""
        if not self._trained:
            return []

        importances = self._model.feature_importances_
        if self._feature_names:
            return sorted(
                zip(self._feature_names, importances),
                key=lambda x: x[1],
                reverse=True,
            )
        return [(f"feature_{i}", imp) for i, imp in enumerate(importances)]

    def save(self, path: str | Path) -> None:
        """Save model to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            'model': self._model,
            'feature_names': self._feature_names,
            'classes': self._classes,
            'metrics': self._metrics,
            'trained': self._trained,
            'saved_at': datetime.utcnow().isoformat(),
        }

        with open(path, 'wb') as f:
            pickle.dump(data, f)

    @classmethod
    def load(cls, path: str | Path) -> "AttackClassifier":
        """Load model from file."""
        with open(path, 'rb') as f:
            data = pickle.load(f)

        instance = cls()
        instance._model = data['model']
        instance._feature_names = data['feature_names']
        instance._classes = data['classes']
        instance._metrics = data['metrics']
        instance._trained = data['trained']

        return instance

    @property
    def classes(self) -> list[str]:
        return self._classes

    @property
    def is_trained(self) -> bool:
        return self._trained


class AnomalyDetector:
    """
    Isolation Forest for anomaly detection.
    
    Identifies unusual attack patterns that don't fit known categories.
    """

    DEFAULT_PARAMS = {
        'n_estimators': 100,
        'contamination': 0.1,
        'max_samples': 'auto',
        'random_state': 42,
        'n_jobs': -1,
    }

    def __init__(self, **kwargs):
        params = {**self.DEFAULT_PARAMS, **kwargs}
        self._model = IsolationForest(**params)
        self._trained = False
        self._threshold: float = 0.0

    def fit(self, X: np.ndarray) -> "AnomalyDetector":
        """
        Train the anomaly detector on normal data.
        
        Args:
            X: Feature matrix of normal/typical attacks
            
        Returns:
            Self for chaining
        """
        self._model.fit(X)
        self._trained = True

        # Calculate threshold based on training data
        scores = self._model.score_samples(X)
        self._threshold = float(np.percentile(scores, 10))

        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomalies.
        
        Returns:
            Array of 1 (normal) or -1 (anomaly)
        """
        if not self._trained:
            raise RuntimeError("Model not trained")
        return self._model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores.
        
        Lower scores indicate more anomalous samples.
        """
        if not self._trained:
            raise RuntimeError("Model not trained")
        return self._model.score_samples(X)

    def is_anomaly(self, X: np.ndarray) -> list[bool]:
        """Check if samples are anomalies."""
        scores = self.score_samples(X)
        return [score < self._threshold for score in scores]

    def get_anomaly_scores(self, X: np.ndarray) -> list[dict[str, Any]]:
        """
        Get detailed anomaly analysis.
        
        Returns:
            List of dicts with score and is_anomaly flag
        """
        scores = self.score_samples(X)
        predictions = self.predict(X)

        results = []
        for score, pred in zip(scores, predictions):
            results.append({
                'anomaly_score': float(score),
                'is_anomaly': pred == -1,
                'confidence': abs(float(score - self._threshold)),
            })

        return results

    def save(self, path: str | Path) -> None:
        """Save model to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            'model': self._model,
            'threshold': self._threshold,
            'trained': self._trained,
            'saved_at': datetime.utcnow().isoformat(),
        }

        with open(path, 'wb') as f:
            pickle.dump(data, f)

    @classmethod
    def load(cls, path: str | Path) -> "AnomalyDetector":
        """Load model from file."""
        with open(path, 'rb') as f:
            data = pickle.load(f)

        instance = cls()
        instance._model = data['model']
        instance._threshold = data['threshold']
        instance._trained = data['trained']

        return instance

    @property
    def is_trained(self) -> bool:
        return self._trained


class HyperparameterTuner:
    """Hyperparameter tuning for attack classifier."""

    PARAM_GRID = {
        'n_estimators': [50, 100, 200],
        'max_depth': [10, 20, 30, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4],
    }

    def __init__(self, param_grid: Optional[dict] = None):
        self._param_grid = param_grid or self.PARAM_GRID
        self._best_params: dict = {}
        self._best_score: float = 0.0

    def tune(
        self,
        X: np.ndarray,
        y: np.ndarray,
        cv: int = 5,
    ) -> dict[str, Any]:
        """
        Find best hyperparameters using grid search.
        
        Args:
            X: Feature matrix
            y: Target labels
            cv: Number of cross-validation folds
            
        Returns:
            Best parameters and scores
        """
        base_model = RandomForestClassifier(
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
        )

        grid_search = GridSearchCV(
            base_model,
            self._param_grid,
            cv=cv,
            scoring='f1_weighted',
            n_jobs=-1,
            verbose=1,
        )

        grid_search.fit(X, y)

        self._best_params = grid_search.best_params_
        self._best_score = grid_search.best_score_

        return {
            'best_params': self._best_params,
            'best_score': self._best_score,
            'cv_results': {
                'mean_scores': grid_search.cv_results_['mean_test_score'].tolist(),
                'std_scores': grid_search.cv_results_['std_test_score'].tolist(),
            },
        }

    def get_tuned_classifier(self) -> AttackClassifier:
        """Get a classifier with the best found parameters."""
        if not self._best_params:
            raise RuntimeError("Run tune() first")
        return AttackClassifier(**self._best_params)

    @property
    def best_params(self) -> dict:
        return self._best_params

    @property
    def best_score(self) -> float:
        return self._best_score

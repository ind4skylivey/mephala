"""
ML Preprocessor Module

Feature extraction and data cleaning for attack classification.
Transforms raw attack data into feature vectors for ML models.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import datetime
from typing import Any, Optional

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder, StandardScaler


class AttackPreprocessor:
    """
    Preprocessor for attack data.
    
    Extracts features from raw attack logs for ML classification.
    """

    def __init__(self):
        self._tfidf_command = TfidfVectorizer(
            max_features=100,
            ngram_range=(1, 2),
            stop_words=None,
        )
        self._tfidf_path = TfidfVectorizer(
            max_features=50,
            ngram_range=(1, 2),
            analyzer='char_wb',
        )
        self._scaler = StandardScaler()
        self._label_encoder = LabelEncoder()
        self._fitted = False

        # Known malicious patterns
        self._sql_patterns = [
            r"union\s+select", r"or\s+1\s*=\s*1", r"'\s*or\s*'",
            r";\s*drop\s+table", r"--\s*$", r"/\*.*\*/",
            r"benchmark\s*\(", r"sleep\s*\(", r"load_file\s*\(",
        ]
        self._xss_patterns = [
            r"<script", r"javascript:", r"onerror\s*=",
            r"onload\s*=", r"onclick\s*=", r"eval\s*\(",
        ]
        self._rce_patterns = [
            r";\s*cat\s+", r"\|\s*cat\s+", r"`.*`",
            r"\$\(.*\)", r"/bin/sh", r"/bin/bash",
            r"nc\s+-", r"wget\s+", r"curl\s+",
        ]
        self._traversal_patterns = [
            r"\.\./", r"\.\.\\", r"%2e%2e", r"etc/passwd",
        ]

    def fit(self, data: pd.DataFrame) -> "AttackPreprocessor":
        """
        Fit the preprocessor on training data.
        
        Args:
            data: DataFrame with attack records
            
        Returns:
            Self for chaining
        """
        # Fit TF-IDF on commands
        if 'command' in data.columns:
            commands = data['command'].fillna('').astype(str)
            self._tfidf_command.fit(commands)

        # Fit TF-IDF on paths
        if 'path' in data.columns:
            paths = data['path'].fillna('').astype(str)
            self._tfidf_path.fit(paths)

        # Fit label encoder on attack types
        if 'attack_type' in data.columns:
            self._label_encoder.fit(data['attack_type'].fillna('unknown'))

        # Fit scaler on numeric features
        numeric_features = self._extract_numeric_features(data)
        if len(numeric_features) > 0:
            self._scaler.fit(numeric_features)

        self._fitted = True
        return self

    def transform(self, data: pd.DataFrame) -> np.ndarray:
        """
        Transform attack data into feature vectors.
        
        Args:
            data: DataFrame with attack records
            
        Returns:
            Feature matrix as numpy array
        """
        features = []

        # Numeric features
        numeric = self._extract_numeric_features(data)
        if self._fitted and len(numeric) > 0:
            numeric = self._scaler.transform(numeric)
        features.append(numeric)

        # Command TF-IDF features
        if 'command' in data.columns and self._fitted:
            commands = data['command'].fillna('').astype(str)
            cmd_features = self._tfidf_command.transform(commands).toarray()
            features.append(cmd_features)

        # Path TF-IDF features
        if 'path' in data.columns and self._fitted:
            paths = data['path'].fillna('').astype(str)
            path_features = self._tfidf_path.transform(paths).toarray()
            features.append(path_features)

        # Pattern-based features
        pattern_features = self._extract_pattern_features(data)
        features.append(pattern_features)

        # Concatenate all features
        return np.hstack([f for f in features if f.size > 0])

    def fit_transform(self, data: pd.DataFrame) -> np.ndarray:
        """Fit and transform in one step."""
        self.fit(data)
        return self.transform(data)

    def _extract_numeric_features(self, data: pd.DataFrame) -> np.ndarray:
        """Extract numeric features from data."""
        features = []

        # Port features
        if 'source_port' in data.columns:
            features.append(data['source_port'].fillna(0).values.reshape(-1, 1))
        if 'destination_port' in data.columns:
            features.append(data['destination_port'].fillna(0).values.reshape(-1, 1))

        # Severity
        if 'severity' in data.columns:
            features.append(data['severity'].fillna(0).values.reshape(-1, 1))

        # Time-based features
        if 'timestamp' in data.columns:
            timestamps = pd.to_datetime(data['timestamp'])
            features.append(timestamps.dt.hour.values.reshape(-1, 1))
            features.append(timestamps.dt.dayofweek.values.reshape(-1, 1))

        # Request size
        if 'body_size' in data.columns:
            features.append(data['body_size'].fillna(0).values.reshape(-1, 1))

        if features:
            return np.hstack(features)
        return np.array([]).reshape(len(data), 0)

    def _extract_pattern_features(self, data: pd.DataFrame) -> np.ndarray:
        """Extract pattern-based binary features."""
        n_samples = len(data)
        features = np.zeros((n_samples, 12))

        for i in range(n_samples):
            row = data.iloc[i]
            text = self._get_text_content(row)

            # SQL injection patterns
            features[i, 0] = self._count_pattern_matches(text, self._sql_patterns)
            features[i, 1] = 1 if features[i, 0] > 0 else 0

            # XSS patterns
            features[i, 2] = self._count_pattern_matches(text, self._xss_patterns)
            features[i, 3] = 1 if features[i, 2] > 0 else 0

            # RCE patterns
            features[i, 4] = self._count_pattern_matches(text, self._rce_patterns)
            features[i, 5] = 1 if features[i, 4] > 0 else 0

            # Path traversal
            features[i, 6] = self._count_pattern_matches(text, self._traversal_patterns)
            features[i, 7] = 1 if features[i, 6] > 0 else 0

            # Content length features
            features[i, 8] = len(text)
            features[i, 9] = text.count('/')
            features[i, 10] = text.count('.')
            features[i, 11] = len(re.findall(r'[<>"\']', text))

        return features

    def _get_text_content(self, row: pd.Series) -> str:
        """Extract all text content from a row."""
        parts = []
        for col in ['command', 'path', 'query_string', 'body', 'user_agent']:
            if col in row.index and pd.notna(row[col]):
                parts.append(str(row[col]))
        return ' '.join(parts).lower()

    def _count_pattern_matches(self, text: str, patterns: list[str]) -> int:
        """Count pattern matches in text."""
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, text, re.IGNORECASE))
        return count

    def encode_labels(self, labels: pd.Series) -> np.ndarray:
        """Encode attack type labels."""
        return self._label_encoder.transform(labels.fillna('unknown'))

    def decode_labels(self, encoded: np.ndarray) -> list[str]:
        """Decode encoded labels back to strings."""
        return self._label_encoder.inverse_transform(encoded).tolist()

    @property
    def classes(self) -> list[str]:
        """Get the list of attack type classes."""
        if self._fitted:
            return self._label_encoder.classes_.tolist()
        return []


class IPFeatureExtractor:
    """Extract features from IP addresses."""

    def __init__(self):
        self._ip_history: dict[str, list[datetime]] = {}
        self._ip_services: dict[str, set[str]] = {}

    def extract_features(self, ip: str, service: str, timestamp: datetime) -> dict[str, Any]:
        """
        Extract features for an IP address.
        
        Args:
            ip: Source IP address
            service: Service type (ssh, http, ftp)
            timestamp: Attack timestamp
            
        Returns:
            Dictionary of features
        """
        # Update history
        if ip not in self._ip_history:
            self._ip_history[ip] = []
            self._ip_services[ip] = set()

        self._ip_history[ip].append(timestamp)
        self._ip_services[ip].add(service)

        history = self._ip_history[ip]

        features = {
            'total_attacks': len(history),
            'services_targeted': len(self._ip_services[ip]),
            'is_repeat_offender': len(history) > 5,
        }

        # Time-based features
        if len(history) > 1:
            deltas = [(history[i] - history[i-1]).total_seconds() 
                      for i in range(1, len(history))]
            features['avg_time_between_attacks'] = np.mean(deltas)
            features['min_time_between_attacks'] = np.min(deltas)
            features['is_automated'] = np.min(deltas) < 1.0  # Less than 1 second
        else:
            features['avg_time_between_attacks'] = 0
            features['min_time_between_attacks'] = 0
            features['is_automated'] = False

        # IP structure features
        octets = ip.split('.')
        if len(octets) == 4:
            features['ip_first_octet'] = int(octets[0])
            features['is_private_ip'] = self._is_private_ip(ip)
        else:
            features['ip_first_octet'] = 0
            features['is_private_ip'] = False

        return features

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range."""
        try:
            octets = [int(o) for o in ip.split('.')]
            if octets[0] == 10:
                return True
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            if octets[0] == 192 and octets[1] == 168:
                return True
            return False
        except (ValueError, IndexError):
            return False


class CommandAnalyzer:
    """Analyze shell commands for threat classification."""

    # Command categories
    RECON_COMMANDS = {'ls', 'cat', 'find', 'grep', 'ps', 'netstat', 'who', 'w', 
                      'id', 'uname', 'hostname', 'ifconfig', 'ip', 'ss', 'lsof'}
    DOWNLOAD_COMMANDS = {'wget', 'curl', 'scp', 'sftp', 'ftp', 'nc', 'netcat'}
    PERSISTENCE_COMMANDS = {'crontab', 'at', 'useradd', 'adduser', 'usermod',
                            'chmod', 'chown', 'systemctl', 'service'}
    EXFIL_COMMANDS = {'tar', 'zip', 'gzip', 'base64', 'xxd', 'nc', 'curl'}
    PRIVESC_COMMANDS = {'sudo', 'su', 'passwd', 'chmod', 'chown', 'setuid'}

    def analyze(self, command: str) -> dict[str, Any]:
        """
        Analyze a command for threat indicators.
        
        Args:
            command: Shell command string
            
        Returns:
            Analysis results
        """
        cmd_parts = command.lower().split()
        base_cmd = cmd_parts[0] if cmd_parts else ''

        results = {
            'base_command': base_cmd,
            'num_args': len(cmd_parts) - 1,
            'has_pipe': '|' in command,
            'has_redirect': '>' in command or '<' in command,
            'has_background': '&' in command,
            'has_semicolon': ';' in command,
            'category': self._categorize_command(base_cmd),
            'risk_score': self._calculate_risk(command, base_cmd),
            'is_obfuscated': self._is_obfuscated(command),
        }

        return results

    def _categorize_command(self, base_cmd: str) -> str:
        """Categorize a command."""
        if base_cmd in self.RECON_COMMANDS:
            return 'reconnaissance'
        if base_cmd in self.DOWNLOAD_COMMANDS:
            return 'download'
        if base_cmd in self.PERSISTENCE_COMMANDS:
            return 'persistence'
        if base_cmd in self.EXFIL_COMMANDS:
            return 'exfiltration'
        if base_cmd in self.PRIVESC_COMMANDS:
            return 'privilege_escalation'
        return 'other'

    def _calculate_risk(self, command: str, base_cmd: str) -> int:
        """Calculate risk score (0-10)."""
        score = 0

        # High-risk commands
        if base_cmd in self.DOWNLOAD_COMMANDS:
            score += 3
        if base_cmd in self.PERSISTENCE_COMMANDS:
            score += 4
        if base_cmd in self.PRIVESC_COMMANDS:
            score += 3

        # Dangerous patterns
        if '/dev/tcp' in command or '/dev/udp' in command:
            score += 5
        if 'base64' in command and ('|' in command or '-d' in command):
            score += 3
        if re.search(r'chmod\s+[47][0-7][0-7]', command):
            score += 2
        if '/tmp/' in command or '/var/tmp/' in command or '/dev/shm/' in command:
            score += 2

        return min(score, 10)

    def _is_obfuscated(self, command: str) -> bool:
        """Check if command appears obfuscated."""
        # Check for base64
        if re.search(r'base64\s+-d', command):
            return True
        # Check for hex encoding
        if re.search(r'\\x[0-9a-f]{2}', command, re.IGNORECASE):
            return True
        # Check for variable substitution tricks
        if re.search(r'\$\{[^}]+\}', command):
            return True
        # Check for excessive escaping
        if command.count('\\') > 5:
            return True
        return False

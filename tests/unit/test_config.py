"""
Unit tests for the configuration module.
"""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from core.config import (
    APIConfig,
    Config,
    DatabaseConfig,
    FTPConfig,
    HTTPConfig,
    LoggingConfig,
    SSHConfig,
    get_config,
    load_config,
    reload_config,
)


class TestSSHConfig:
    """Tests for SSH configuration."""

    def test_default_values(self):
        config = SSHConfig()
        assert config.enabled is True
        assert config.host == "0.0.0.0"
        assert config.port == 2222
        assert "OpenSSH" in config.banner

    def test_custom_values(self):
        config = SSHConfig(port=2200, enabled=False)
        assert config.port == 2200
        assert config.enabled is False


class TestHTTPConfig:
    """Tests for HTTP configuration."""

    def test_default_values(self):
        config = HTTPConfig()
        assert config.enabled is True
        assert config.port == 8080
        assert config.https_port == 8443
        assert config.ssl_enabled is False

    def test_ssl_config(self):
        config = HTTPConfig(
            ssl_enabled=True,
            ssl_cert_path="/path/to/cert.pem",
            ssl_key_path="/path/to/key.pem",
        )
        assert config.ssl_enabled is True
        assert config.ssl_cert_path == "/path/to/cert.pem"


class TestFTPConfig:
    """Tests for FTP configuration."""

    def test_default_values(self):
        config = FTPConfig()
        assert config.enabled is True
        assert config.port == 2121
        assert config.anonymous_enabled is True

    def test_passive_ports(self):
        config = FTPConfig(passive_ports=(50000, 50100))
        assert config.passive_ports == (50000, 50100)


class TestDatabaseConfig:
    """Tests for database configuration."""

    def test_explicit_postgresql_url(self):
        config = DatabaseConfig(url="postgresql+asyncpg://localhost/db")
        assert "postgresql" in config.url

    def test_explicit_sqlite_url(self):
        config = DatabaseConfig(url="sqlite+aiosqlite:///:memory:")
        assert "sqlite" in config.url

    def test_invalid_url(self):
        with pytest.raises(ValueError):
            DatabaseConfig(url="mysql://localhost/db")

    def test_pool_settings(self):
        config = DatabaseConfig(pool_size=20, max_overflow=30)
        assert config.pool_size == 20
        assert config.max_overflow == 30


class TestLoggingConfig:
    """Tests for logging configuration."""

    def test_default_level(self):
        config = LoggingConfig()
        assert config.level == "INFO"

    def test_valid_levels(self):
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            config = LoggingConfig(level=level)
            assert config.level == level

    def test_invalid_level(self):
        with pytest.raises(ValueError):
            LoggingConfig(level="INVALID")

    def test_case_insensitive_level(self):
        config = LoggingConfig(level="debug")
        assert config.level == "DEBUG"


class TestMainConfig:
    """Tests for main configuration class."""

    def test_explicit_config(self, monkeypatch):
        monkeypatch.delenv("MEPHALA_ENV", raising=False)
        monkeypatch.delenv("DEBUG", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)

        config = Config(env="development", debug=False)
        assert config.env == "development"
        assert config.debug is False
        assert isinstance(config.ssh, SSHConfig)
        assert isinstance(config.http, HTTPConfig)
        assert isinstance(config.ftp, FTPConfig)

    def test_environment_detection(self):
        # Test environment detection methods directly
        # Note: pydantic-settings env vars override explicit params
        config = Config.model_construct(env="production", debug=False)
        assert config.is_production() is True
        assert config.is_development() is False

        config = Config.model_construct(env="development", debug=False)
        assert config.is_production() is False
        assert config.is_development() is True

    def test_enabled_services(self):
        config = Config()
        services = config.get_enabled_services()
        assert "ssh" in services
        assert "http" in services
        assert "ftp" in services

    def test_disabled_services(self):
        ssh_config = SSHConfig(enabled=False)
        http_config = HTTPConfig(enabled=False)
        config = Config(ssh=ssh_config, http=http_config)
        services = config.get_enabled_services()
        assert "ssh" not in services
        assert "http" not in services
        assert "ftp" in services

    def test_from_yaml(self, monkeypatch):
        # Clear environment variables that might interfere
        monkeypatch.delenv("MEPHALA_ENV", raising=False)
        monkeypatch.delenv("DEBUG", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)

        yaml_content = {
            "ssh": {"port": 2200, "enabled": True},
            "http": {"port": 8888},
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            yaml.dump(yaml_content, f)
            temp_path = f.name

        try:
            config = Config.from_yaml(temp_path)
            # Note: env vars take precedence in pydantic-settings
            # Test that yaml values for sub-configs are loaded
            assert config.ssh.port == 2200
            assert config.http.port == 8888
        finally:
            os.unlink(temp_path)

    def test_from_yaml_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            Config.from_yaml("/nonexistent/path.yml")


class TestConfigLoading:
    """Tests for configuration loading functions."""

    def test_load_config_default(self):
        config = load_config()
        assert isinstance(config, Config)

    def test_reload_config(self):
        config1 = get_config()
        config2 = reload_config()
        assert isinstance(config2, Config)

    def test_load_config_from_yaml(self, monkeypatch):
        # Clear environment variables that might interfere
        monkeypatch.delenv("MEPHALA_ENV", raising=False)
        monkeypatch.delenv("DEBUG", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)

        yaml_content = {"ssh": {"port": 2299}}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            yaml.dump(yaml_content, f)
            temp_path = f.name

        try:
            config = load_config(temp_path)
            # Test that config was loaded from yaml
            assert config.ssh.port == 2299
        finally:
            os.unlink(temp_path)

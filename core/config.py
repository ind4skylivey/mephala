"""
Mephala Configuration Module

Configuration parser with YAML/ENV support and validation.
Uses Pydantic for type validation and settings management.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SSHConfig(BaseSettings):
    """SSH honeypot configuration."""

    model_config = SettingsConfigDict(env_prefix="SSH_")

    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 2222
    banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
    host_key_path: Optional[str] = None
    max_auth_attempts: int = 6
    login_timeout: int = 120
    fake_users: list[str] = Field(default_factory=lambda: ["root", "admin", "ubuntu", "user"])
    allowed_passwords: list[str] = Field(default_factory=lambda: ["password", "123456", "admin"])


class HTTPConfig(BaseSettings):
    """HTTP honeypot configuration."""

    model_config = SettingsConfigDict(env_prefix="HTTP_")

    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8080
    https_port: int = 8443
    ssl_enabled: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    server_header: str = "Apache/2.4.52 (Ubuntu)"
    max_request_size: int = 10 * 1024 * 1024  # 10MB


class FTPConfig(BaseSettings):
    """FTP honeypot configuration."""

    model_config = SettingsConfigDict(env_prefix="FTP_")

    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 2121
    passive_ports: tuple[int, int] = (60000, 60100)
    banner: str = "220 FTP Server ready"
    max_login_attempts: int = 3
    anonymous_enabled: bool = True


class DatabaseConfig(BaseSettings):
    """Database configuration."""

    model_config = SettingsConfigDict(env_prefix="DATABASE_")

    url: str = "postgresql+asyncpg://mephala:mephala@localhost:5432/mephala"
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("postgresql", "sqlite")):
            raise ValueError("Only PostgreSQL and SQLite databases are supported")
        return v


class RedisConfig(BaseSettings):
    """Redis configuration."""

    model_config = SettingsConfigDict(env_prefix="REDIS_")

    url: str = "redis://localhost:6379/0"
    max_connections: int = 10


class APIConfig(BaseSettings):
    """API configuration."""

    model_config = SettingsConfigDict(env_prefix="API_")

    host: str = "0.0.0.0"
    port: int = 8000
    secret_key: str = "change-this-to-a-secure-random-string"
    access_token_expire_minutes: int = 30
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    debug: bool = False


class LoggingConfig(BaseSettings):
    """Logging configuration."""

    model_config = SettingsConfigDict(env_prefix="LOG_")

    level: str = "INFO"
    format: str = "json"
    file: Optional[str] = "data/logs/mephala.log"
    max_size_mb: int = 100
    backup_count: int = 5
    console_output: bool = True

    @field_validator("level")
    @classmethod
    def validate_level(cls, v: str) -> str:
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level. Must be one of: {valid_levels}")
        return v.upper()


class MLConfig(BaseSettings):
    """Machine learning configuration."""

    model_config = SettingsConfigDict(env_prefix="ML_")

    model_path: str = "ml/models/"
    retrain_interval_hours: int = 24
    min_samples_for_training: int = 1000
    confidence_threshold: float = 0.7


class GeoIPConfig(BaseSettings):
    """GeoIP configuration."""

    model_config = SettingsConfigDict(env_prefix="GEOIP_")

    database_path: Optional[str] = "data/GeoLite2-City.mmdb"
    enabled: bool = True


class ThreatIntelConfig(BaseSettings):
    """Threat intelligence API configuration."""

    model_config = SettingsConfigDict(env_prefix="")

    abuseipdb_api_key: Optional[str] = Field(default=None, alias="ABUSEIPDB_API_KEY")
    virustotal_api_key: Optional[str] = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    cache_ttl_seconds: int = 3600


class Config(BaseSettings):
    """Main configuration class aggregating all settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Environment
    env: str = Field(default="development", alias="MEPHALA_ENV")
    debug: bool = Field(default=False, alias="DEBUG")

    # Sub-configurations
    ssh: SSHConfig = Field(default_factory=SSHConfig)
    http: HTTPConfig = Field(default_factory=HTTPConfig)
    ftp: FTPConfig = Field(default_factory=FTPConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    ml: MLConfig = Field(default_factory=MLConfig)
    geoip: GeoIPConfig = Field(default_factory=GeoIPConfig)
    threat_intel: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Config":
        """Load configuration from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(path) as f:
            yaml_config = yaml.safe_load(f)

        return cls(**yaml_config) if yaml_config else cls()

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        return cls()

    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.env.lower() == "production"

    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.env.lower() == "development"

    def get_enabled_services(self) -> list[str]:
        """Get list of enabled honeypot services."""
        services = []
        if self.ssh.enabled:
            services.append("ssh")
        if self.http.enabled:
            services.append("http")
        if self.ftp.enabled:
            services.append("ftp")
        return services


_config: Optional[Config] = None


def load_config(yaml_path: Optional[str | Path] = None) -> Config:
    """Load and cache the configuration."""
    global _config

    if yaml_path:
        _config = Config.from_yaml(yaml_path)
    else:
        config_path = os.getenv("MEPHALA_CONFIG")
        if config_path and Path(config_path).exists():
            _config = Config.from_yaml(config_path)
        else:
            _config = Config.from_env()

    return _config


@lru_cache
def get_config() -> Config:
    """Get the cached configuration instance."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config(yaml_path: Optional[str | Path] = None) -> Config:
    """Reload configuration (clears cache)."""
    global _config
    get_config.cache_clear()
    return load_config(yaml_path)

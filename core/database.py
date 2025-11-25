"""
HoneyTrap Database Module

SQLAlchemy async ORM models and session management.
Implements the complete database schema for attack logging and analysis.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from decimal import Decimal
from typing import AsyncGenerator, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


class Attack(Base):
    """Main attacks table - records all detected attack events."""

    __tablename__ = "attacks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Temporal data
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), index=True
    )
    duration_seconds: Mapped[Optional[Decimal]] = mapped_column(Numeric(10, 3))

    # Network information
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer)
    protocol: Mapped[Optional[str]] = mapped_column(String(10))

    # Service and classification
    service_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    attack_type: Mapped[Optional[str]] = mapped_column(String(50), index=True)
    attack_subtype: Mapped[Optional[str]] = mapped_column(String(100))

    # Severity and confidence
    severity: Mapped[Optional[int]] = mapped_column(
        Integer, CheckConstraint("severity BETWEEN 1 AND 10")
    )
    ml_confidence: Mapped[Optional[Decimal]] = mapped_column(Numeric(5, 4))

    # Geolocation data
    country_code: Mapped[Optional[str]] = mapped_column(String(2))
    country_name: Mapped[Optional[str]] = mapped_column(String(100))
    city: Mapped[Optional[str]] = mapped_column(String(100))
    latitude: Mapped[Optional[Decimal]] = mapped_column(Numeric(10, 8))
    longitude: Mapped[Optional[Decimal]] = mapped_column(Numeric(11, 8))
    asn: Mapped[Optional[int]] = mapped_column(Integer)
    isp: Mapped[Optional[str]] = mapped_column(String(255))

    # Raw data storage
    raw_log: Mapped[Optional[str]] = mapped_column(Text)
    metadata: Mapped[Optional[dict]] = mapped_column(JSONB)

    # Relationships
    credentials: Mapped[list["Credential"]] = relationship(
        back_populates="attack", cascade="all, delete-orphan"
    )
    http_requests: Mapped[list["HttpRequest"]] = relationship(
        back_populates="attack", cascade="all, delete-orphan"
    )
    commands: Mapped[list["Command"]] = relationship(
        back_populates="attack", cascade="all, delete-orphan"
    )
    files: Mapped[list["File"]] = relationship(
        back_populates="attack", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="attack", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_attacks_timestamp_desc", timestamp.desc()),
        Index("ix_attacks_source_ip_service", source_ip, service_type),
    )


class Credential(Base):
    """Credentials table - SSH/FTP authentication attempts."""

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attack_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("attacks.id", ondelete="CASCADE"), nullable=False
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )
    username: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[Optional[str]] = mapped_column(String(64), index=True)

    auth_method: Mapped[Optional[str]] = mapped_column(String(50))
    success: Mapped[bool] = mapped_column(Boolean, default=False)

    # Pattern detection
    is_default_credential: Mapped[bool] = mapped_column(Boolean, default=False)
    is_dictionary_word: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationship
    attack: Mapped["Attack"] = relationship(back_populates="credentials")


class HttpRequest(Base):
    """HTTP requests table - captured HTTP/HTTPS requests."""

    __tablename__ = "http_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attack_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("attacks.id", ondelete="CASCADE"), nullable=False
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    query_string: Mapped[Optional[str]] = mapped_column(Text)

    # Headers and body
    headers: Mapped[Optional[dict]] = mapped_column(JSONB)
    body: Mapped[Optional[str]] = mapped_column(Text)
    body_size: Mapped[Optional[int]] = mapped_column(Integer)

    # Request analysis
    user_agent: Mapped[Optional[str]] = mapped_column(Text, index=True)
    referer: Mapped[Optional[str]] = mapped_column(Text)
    content_type: Mapped[Optional[str]] = mapped_column(String(100))

    # Response information
    response_status: Mapped[Optional[int]] = mapped_column(Integer)
    response_size: Mapped[Optional[int]] = mapped_column(Integer)

    # Threat indicators
    contains_sql_injection: Mapped[bool] = mapped_column(Boolean, default=False)
    contains_xss: Mapped[bool] = mapped_column(Boolean, default=False)
    contains_path_traversal: Mapped[bool] = mapped_column(Boolean, default=False)
    contains_rce_attempt: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationship
    attack: Mapped["Attack"] = relationship(back_populates="http_requests")

    __table_args__ = (Index("ix_http_requests_method_path", method, path),)


class Command(Base):
    """Commands table - SSH/shell commands executed."""

    __tablename__ = "commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attack_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("attacks.id", ondelete="CASCADE"), nullable=False
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), index=True
    )
    command: Mapped[str] = mapped_column(Text, nullable=False)
    arguments: Mapped[Optional[str]] = mapped_column(Text)
    full_command_line: Mapped[Optional[str]] = mapped_column(Text)

    # Command analysis
    command_type: Mapped[Optional[str]] = mapped_column(String(50))
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    is_automated: Mapped[bool] = mapped_column(Boolean, default=False)

    # Execution context
    working_directory: Mapped[Optional[str]] = mapped_column(String(255))
    exit_code: Mapped[Optional[int]] = mapped_column(Integer)

    # Output
    output: Mapped[Optional[str]] = mapped_column(Text)
    error_output: Mapped[Optional[str]] = mapped_column(Text)
    execution_time_ms: Mapped[Optional[int]] = mapped_column(Integer)

    # Relationship
    attack: Mapped["Attack"] = relationship(back_populates="commands")


class File(Base):
    """Files table - uploaded/downloaded files."""

    __tablename__ = "files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attack_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("attacks.id", ondelete="CASCADE"), nullable=False
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )
    operation: Mapped[str] = mapped_column(String(20), nullable=False)

    # File metadata
    filename: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    original_path: Mapped[Optional[str]] = mapped_column(Text)
    file_extension: Mapped[Optional[str]] = mapped_column(String(20))
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)

    # File hashing
    md5_hash: Mapped[Optional[str]] = mapped_column(String(32))
    sha1_hash: Mapped[Optional[str]] = mapped_column(String(40))
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # File storage
    storage_path: Mapped[Optional[str]] = mapped_column(String(500))
    content: Mapped[Optional[bytes]] = mapped_column(LargeBinary)

    # Malware analysis
    is_malware: Mapped[bool] = mapped_column(Boolean, default=False)
    malware_family: Mapped[Optional[str]] = mapped_column(String(100))
    virustotal_detections: Mapped[Optional[int]] = mapped_column(Integer)
    virustotal_results: Mapped[Optional[dict]] = mapped_column(JSONB)

    # MIME type detection
    mime_type: Mapped[Optional[str]] = mapped_column(String(100))
    magic_signature: Mapped[Optional[str]] = mapped_column(String(255))

    # Relationship
    attack: Mapped["Attack"] = relationship(back_populates="files")

    __table_args__ = (UniqueConstraint("sha256_hash", name="uq_files_sha256"),)


class IpReputation(Base):
    """IP reputation table - threat intelligence data."""

    __tablename__ = "ip_reputation"

    ip: Mapped[str] = mapped_column(String(45), primary_key=True)

    # Threat intelligence scores
    abuseipdb_score: Mapped[Optional[int]] = mapped_column(
        Integer, CheckConstraint("abuseipdb_score BETWEEN 0 AND 100"), index=True
    )
    abuseipdb_reports: Mapped[Optional[int]] = mapped_column(Integer)
    abuseipdb_last_reported: Mapped[Optional[datetime]] = mapped_column(DateTime)

    virustotal_malicious_count: Mapped[Optional[int]] = mapped_column(Integer)
    virustotal_suspicious_count: Mapped[Optional[int]] = mapped_column(Integer)
    virustotal_harmless_count: Mapped[Optional[int]] = mapped_column(Integer)

    # Metadata
    is_tor_exit_node: Mapped[bool] = mapped_column(Boolean, default=False)
    is_vpn: Mapped[bool] = mapped_column(Boolean, default=False)
    is_proxy: Mapped[bool] = mapped_column(Boolean, default=False)
    is_hosting_provider: Mapped[bool] = mapped_column(Boolean, default=False)

    # Attack history
    first_seen: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), index=True
    )
    total_attacks: Mapped[int] = mapped_column(Integer, default=1)

    # Cache management
    last_updated: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )
    cache_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)


class MlModel(Base):
    """ML models table - model versioning and metadata."""

    __tablename__ = "ml_models"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    model_type: Mapped[Optional[str]] = mapped_column(String(50))

    # Performance metrics
    accuracy: Mapped[Optional[Decimal]] = mapped_column(Numeric(5, 4))
    precision: Mapped[Optional[Decimal]] = mapped_column(Numeric(5, 4))
    recall: Mapped[Optional[Decimal]] = mapped_column(Numeric(5, 4))
    f1_score: Mapped[Optional[Decimal]] = mapped_column(Numeric(5, 4))

    # Training metadata
    training_samples: Mapped[Optional[int]] = mapped_column(Integer)
    training_duration_seconds: Mapped[Optional[int]] = mapped_column(Integer)
    trained_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), index=True
    )
    trained_by: Mapped[Optional[str]] = mapped_column(String(100))

    # Deployment
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    deployed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Model storage
    model_path: Mapped[Optional[str]] = mapped_column(String(500))
    model_data: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
    hyperparameters: Mapped[Optional[dict]] = mapped_column(JSONB)
    feature_names: Mapped[Optional[dict]] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_ml_models_name_version"),
    )


class Session(Base):
    """Sessions table - track attacker sessions."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    session_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    service_type: Mapped[str] = mapped_column(String(20), nullable=False)

    # Session lifecycle
    started_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), index=True
    )
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer)

    # Session statistics
    total_commands: Mapped[int] = mapped_column(Integer, default=0)
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    total_uploads: Mapped[int] = mapped_column(Integer, default=0)
    total_downloads: Mapped[int] = mapped_column(Integer, default=0)

    # User behavior
    was_successful_login: Mapped[bool] = mapped_column(Boolean, default=False)
    escalated_privileges: Mapped[bool] = mapped_column(Boolean, default=False)


class Alert(Base):
    """Alerts table - automated alert management."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attack_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("attacks.id", ondelete="CASCADE")
    )

    # Alert metadata
    alert_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), index=True
    )
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Assignment
    assigned_to: Mapped[Optional[str]] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)

    # Notification tracking
    email_sent: Mapped[bool] = mapped_column(Boolean, default=False)
    webhook_sent: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationship
    attack: Mapped[Optional["Attack"]] = relationship(back_populates="alerts")


class User(Base):
    """Users table - dashboard authentication."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime)


class DatabaseManager:
    """Async database connection and session management."""

    def __init__(
        self,
        database_url: str,
        pool_size: int = 10,
        max_overflow: int = 20,
        echo: bool = False,
    ):
        self._database_url = database_url
        self._pool_size = pool_size
        self._max_overflow = max_overflow
        self._echo = echo
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker[AsyncSession]] = None

    async def initialize(self) -> None:
        """Initialize the database engine and session factory."""
        self._engine = create_async_engine(
            self._database_url,
            pool_size=self._pool_size,
            max_overflow=self._max_overflow,
            echo=self._echo,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    async def close(self) -> None:
        """Close the database engine and release connections."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Provide a transactional scope for database operations."""
        if not self._session_factory:
            raise RuntimeError("Database not initialized. Call initialize() first.")

        session = self._session_factory()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    async def create_tables(self) -> None:
        """Create all tables (for development/testing only)."""
        if not self._engine:
            raise RuntimeError("Database not initialized. Call initialize() first.")

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_tables(self) -> None:
        """Drop all tables (for development/testing only)."""
        if not self._engine:
            raise RuntimeError("Database not initialized. Call initialize() first.")

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    @property
    def engine(self) -> Optional[AsyncEngine]:
        """Get the underlying async engine."""
        return self._engine


_db_manager: Optional[DatabaseManager] = None


async def get_db_manager() -> DatabaseManager:
    """Get the global database manager instance."""
    global _db_manager
    if _db_manager is None:
        raise RuntimeError("Database manager not initialized.")
    return _db_manager


async def init_database(
    database_url: str,
    pool_size: int = 10,
    max_overflow: int = 20,
    echo: bool = False,
) -> DatabaseManager:
    """Initialize the global database manager."""
    global _db_manager
    _db_manager = DatabaseManager(
        database_url=database_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        echo=echo,
    )
    await _db_manager.initialize()
    return _db_manager


async def close_database() -> None:
    """Close the global database manager."""
    global _db_manager
    if _db_manager:
        await _db_manager.close()
        _db_manager = None


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get a database session from the global manager."""
    db = await get_db_manager()
    async with db.session() as session:
        yield session

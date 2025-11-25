"""
Pytest configuration and fixtures for Mephala tests.
"""

import asyncio
import os
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Set test environment
os.environ["MEPHALA_ENV"] = "testing"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

from core.config import Config, reload_config
from core.database import Base, DatabaseManager


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_config() -> Config:
    """Create a test configuration."""
    return Config(
        env="testing",
        debug=True,
        ssh=Config.model_fields["ssh"].default_factory(),
        http=Config.model_fields["http"].default_factory(),
        ftp=Config.model_fields["ftp"].default_factory(),
        database=Config.model_fields["database"].default_factory(),
        redis=Config.model_fields["redis"].default_factory(),
        api=Config.model_fields["api"].default_factory(),
        logging=Config.model_fields["logging"].default_factory(),
        ml=Config.model_fields["ml"].default_factory(),
        geoip=Config.model_fields["geoip"].default_factory(),
        threat_intel=Config.model_fields["threat_intel"].default_factory(),
    )


@pytest_asyncio.fixture
async def db_engine():
    """Create a test database engine with SQLite in-memory."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async_session_factory = sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    async with async_session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def db_manager(db_engine) -> AsyncGenerator[DatabaseManager, None]:
    """Create a test database manager."""
    manager = DatabaseManager.__new__(DatabaseManager)
    manager._engine = db_engine
    manager._session_factory = sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    yield manager


@pytest.fixture
def mock_stream_reader() -> AsyncMock:
    """Create a mock StreamReader."""
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=b"")
    reader.readline = AsyncMock(return_value=b"")
    reader.readexactly = AsyncMock(return_value=b"")
    reader.at_eof = MagicMock(return_value=False)
    return reader


@pytest.fixture
def mock_stream_writer() -> MagicMock:
    """Create a mock StreamWriter."""
    writer = MagicMock()
    writer.write = MagicMock()
    writer.writelines = MagicMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    writer.drain = AsyncMock()
    writer.get_extra_info = MagicMock(return_value=("192.168.1.100", 12345))
    writer.is_closing = MagicMock(return_value=False)
    return writer


@pytest.fixture
def sample_attack_data() -> dict:
    """Sample attack data for testing."""
    return {
        "source_ip": "192.168.1.100",
        "source_port": 54321,
        "destination_port": 22,
        "protocol": "TCP",
        "service_type": "ssh",
        "attack_type": "brute_force",
        "severity": 5,
    }


@pytest.fixture
def sample_credential_data() -> dict:
    """Sample credential data for testing."""
    return {
        "username": "root",
        "password": "password123",
        "auth_method": "password",
        "success": False,
    }


@pytest.fixture
def sample_http_request_data() -> dict:
    """Sample HTTP request data for testing."""
    return {
        "method": "GET",
        "path": "/admin/login.php",
        "query_string": "user=admin",
        "headers": {"User-Agent": "Mozilla/5.0", "Host": "localhost"},
        "user_agent": "Mozilla/5.0",
    }


@pytest.fixture
def sample_command_data() -> dict:
    """Sample command data for testing."""
    return {
        "command": "cat",
        "arguments": "/etc/passwd",
        "command_type": "recon",
        "is_malicious": True,
        "working_directory": "/home/user",
    }


@pytest.fixture
def malicious_payloads() -> dict:
    """Collection of malicious payloads for testing detection."""
    return {
        "sql_injection": [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "1' AND SLEEP(5)--",
        ],
        "xss": [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert(document.cookie)",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "....//....//etc/shadow",
            "%2e%2e%2f%2e%2e%2fetc/passwd",
        ],
        "rce": [
            "; cat /etc/passwd",
            "| whoami",
            "`id`",
            "$(cat /etc/shadow)",
            "/bin/bash -c 'ls'",
        ],
    }

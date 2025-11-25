"""
Unit tests for the logging module.
"""

import logging
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.logger import (
    ServiceLogger,
    add_service_context,
    add_timestamp,
    censor_sensitive_data,
    get_logger,
    setup_logging,
)


class TestLogProcessors:
    """Tests for log processors."""

    def test_add_timestamp(self):
        event_dict = {"event": "test"}
        result = add_timestamp(None, "info", event_dict)
        assert "timestamp" in result
        assert result["timestamp"].endswith("Z")

    def test_add_service_context_default(self):
        event_dict = {"event": "test"}
        result = add_service_context(None, "info", event_dict)
        assert result["service"] == "mephala"

    def test_add_service_context_existing(self):
        event_dict = {"event": "test", "service": "ssh"}
        result = add_service_context(None, "info", event_dict)
        assert result["service"] == "ssh"

    def test_censor_sensitive_data(self):
        event_dict = {
            "event": "test",
            "password": "secret123",
            "api_key": "key123",
            "token": "tok123",
            "user_password": "pass",
            "normal_field": "visible",
        }
        result = censor_sensitive_data(None, "info", event_dict)

        assert result["password"] == "***REDACTED***"
        assert result["api_key"] == "***REDACTED***"
        assert result["token"] == "***REDACTED***"
        assert result["user_password"] == "***REDACTED***"
        assert result["normal_field"] == "visible"


class TestSetupLogging:
    """Tests for logging setup."""

    def test_setup_logging_default(self):
        setup_logging()
        logger = logging.getLogger()
        assert logger.level == logging.INFO

    def test_setup_logging_debug_level(self):
        # Reset configured state for testing
        import core.logger
        core.logger._configured = False

        setup_logging(level="DEBUG")
        logger = logging.getLogger()
        assert logger.level == logging.DEBUG

        core.logger._configured = False

    def test_setup_logging_with_file(self):
        import core.logger
        core.logger._configured = False

        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.log"
            setup_logging(log_file=str(log_file))
            assert log_file.parent.exists()

        core.logger._configured = False

    def test_setup_logging_json_format(self):
        import core.logger
        core.logger._configured = False

        setup_logging(log_format="json")
        # Should not raise any errors
        logger = get_logger("test")
        assert logger is not None

        core.logger._configured = False

    def test_setup_logging_text_format(self):
        import core.logger
        core.logger._configured = False

        setup_logging(log_format="text")
        logger = get_logger("test")
        assert logger is not None

        core.logger._configured = False


class TestGetLogger:
    """Tests for get_logger function."""

    def test_get_logger_default(self):
        logger = get_logger()
        assert logger is not None

    def test_get_logger_with_name(self):
        logger = get_logger("test.module")
        assert logger is not None

    def test_get_logger_with_context(self):
        logger = get_logger("test", service="ssh", port=2222)
        assert logger is not None


class TestServiceLogger:
    """Tests for ServiceLogger class."""

    def test_service_logger_creation(self):
        logger = ServiceLogger("ssh", 2222)
        assert logger is not None

    def test_service_logger_bind(self):
        logger = ServiceLogger("ssh", 2222)
        bound_logger = logger.bind(session_id="test123")
        assert bound_logger is not None
        assert bound_logger is not logger

    def test_service_logger_debug(self):
        logger = ServiceLogger("ssh", 2222)
        # Should not raise
        logger.debug("test message", extra_field="value")

    def test_service_logger_info(self):
        logger = ServiceLogger("ssh", 2222)
        logger.info("test message")

    def test_service_logger_warning(self):
        logger = ServiceLogger("ssh", 2222)
        logger.warning("test warning")

    def test_service_logger_error(self):
        logger = ServiceLogger("ssh", 2222)
        logger.error("test error")

    def test_service_logger_critical(self):
        logger = ServiceLogger("ssh", 2222)
        logger.critical("test critical")

    def test_service_logger_connection(self):
        logger = ServiceLogger("ssh", 2222)
        logger.connection(
            source_ip="192.168.1.100",
            source_port=54321,
            event="new_connection",
        )

    def test_service_logger_attack(self):
        logger = ServiceLogger("ssh", 2222)
        logger.attack(
            source_ip="192.168.1.100",
            attack_type="brute_force",
            severity=5,
        )

    def test_service_logger_credential_attempt(self):
        logger = ServiceLogger("ssh", 2222)
        logger.credential_attempt(
            source_ip="192.168.1.100",
            username="root",
            success=False,
        )

"""
Mephala Logging Module

Centralized structured logging system with async support.
Supports JSON and text formatting, file rotation, and console output.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

import structlog
from structlog.types import EventDict, Processor

_configured = False


def add_timestamp(
    logger: logging.Logger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add ISO format timestamp to log events."""
    event_dict["timestamp"] = datetime.utcnow().isoformat() + "Z"
    return event_dict


def add_service_context(
    logger: logging.Logger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add service context if available."""
    if "service" not in event_dict:
        event_dict["service"] = "mephala"
    return event_dict


def censor_sensitive_data(
    logger: logging.Logger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Remove or mask sensitive data from logs."""
    sensitive_keys = {"password", "secret", "token", "api_key", "credential"}
    for key in list(event_dict.keys()):
        if any(s in key.lower() for s in sensitive_keys):
            event_dict[key] = "***REDACTED***"
    return event_dict


class AsyncLogHandler(logging.Handler):
    """Async-safe log handler that queues log records."""

    def __init__(self, handler: logging.Handler):
        super().__init__()
        self._handler = handler
        self._queue: asyncio.Queue[logging.LogRecord] = asyncio.Queue()
        self._task: Optional[asyncio.Task] = None

    def emit(self, record: logging.LogRecord) -> None:
        """Queue the log record for async processing."""
        try:
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            self._handler.emit(record)

    async def start(self) -> None:
        """Start the async log processing task."""
        if self._task is None:
            self._task = asyncio.create_task(self._process_logs())

    async def stop(self) -> None:
        """Stop the async log processing task."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _process_logs(self) -> None:
        """Process queued log records."""
        while True:
            try:
                record = await self._queue.get()
                self._handler.emit(record)
                self._queue.task_done()
            except asyncio.CancelledError:
                while not self._queue.empty():
                    try:
                        record = self._queue.get_nowait()
                        self._handler.emit(record)
                    except asyncio.QueueEmpty:
                        break
                raise


def setup_logging(
    level: str = "INFO",
    log_format: str = "json",
    log_file: Optional[str] = None,
    max_size_mb: int = 100,
    backup_count: int = 5,
    console_output: bool = True,
) -> None:
    """
    Set up the logging system.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Output format ('json' or 'text')
        log_file: Path to log file (optional)
        max_size_mb: Maximum log file size in MB before rotation
        backup_count: Number of backup files to keep
        console_output: Whether to output to console
    """
    global _configured
    if _configured:
        return

    # Configure standard logging
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Define processors based on format
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        add_timestamp,
        add_service_context,
        censor_sensitive_data,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if log_format == "json":
        shared_processors.append(structlog.processors.format_exc_info)
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    # Configure structlog
    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Create formatter
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    # File handler with rotation
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # Suppress noisy loggers
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("asyncssh").setLevel(logging.WARNING)

    _configured = True


def get_logger(name: Optional[str] = None, **context: Any) -> structlog.stdlib.BoundLogger:
    """
    Get a structured logger instance.

    Args:
        name: Logger name (usually __name__)
        **context: Additional context to bind to the logger

    Returns:
        A configured structlog logger
    """
    if not _configured:
        setup_logging()

    logger = structlog.get_logger(name)
    if context:
        logger = logger.bind(**context)
    return logger


class ServiceLogger:
    """Logger wrapper for honeypot services with service-specific context."""

    def __init__(self, service_name: str, service_port: int):
        self._logger = get_logger(
            f"mephala.{service_name}",
            service=service_name,
            port=service_port,
        )

    def bind(self, **context: Any) -> "ServiceLogger":
        """Create a new logger with additional context."""
        new_logger = ServiceLogger.__new__(ServiceLogger)
        new_logger._logger = self._logger.bind(**context)
        return new_logger

    def debug(self, event: str, **kw: Any) -> None:
        self._logger.debug(event, **kw)

    def info(self, event: str, **kw: Any) -> None:
        self._logger.info(event, **kw)

    def warning(self, event: str, **kw: Any) -> None:
        self._logger.warning(event, **kw)

    def error(self, event: str, **kw: Any) -> None:
        self._logger.error(event, **kw)

    def critical(self, event: str, **kw: Any) -> None:
        self._logger.critical(event, **kw)

    def exception(self, event: str, **kw: Any) -> None:
        self._logger.exception(event, **kw)

    def connection(
        self,
        source_ip: str,
        source_port: int,
        event: str = "connection",
        **kw: Any,
    ) -> None:
        """Log a connection event."""
        self._logger.info(
            event,
            source_ip=source_ip,
            source_port=source_port,
            **kw,
        )

    def attack(
        self,
        source_ip: str,
        attack_type: str,
        severity: int,
        **kw: Any,
    ) -> None:
        """Log an attack event."""
        self._logger.warning(
            "attack_detected",
            source_ip=source_ip,
            attack_type=attack_type,
            severity=severity,
            **kw,
        )

    def credential_attempt(
        self,
        source_ip: str,
        username: str,
        success: bool = False,
        **kw: Any,
    ) -> None:
        """Log a credential attempt."""
        self._logger.info(
            "credential_attempt",
            source_ip=source_ip,
            username=username,
            success=success,
            **kw,
        )

"""
Mephala Main Orchestrator

Manages all honeypot services lifecycle, coordinates startup/shutdown,
and handles graceful termination.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from typing import Optional

from core.base_service import BaseHoneypotService
from core.config import Config, get_config, load_config
from core.database import close_database, init_database
from core.logger import get_logger, setup_logging


class HoneypotOrchestrator:
    """
    Main orchestrator for managing honeypot services.

    Handles service registration, lifecycle management, and graceful shutdown.
    """

    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the orchestrator.

        Args:
            config: Configuration object. If None, loads from environment.
        """
        self._config = config or get_config()
        self._services: dict[str, BaseHoneypotService] = {}
        self._running = False
        self._shutdown_event = asyncio.Event()
        self._logger = get_logger("mephala.orchestrator")

    @property
    def is_running(self) -> bool:
        """Check if the orchestrator is running."""
        return self._running

    @property
    def services(self) -> dict[str, BaseHoneypotService]:
        """Get registered services."""
        return self._services.copy()

    def register_service(self, service: BaseHoneypotService) -> None:
        """
        Register a honeypot service.

        Args:
            service: Service instance to register
        """
        if service.service_name in self._services:
            raise ValueError(f"Service '{service.service_name}' already registered")

        self._services[service.service_name] = service
        self._logger.info(
            "service_registered",
            service=service.service_name,
            port=service.port,
        )

    def unregister_service(self, service_name: str) -> None:
        """
        Unregister a honeypot service.

        Args:
            service_name: Name of the service to unregister
        """
        if service_name in self._services:
            del self._services[service_name]
            self._logger.info("service_unregistered", service=service_name)

    async def start(self) -> None:
        """
        Start all registered honeypot services.

        Sets up signal handlers and starts services concurrently.
        """
        if self._running:
            self._logger.warning("orchestrator_already_running")
            return

        self._logger.info(
            "orchestrator_starting",
            services=list(self._services.keys()),
            env=self._config.env,
        )

        # Initialize database
        await init_database(
            database_url=self._config.database.url,
            pool_size=self._config.database.pool_size,
            max_overflow=self._config.database.max_overflow,
            echo=self._config.database.echo,
        )
        self._logger.info("database_initialized")

        # Set up signal handlers
        self._setup_signal_handlers()

        # Start all services concurrently
        self._running = True
        start_tasks = [
            asyncio.create_task(self._start_service(name, service))
            for name, service in self._services.items()
        ]

        if start_tasks:
            results = await asyncio.gather(*start_tasks, return_exceptions=True)
            for name, result in zip(self._services.keys(), results):
                if isinstance(result, Exception):
                    self._logger.error(
                        "service_start_failed",
                        service=name,
                        error=str(result),
                    )

        self._logger.info(
            "orchestrator_started",
            active_services=[
                name for name, svc in self._services.items() if svc.is_running
            ],
        )

    async def _start_service(
        self, name: str, service: BaseHoneypotService
    ) -> None:
        """Start a single service with error handling."""
        try:
            await service.start()
            self._logger.info("service_started", service=name, port=service.port)
        except Exception as e:
            self._logger.error(
                "service_start_error",
                service=name,
                error=str(e),
                exc_info=True,
            )
            raise

    async def stop(self) -> None:
        """
        Stop all services gracefully.

        Waits for services to complete shutdown within a timeout.
        """
        if not self._running:
            return

        self._logger.info("orchestrator_stopping")
        self._running = False

        # Stop all services concurrently
        stop_tasks = [
            asyncio.create_task(self._stop_service(name, service))
            for name, service in self._services.items()
        ]

        if stop_tasks:
            # Wait with timeout
            try:
                await asyncio.wait_for(
                    asyncio.gather(*stop_tasks, return_exceptions=True),
                    timeout=30.0,
                )
            except asyncio.TimeoutError:
                self._logger.warning("service_stop_timeout")

        # Close database connection
        await close_database()
        self._logger.info("database_closed")

        self._shutdown_event.set()
        self._logger.info("orchestrator_stopped")

    async def _stop_service(
        self, name: str, service: BaseHoneypotService
    ) -> None:
        """Stop a single service with error handling."""
        try:
            await service.stop()
            self._logger.info("service_stopped", service=name)
        except Exception as e:
            self._logger.error(
                "service_stop_error",
                service=name,
                error=str(e),
            )

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        loop = asyncio.get_running_loop()

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(
                sig,
                lambda s=sig: asyncio.create_task(self._handle_signal(s)),
            )

    async def _handle_signal(self, sig: signal.Signals) -> None:
        """Handle termination signals."""
        self._logger.info("signal_received", signal=sig.name)
        await self.stop()

    async def wait_for_shutdown(self) -> None:
        """Wait for the shutdown event."""
        await self._shutdown_event.wait()

    async def run_forever(self) -> None:
        """
        Run the orchestrator until shutdown signal.

        Convenience method that starts services and waits for termination.
        """
        await self.start()
        await self.wait_for_shutdown()

    async def health_check(self) -> dict:
        """
        Perform health check on all services.

        Returns:
            Dictionary with overall health status
        """
        service_health = {}
        for name, service in self._services.items():
            service_health[name] = await service.health_check()

        all_healthy = all(
            s.get("status") == "healthy" for s in service_health.values()
        )

        return {
            "status": "healthy" if all_healthy else "degraded",
            "running": self._running,
            "services": service_health,
            "total_connections": sum(
                s.get("connections", 0) for s in service_health.values()
            ),
        }

    async def get_stats(self) -> dict:
        """
        Get statistics from all services.

        Returns:
            Dictionary with aggregated statistics
        """
        stats = {
            "running": self._running,
            "services": {},
            "total_connections": 0,
        }

        for name, service in self._services.items():
            health = await service.health_check()
            stats["services"][name] = health
            stats["total_connections"] += health.get("connections", 0)

        return stats


async def create_orchestrator(
    config_path: Optional[str] = None,
) -> HoneypotOrchestrator:
    """
    Create and configure the honeypot orchestrator.

    Args:
        config_path: Optional path to YAML configuration file

    Returns:
        Configured HoneypotOrchestrator instance
    """
    # Load configuration
    config = load_config(config_path)

    # Set up logging
    setup_logging(
        level=config.logging.level,
        log_format=config.logging.format,
        log_file=config.logging.file,
        max_size_mb=config.logging.max_size_mb,
        backup_count=config.logging.backup_count,
        console_output=config.logging.console_output,
    )

    # Create orchestrator
    orchestrator = HoneypotOrchestrator(config)

    return orchestrator


async def main(config_path: Optional[str] = None) -> None:
    """
    Main entry point for running Mephala.

    Args:
        config_path: Optional path to configuration file
    """
    orchestrator = await create_orchestrator(config_path)

    # Import and register services based on configuration
    config = get_config()

    if config.ssh.enabled:
        try:
            from services.ssh_honeypot import SSHHoneypot

            orchestrator.register_service(SSHHoneypot(config))
        except ImportError:
            get_logger().warning("SSH honeypot module not available")

    if config.http.enabled:
        try:
            from services.http_honeypot import HTTPHoneypot

            orchestrator.register_service(HTTPHoneypot(config))
        except ImportError:
            get_logger().warning("HTTP honeypot module not available")

    if config.ftp.enabled:
        try:
            from services.ftp_honeypot import FTPHoneypot

            orchestrator.register_service(FTPHoneypot(config))
        except ImportError:
            get_logger().warning("FTP honeypot module not available")

    # Run until shutdown
    await orchestrator.run_forever()


if __name__ == "__main__":
    config_file = sys.argv[1] if len(sys.argv) > 1 else None
    asyncio.run(main(config_file))

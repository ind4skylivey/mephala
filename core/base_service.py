"""
HoneyTrap Base Service Module

Abstract base class for all honeypot services.
Defines the interface and common functionality for SSH, HTTP, FTP honeypots.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from decimal import Decimal
from typing import Any, Optional

from core.config import Config
from core.database import (
    Attack,
    Command,
    Credential,
    File,
    HttpRequest,
    Session,
    get_session,
)
from core.logger import ServiceLogger


class BaseHoneypotService(ABC):
    """
    Abstract base class for honeypot services.

    All honeypot implementations (SSH, HTTP, FTP) must inherit from this class
    and implement the required abstract methods.
    """

    def __init__(self, config: Config):
        """
        Initialize the base honeypot service.

        Args:
            config: Application configuration
        """
        self._config = config
        self._running = False
        self._server: Optional[Any] = None
        self._connections: dict[str, datetime] = {}
        self._logger = ServiceLogger(self.service_name, self.port)

    @property
    @abstractmethod
    def service_name(self) -> str:
        """Return the service name (e.g., 'ssh', 'http', 'ftp')."""
        pass

    @property
    @abstractmethod
    def port(self) -> int:
        """Return the port number the service listens on."""
        pass

    @property
    @abstractmethod
    def protocol(self) -> str:
        """Return the protocol (e.g., 'TCP', 'UDP')."""
        pass

    @property
    def is_running(self) -> bool:
        """Check if the service is currently running."""
        return self._running

    @property
    def connection_count(self) -> int:
        """Get the current number of active connections."""
        return len(self._connections)

    @abstractmethod
    async def start(self) -> None:
        """
        Start the honeypot service.

        This method should set up the server and begin accepting connections.
        Must be implemented by subclasses.
        """
        pass

    @abstractmethod
    async def stop(self) -> None:
        """
        Stop the honeypot service gracefully.

        This method should close all connections and release resources.
        Must be implemented by subclasses.
        """
        pass

    @abstractmethod
    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handle an incoming connection.

        Args:
            reader: Async stream reader for incoming data
            writer: Async stream writer for outgoing data
        """
        pass

    def _generate_session_id(self) -> str:
        """Generate a unique session identifier."""
        return str(uuid.uuid4())

    def _get_client_info(
        self, writer: asyncio.StreamWriter
    ) -> tuple[str, int]:
        """
        Extract client IP and port from the stream writer.

        Args:
            writer: Async stream writer

        Returns:
            Tuple of (ip_address, port)
        """
        peername = writer.get_extra_info("peername")
        if peername:
            return peername[0], peername[1]
        return "unknown", 0

    async def _record_attack(
        self,
        source_ip: str,
        source_port: int,
        attack_type: Optional[str] = None,
        attack_subtype: Optional[str] = None,
        severity: Optional[int] = None,
        duration_seconds: Optional[float] = None,
        raw_log: Optional[str] = None,
        extra_data: Optional[dict] = None,
    ) -> Attack:
        """
        Record an attack in the database.

        Args:
            source_ip: Source IP address
            source_port: Source port
            attack_type: Type of attack detected
            attack_subtype: More specific attack classification
            severity: Severity level (1-10)
            duration_seconds: Duration of the attack session
            raw_log: Raw log data
            extra_data: Additional data as JSON

        Returns:
            The created Attack record
        """
        async with get_session() as session:
            attack = Attack(
                source_ip=source_ip,
                source_port=source_port,
                destination_port=self.port,
                protocol=self.protocol,
                service_type=self.service_name,
                attack_type=attack_type,
                attack_subtype=attack_subtype,
                severity=severity,
                duration_seconds=Decimal(str(duration_seconds)) if duration_seconds else None,
                raw_log=raw_log,
                extra_data=extra_data or {},
            )
            session.add(attack)
            await session.flush()
            await session.refresh(attack)

            self._logger.attack(
                source_ip=source_ip,
                attack_type=attack_type or "unknown",
                severity=severity or 1,
                attack_id=attack.id,
            )

            return attack

    async def _record_credential(
        self,
        attack_id: int,
        username: str,
        password: str,
        auth_method: str = "password",
        success: bool = False,
    ) -> Credential:
        """
        Record a credential attempt.

        Args:
            attack_id: Associated attack ID
            username: Username attempted
            password: Password attempted
            auth_method: Authentication method used
            success: Whether authentication succeeded

        Returns:
            The created Credential record
        """
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        async with get_session() as session:
            credential = Credential(
                attack_id=attack_id,
                username=username,
                password=password,
                password_hash=password_hash,
                auth_method=auth_method,
                success=success,
                is_default_credential=self._is_default_credential(username, password),
            )
            session.add(credential)
            await session.flush()
            await session.refresh(credential)

            self._logger.credential_attempt(
                source_ip="",  # Will be logged at attack level
                username=username,
                success=success,
                credential_id=credential.id,
            )

            return credential

    async def _record_command(
        self,
        attack_id: int,
        command: str,
        arguments: Optional[str] = None,
        command_type: Optional[str] = None,
        is_malicious: bool = False,
        working_directory: Optional[str] = None,
        output: Optional[str] = None,
        exit_code: Optional[int] = None,
    ) -> Command:
        """
        Record a command execution.

        Args:
            attack_id: Associated attack ID
            command: Command executed
            arguments: Command arguments
            command_type: Type of command
            is_malicious: Whether command is malicious
            working_directory: Current working directory
            output: Command output
            exit_code: Command exit code

        Returns:
            The created Command record
        """
        full_command = f"{command} {arguments}" if arguments else command

        async with get_session() as session:
            cmd = Command(
                attack_id=attack_id,
                command=command,
                arguments=arguments,
                full_command_line=full_command,
                command_type=command_type,
                is_malicious=is_malicious,
                working_directory=working_directory,
                output=output,
                exit_code=exit_code,
            )
            session.add(cmd)
            await session.flush()
            await session.refresh(cmd)

            self._logger.debug(
                "command_recorded",
                command=command,
                is_malicious=is_malicious,
            )

            return cmd

    async def _record_http_request(
        self,
        attack_id: int,
        method: str,
        path: str,
        query_string: Optional[str] = None,
        headers: Optional[dict] = None,
        body: Optional[str] = None,
        user_agent: Optional[str] = None,
        response_status: Optional[int] = None,
    ) -> HttpRequest:
        """
        Record an HTTP request.

        Args:
            attack_id: Associated attack ID
            method: HTTP method
            path: Request path
            query_string: Query string
            headers: Request headers
            body: Request body
            user_agent: User agent string
            response_status: Response status code

        Returns:
            The created HttpRequest record
        """
        async with get_session() as session:
            request = HttpRequest(
                attack_id=attack_id,
                method=method,
                path=path,
                query_string=query_string,
                headers=headers,
                body=body,
                body_size=len(body) if body else 0,
                user_agent=user_agent,
                response_status=response_status,
                contains_sql_injection=self._detect_sql_injection(path, body),
                contains_xss=self._detect_xss(path, body),
                contains_path_traversal=self._detect_path_traversal(path),
                contains_rce_attempt=self._detect_rce(path, body),
            )
            session.add(request)
            await session.flush()
            await session.refresh(request)

            return request

    async def _record_file(
        self,
        attack_id: int,
        filename: str,
        content: bytes,
        operation: str = "upload",
        original_path: Optional[str] = None,
    ) -> File:
        """
        Record a file upload/download.

        Args:
            attack_id: Associated attack ID
            filename: File name
            content: File content
            operation: 'upload' or 'download'
            original_path: Original file path

        Returns:
            The created File record
        """
        # Calculate hashes
        md5_hash = hashlib.md5(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()

        # Extract extension
        extension = filename.rsplit(".", 1)[-1] if "." in filename else None

        async with get_session() as session:
            file_record = File(
                attack_id=attack_id,
                operation=operation,
                filename=filename,
                original_path=original_path,
                file_extension=extension,
                file_size=len(content),
                md5_hash=md5_hash,
                sha1_hash=sha1_hash,
                sha256_hash=sha256_hash,
                content=content if len(content) < 1024 * 1024 else None,  # Store if < 1MB
            )
            session.add(file_record)
            await session.flush()
            await session.refresh(file_record)

            self._logger.info(
                "file_recorded",
                filename=filename,
                operation=operation,
                size=len(content),
                sha256=sha256_hash,
            )

            return file_record

    async def _create_session(
        self,
        session_id: str,
        source_ip: str,
    ) -> Session:
        """
        Create a new attacker session record.

        Args:
            session_id: Unique session identifier
            source_ip: Source IP address

        Returns:
            The created Session record
        """
        async with get_session() as db_session:
            session_record = Session(
                session_id=session_id,
                source_ip=source_ip,
                service_type=self.service_name,
            )
            db_session.add(session_record)
            await db_session.flush()
            await db_session.refresh(session_record)
            return session_record

    async def _end_session(
        self,
        session_id: str,
        stats: Optional[dict] = None,
    ) -> None:
        """
        Mark a session as ended.

        Args:
            session_id: Session identifier
            stats: Optional statistics to update
        """
        from sqlalchemy import select, update

        async with get_session() as db_session:
            stmt = (
                update(Session)
                .where(Session.session_id == session_id)
                .values(
                    ended_at=datetime.utcnow(),
                    **(stats or {}),
                )
            )
            await db_session.execute(stmt)

    def _is_default_credential(self, username: str, password: str) -> bool:
        """Check if credentials are common defaults."""
        default_combos = {
            ("root", "root"),
            ("root", "password"),
            ("root", "123456"),
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("user", "user"),
            ("user", "password"),
            ("test", "test"),
            ("guest", "guest"),
            ("ubuntu", "ubuntu"),
            ("pi", "raspberry"),
        }
        return (username.lower(), password) in default_combos

    def _detect_sql_injection(
        self, path: Optional[str], body: Optional[str]
    ) -> bool:
        """Detect potential SQL injection patterns."""
        patterns = [
            "union select",
            "' or '1'='1",
            "'; drop",
            "; drop",
            "1=1",
            "' or 1=1",
            "\" or 1=1",
            "sleep(",
            "benchmark(",
            "load_file(",
            "into outfile",
            "information_schema",
        ]
        text = f"{path or ''} {body or ''}".lower()
        return any(p in text for p in patterns)

    def _detect_xss(self, path: Optional[str], body: Optional[str]) -> bool:
        """Detect potential XSS patterns."""
        patterns = [
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "onmouseover=",
            "onfocus=",
            "eval(",
            "document.cookie",
            "document.location",
        ]
        text = f"{path or ''} {body or ''}".lower()
        return any(p in text for p in patterns)

    def _detect_path_traversal(self, path: Optional[str]) -> bool:
        """Detect potential path traversal patterns."""
        if not path:
            return False
        patterns = ["../", "..\\", "%2e%2e%2f", "%2e%2e/", "%2e%2e\\", "....//"]
        path_lower = path.lower()
        return any(p in path_lower for p in patterns)

    def _detect_rce(self, path: Optional[str], body: Optional[str]) -> bool:
        """Detect potential RCE patterns."""
        patterns = [
            "; cat ",
            "; ls ",
            "; id",
            "; whoami",
            "| cat ",
            "| ls ",
            "| id",
            "| whoami",
            "`cat ",
            "`ls ",
            "`id`",
            "`whoami`",
            "$(cat ",
            "$(ls ",
            "$(id)",
            "$(whoami)",
            "/bin/sh",
            "/bin/bash",
            "cmd.exe",
            "powershell",
        ]
        text = f"{path or ''} {body or ''}".lower()
        return any(p in text for p in patterns)

    async def health_check(self) -> dict[str, Any]:
        """
        Perform a health check on the service.

        Returns:
            Dictionary with health status information
        """
        return {
            "service": self.service_name,
            "port": self.port,
            "running": self._running,
            "connections": self.connection_count,
            "status": "healthy" if self._running else "stopped",
        }

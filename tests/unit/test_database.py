"""
Unit tests for the database module.
"""

from datetime import datetime
from decimal import Decimal

import pytest
from sqlalchemy import select

from core.database import (
    Alert,
    Attack,
    Base,
    Command,
    Credential,
    DatabaseManager,
    File,
    HttpRequest,
    IpReputation,
    MlModel,
    Session,
    User,
)


class TestAttackModel:
    """Tests for Attack model."""

    @pytest.mark.asyncio
    async def test_create_attack(self, db_session):
        attack = Attack(
            source_ip="192.168.1.100",
            source_port=54321,
            destination_port=22,
            protocol="TCP",
            service_type="ssh",
            attack_type="brute_force",
            severity=5,
        )
        db_session.add(attack)
        await db_session.commit()
        await db_session.refresh(attack)

        assert attack.id is not None
        assert attack.source_ip == "192.168.1.100"
        assert attack.service_type == "ssh"
        assert attack.severity == 5

    @pytest.mark.asyncio
    async def test_attack_timestamp_default(self, db_session):
        attack = Attack(
            source_ip="10.0.0.1",
            service_type="http",
        )
        db_session.add(attack)
        await db_session.commit()
        await db_session.refresh(attack)

        assert attack.timestamp is not None
        assert isinstance(attack.timestamp, datetime)

    @pytest.mark.asyncio
    async def test_attack_extra_data_jsonb(self, db_session):
        extra_data = {"user_agent": "test", "headers": {"X-Custom": "value"}}
        attack = Attack(
            source_ip="10.0.0.1",
            service_type="http",
            extra_data=extra_data,
        )
        db_session.add(attack)
        await db_session.commit()
        await db_session.refresh(attack)

        assert attack.extra_data == extra_data


class TestCredentialModel:
    """Tests for Credential model."""

    @pytest.mark.asyncio
    async def test_create_credential(self, db_session):
        # First create an attack
        attack = Attack(source_ip="192.168.1.100", service_type="ssh")
        db_session.add(attack)
        await db_session.commit()
        await db_session.refresh(attack)

        credential = Credential(
            attack_id=attack.id,
            username="root",
            password="password123",
            password_hash="abc123",
            auth_method="password",
            success=False,
        )
        db_session.add(credential)
        await db_session.commit()
        await db_session.refresh(credential)

        assert credential.id is not None
        assert credential.username == "root"
        assert credential.success is False

    @pytest.mark.asyncio
    async def test_credential_attack_relationship(self, db_session):
        attack = Attack(source_ip="192.168.1.100", service_type="ssh")
        db_session.add(attack)
        await db_session.commit()
        await db_session.refresh(attack)

        credential = Credential(
            attack_id=attack.id,
            username="admin",
            password="admin",
        )
        db_session.add(credential)
        await db_session.commit()

        # Reload attack with relationship
        result = await db_session.execute(
            select(Attack).where(Attack.id == attack.id)
        )
        loaded_attack = result.scalar_one()
        await db_session.refresh(loaded_attack, ["credentials"])

        assert len(loaded_attack.credentials) == 1
        assert loaded_attack.credentials[0].username == "admin"


class TestHttpRequestModel:
    """Tests for HttpRequest model."""

    @pytest.mark.asyncio
    async def test_create_http_request(self, db_session):
        attack = Attack(source_ip="192.168.1.100", service_type="http")
        db_session.add(attack)
        await db_session.commit()
        await db_session.refresh(attack)

        request = HttpRequest(
            attack_id=attack.id,
            method="POST",
            path="/login",
            body='{"user": "admin"}',
            user_agent="Mozilla/5.0",
            contains_sql_injection=False,
        )
        db_session.add(request)
        await db_session.commit()
        await db_session.refresh(request)

        assert request.id is not None
        assert request.method == "POST"
        assert request.path == "/login"

    @pytest.mark.asyncio
    async def test_http_request_threat_flags(self, db_session):
        attack = Attack(source_ip="192.168.1.100", service_type="http")
        db_session.add(attack)
        await db_session.commit()
        await db_session.refresh(attack)

        request = HttpRequest(
            attack_id=attack.id,
            method="GET",
            path="/search?q=' OR 1=1--",
            contains_sql_injection=True,
            contains_xss=False,
            contains_path_traversal=False,
            contains_rce_attempt=False,
        )
        db_session.add(request)
        await db_session.commit()
        await db_session.refresh(request)

        assert request.contains_sql_injection is True


class TestCommandModel:
    """Tests for Command model."""

    @pytest.mark.asyncio
    async def test_create_command(self, db_session):
        attack = Attack(source_ip="192.168.1.100", service_type="ssh")
        db_session.add(attack)
        await db_session.commit()
        await db_session.refresh(attack)

        command = Command(
            attack_id=attack.id,
            command="cat",
            arguments="/etc/passwd",
            full_command_line="cat /etc/passwd",
            command_type="recon",
            is_malicious=True,
            exit_code=0,
        )
        db_session.add(command)
        await db_session.commit()
        await db_session.refresh(command)

        assert command.id is not None
        assert command.command == "cat"
        assert command.is_malicious is True


class TestFileModel:
    """Tests for File model."""

    @pytest.mark.asyncio
    async def test_create_file(self, db_session):
        attack = Attack(source_ip="192.168.1.100", service_type="ftp")
        db_session.add(attack)
        await db_session.commit()
        await db_session.refresh(attack)

        file = File(
            attack_id=attack.id,
            operation="upload",
            filename="malware.exe",
            file_size=1024,
            sha256_hash="abc123def456",
            is_malware=True,
        )
        db_session.add(file)
        await db_session.commit()
        await db_session.refresh(file)

        assert file.id is not None
        assert file.filename == "malware.exe"
        assert file.is_malware is True


class TestIpReputationModel:
    """Tests for IpReputation model."""

    @pytest.mark.asyncio
    async def test_create_ip_reputation(self, db_session):
        reputation = IpReputation(
            ip="192.168.1.100",
            abuseipdb_score=75,
            is_tor_exit_node=False,
            is_vpn=True,
            total_attacks=5,
        )
        db_session.add(reputation)
        await db_session.commit()
        await db_session.refresh(reputation)

        assert reputation.ip == "192.168.1.100"
        assert reputation.abuseipdb_score == 75
        assert reputation.is_vpn is True


class TestSessionModel:
    """Tests for Session model."""

    @pytest.mark.asyncio
    async def test_create_session(self, db_session):
        session_record = Session(
            session_id="test-session-123",
            source_ip="192.168.1.100",
            service_type="ssh",
            total_commands=5,
            was_successful_login=False,
        )
        db_session.add(session_record)
        await db_session.commit()
        await db_session.refresh(session_record)

        assert session_record.id is not None
        assert session_record.session_id == "test-session-123"


class TestAlertModel:
    """Tests for Alert model."""

    @pytest.mark.asyncio
    async def test_create_alert(self, db_session):
        alert = Alert(
            alert_type="high_severity",
            severity="critical",
            title="Critical attack detected",
            description="Multiple brute force attempts",
            status="open",
        )
        db_session.add(alert)
        await db_session.commit()
        await db_session.refresh(alert)

        assert alert.id is not None
        assert alert.severity == "critical"
        assert alert.status == "open"


class TestUserModel:
    """Tests for User model."""

    @pytest.mark.asyncio
    async def test_create_user(self, db_session):
        user = User(
            username="admin",
            email="admin@honeytrap.local",
            hashed_password="hashed_password_here",
            is_admin=True,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        assert user.id is not None
        assert user.username == "admin"
        assert user.is_admin is True


class TestDatabaseManager:
    """Tests for DatabaseManager class."""

    @pytest.mark.asyncio
    async def test_session_context_manager(self, db_manager):
        async with db_manager.session() as session:
            attack = Attack(source_ip="10.0.0.1", service_type="ssh")
            session.add(attack)
            # Session should auto-commit on successful exit

    @pytest.mark.asyncio
    async def test_session_rollback_on_error(self, db_manager):
        try:
            async with db_manager.session() as session:
                attack = Attack(source_ip="10.0.0.1", service_type="ssh")
                session.add(attack)
                raise ValueError("Test error")
        except ValueError:
            pass
        # Session should have rolled back

"""Initial database schema

Revision ID: 001
Revises: 
Create Date: 2024-11-25 00:00:01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users table
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, default=True),
        sa.Column("is_admin", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_login", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
        sa.UniqueConstraint("email"),
    )

    # Attacks table
    op.create_table(
        "attacks",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("duration_seconds", sa.Numeric(10, 3), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(10), nullable=True),
        sa.Column("service_type", sa.String(20), nullable=False),
        sa.Column("attack_type", sa.String(50), nullable=True),
        sa.Column("attack_subtype", sa.String(100), nullable=True),
        sa.Column("severity", sa.Integer(), nullable=True),
        sa.Column("ml_confidence", sa.Numeric(5, 4), nullable=True),
        sa.Column("country_code", sa.String(2), nullable=True),
        sa.Column("country_name", sa.String(100), nullable=True),
        sa.Column("city", sa.String(100), nullable=True),
        sa.Column("latitude", sa.Numeric(10, 8), nullable=True),
        sa.Column("longitude", sa.Numeric(11, 8), nullable=True),
        sa.Column("asn", sa.Integer(), nullable=True),
        sa.Column("isp", sa.String(255), nullable=True),
        sa.Column("raw_log", sa.Text(), nullable=True),
        sa.Column("extra_data", postgresql.JSONB(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("severity BETWEEN 1 AND 10", name="ck_attacks_severity"),
    )
    op.create_index("ix_attacks_timestamp", "attacks", ["timestamp"], unique=False)
    op.create_index("ix_attacks_timestamp_desc", "attacks", [sa.text("timestamp DESC")], unique=False)
    op.create_index("ix_attacks_source_ip", "attacks", ["source_ip"], unique=False)
    op.create_index("ix_attacks_service_type", "attacks", ["service_type"], unique=False)
    op.create_index("ix_attacks_attack_type", "attacks", ["attack_type"], unique=False)
    op.create_index("ix_attacks_source_ip_service", "attacks", ["source_ip", "service_type"], unique=False)

    # Credentials table
    op.create_table(
        "credentials",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("attack_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("password", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(64), nullable=True),
        sa.Column("auth_method", sa.String(50), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False, default=False),
        sa.Column("is_default_credential", sa.Boolean(), nullable=False, default=False),
        sa.Column("is_dictionary_word", sa.Boolean(), nullable=False, default=False),
        sa.ForeignKeyConstraint(["attack_id"], ["attacks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_credentials_username", "credentials", ["username"], unique=False)
    op.create_index("ix_credentials_password_hash", "credentials", ["password_hash"], unique=False)

    # HTTP requests table
    op.create_table(
        "http_requests",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("attack_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("query_string", sa.Text(), nullable=True),
        sa.Column("headers", postgresql.JSONB(), nullable=True),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("body_size", sa.Integer(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("referer", sa.Text(), nullable=True),
        sa.Column("content_type", sa.String(100), nullable=True),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("response_size", sa.Integer(), nullable=True),
        sa.Column("contains_sql_injection", sa.Boolean(), nullable=False, default=False),
        sa.Column("contains_xss", sa.Boolean(), nullable=False, default=False),
        sa.Column("contains_path_traversal", sa.Boolean(), nullable=False, default=False),
        sa.Column("contains_rce_attempt", sa.Boolean(), nullable=False, default=False),
        sa.ForeignKeyConstraint(["attack_id"], ["attacks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_http_requests_user_agent", "http_requests", ["user_agent"], unique=False)
    op.create_index("ix_http_requests_method_path", "http_requests", ["method", "path"], unique=False)

    # Commands table
    op.create_table(
        "commands",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("attack_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("arguments", sa.Text(), nullable=True),
        sa.Column("full_command_line", sa.Text(), nullable=True),
        sa.Column("command_type", sa.String(50), nullable=True),
        sa.Column("is_malicious", sa.Boolean(), nullable=False, default=False),
        sa.Column("is_automated", sa.Boolean(), nullable=False, default=False),
        sa.Column("working_directory", sa.String(255), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("error_output", sa.Text(), nullable=True),
        sa.Column("execution_time_ms", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["attack_id"], ["attacks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_commands_timestamp", "commands", ["timestamp"], unique=False)

    # Files table
    op.create_table(
        "files",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("attack_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("operation", sa.String(20), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("original_path", sa.Text(), nullable=True),
        sa.Column("file_extension", sa.String(20), nullable=True),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("md5_hash", sa.String(32), nullable=True),
        sa.Column("sha1_hash", sa.String(40), nullable=True),
        sa.Column("sha256_hash", sa.String(64), nullable=False),
        sa.Column("storage_path", sa.String(500), nullable=True),
        sa.Column("content", sa.LargeBinary(), nullable=True),
        sa.Column("is_malware", sa.Boolean(), nullable=False, default=False),
        sa.Column("malware_family", sa.String(100), nullable=True),
        sa.Column("virustotal_detections", sa.Integer(), nullable=True),
        sa.Column("virustotal_results", postgresql.JSONB(), nullable=True),
        sa.Column("mime_type", sa.String(100), nullable=True),
        sa.Column("magic_signature", sa.String(255), nullable=True),
        sa.ForeignKeyConstraint(["attack_id"], ["attacks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sha256_hash", name="uq_files_sha256"),
    )
    op.create_index("ix_files_filename", "files", ["filename"], unique=False)
    op.create_index("ix_files_sha256_hash", "files", ["sha256_hash"], unique=False)

    # IP reputation table
    op.create_table(
        "ip_reputation",
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("abuseipdb_score", sa.Integer(), nullable=True),
        sa.Column("abuseipdb_reports", sa.Integer(), nullable=True),
        sa.Column("abuseipdb_last_reported", sa.DateTime(), nullable=True),
        sa.Column("virustotal_malicious_count", sa.Integer(), nullable=True),
        sa.Column("virustotal_suspicious_count", sa.Integer(), nullable=True),
        sa.Column("virustotal_harmless_count", sa.Integer(), nullable=True),
        sa.Column("is_tor_exit_node", sa.Boolean(), nullable=False, default=False),
        sa.Column("is_vpn", sa.Boolean(), nullable=False, default=False),
        sa.Column("is_proxy", sa.Boolean(), nullable=False, default=False),
        sa.Column("is_hosting_provider", sa.Boolean(), nullable=False, default=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("total_attacks", sa.Integer(), nullable=False, default=1),
        sa.Column("last_updated", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("cache_expires_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("ip"),
        sa.CheckConstraint("abuseipdb_score BETWEEN 0 AND 100", name="ck_ip_reputation_abuseipdb_score"),
    )
    op.create_index("ix_ip_reputation_last_seen", "ip_reputation", ["last_seen"], unique=False)
    op.create_index("ix_ip_reputation_abuseipdb_score", "ip_reputation", ["abuseipdb_score"], unique=False)

    # ML models table
    op.create_table(
        "ml_models",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("version", sa.String(20), nullable=False),
        sa.Column("model_type", sa.String(50), nullable=True),
        sa.Column("accuracy", sa.Numeric(5, 4), nullable=True),
        sa.Column("precision", sa.Numeric(5, 4), nullable=True),
        sa.Column("recall", sa.Numeric(5, 4), nullable=True),
        sa.Column("f1_score", sa.Numeric(5, 4), nullable=True),
        sa.Column("training_samples", sa.Integer(), nullable=True),
        sa.Column("training_duration_seconds", sa.Integer(), nullable=True),
        sa.Column("trained_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("trained_by", sa.String(100), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, default=False),
        sa.Column("deployed_at", sa.DateTime(), nullable=True),
        sa.Column("model_path", sa.String(500), nullable=True),
        sa.Column("model_data", sa.LargeBinary(), nullable=True),
        sa.Column("hyperparameters", postgresql.JSONB(), nullable=True),
        sa.Column("feature_names", postgresql.JSONB(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", "version", name="uq_ml_models_name_version"),
    )
    op.create_index("ix_ml_models_trained_at", "ml_models", ["trained_at"], unique=False)

    # Sessions table
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("session_id", sa.String(64), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("service_type", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("total_commands", sa.Integer(), nullable=False, default=0),
        sa.Column("total_requests", sa.Integer(), nullable=False, default=0),
        sa.Column("total_uploads", sa.Integer(), nullable=False, default=0),
        sa.Column("total_downloads", sa.Integer(), nullable=False, default=0),
        sa.Column("was_successful_login", sa.Boolean(), nullable=False, default=False),
        sa.Column("escalated_privileges", sa.Boolean(), nullable=False, default=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id"),
    )
    op.create_index("ix_sessions_source_ip", "sessions", ["source_ip"], unique=False)
    op.create_index("ix_sessions_started_at", "sessions", ["started_at"], unique=False)

    # Alerts table
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("attack_id", sa.Integer(), nullable=True),
        sa.Column("alert_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("assigned_to", sa.String(100), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, default="open"),
        sa.Column("email_sent", sa.Boolean(), nullable=False, default=False),
        sa.Column("webhook_sent", sa.Boolean(), nullable=False, default=False),
        sa.ForeignKeyConstraint(["attack_id"], ["attacks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"], unique=False)
    op.create_index("ix_alerts_status", "alerts", ["status"], unique=False)


def downgrade() -> None:
    op.drop_table("alerts")
    op.drop_table("sessions")
    op.drop_table("ml_models")
    op.drop_table("ip_reputation")
    op.drop_table("files")
    op.drop_table("commands")
    op.drop_table("http_requests")
    op.drop_table("credentials")
    op.drop_table("attacks")
    op.drop_table("users")

"""
API Models Module

Pydantic schemas for request/response validation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class AttackBase(BaseModel):
    """Base attack schema."""
    source_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    service_type: str
    attack_type: Optional[str] = None
    severity: Optional[int] = Field(None, ge=1, le=10)


class AttackCreate(AttackBase):
    """Schema for creating an attack record."""
    raw_log: Optional[str] = None
    extra_data: Optional[dict[str, Any]] = None


class AttackResponse(AttackBase):
    """Schema for attack response."""
    id: int
    timestamp: datetime
    attack_subtype: Optional[str] = None
    ml_confidence: Optional[float] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    class Config:
        from_attributes = True


class AttackDetail(AttackResponse):
    """Detailed attack response with related data."""
    credentials: list["CredentialResponse"] = []
    commands: list["CommandResponse"] = []
    http_requests: list["HttpRequestResponse"] = []


class CredentialResponse(BaseModel):
    """Schema for credential response."""
    id: int
    timestamp: datetime
    username: str
    password: str
    auth_method: Optional[str] = None
    success: bool

    class Config:
        from_attributes = True


class CommandResponse(BaseModel):
    """Schema for command response."""
    id: int
    timestamp: datetime
    command: str
    arguments: Optional[str] = None
    command_type: Optional[str] = None
    is_malicious: bool

    class Config:
        from_attributes = True


class HttpRequestResponse(BaseModel):
    """Schema for HTTP request response."""
    id: int
    timestamp: datetime
    method: str
    path: str
    user_agent: Optional[str] = None
    response_status: Optional[int] = None
    contains_sql_injection: bool
    contains_xss: bool

    class Config:
        from_attributes = True


class PaginatedResponse(BaseModel):
    """Generic paginated response."""
    items: list[Any]
    total: int
    page: int
    page_size: int
    pages: int


class AttackListResponse(BaseModel):
    """Paginated attack list response."""
    items: list[AttackResponse]
    total: int
    page: int
    page_size: int
    pages: int


class StatsOverview(BaseModel):
    """Dashboard overview statistics."""
    total_attacks: int
    attacks_today: int
    attacks_this_week: int
    unique_ips: int
    top_attack_type: Optional[str] = None
    top_targeted_service: Optional[str] = None
    avg_severity: float


class TimelinePoint(BaseModel):
    """Single point in attack timeline."""
    timestamp: datetime
    count: int
    service_type: Optional[str] = None


class GeoPoint(BaseModel):
    """Geographic attack data point."""
    country_code: str
    country_name: str
    count: int
    latitude: float
    longitude: float


class TopAttacker(BaseModel):
    """Top attacker information."""
    ip: str
    attack_count: int
    first_seen: datetime
    last_seen: datetime
    services_targeted: list[str]


class AttackTypeDistribution(BaseModel):
    """Attack type distribution."""
    attack_type: str
    count: int
    percentage: float


class SearchFilters(BaseModel):
    """Attack search filters."""
    source_ip: Optional[str] = None
    service_type: Optional[str] = None
    attack_type: Optional[str] = None
    severity_min: Optional[int] = Field(None, ge=1, le=10)
    severity_max: Optional[int] = Field(None, ge=1, le=10)
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    country_code: Optional[str] = None


class LoginRequest(BaseModel):
    """Login request schema."""
    username: str
    password: str


class UserResponse(BaseModel):
    """User response schema."""
    id: int
    username: str
    email: str
    is_admin: bool
    created_at: datetime

    class Config:
        from_attributes = True


class LiveAttackEvent(BaseModel):
    """Real-time attack event for WebSocket."""
    event_type: str = "attack"
    attack: AttackResponse
    ml_prediction: Optional[dict[str, Any]] = None


AttackDetail.model_rebuild()

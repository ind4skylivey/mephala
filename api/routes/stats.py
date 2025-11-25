"""
Statistics API Routes

Endpoints for dashboard analytics and statistics.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from api.models import (
    AttackTypeDistribution,
    GeoPoint,
    StatsOverview,
    TimelinePoint,
    TopAttacker,
)
from core.database import Attack, get_session

router = APIRouter()


@router.get("/stats/overview", response_model=StatsOverview)
async def get_overview(
    _: str = Depends(get_current_user),
):
    """Get dashboard overview statistics."""
    async with get_session() as session:
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=7)

        total_result = await session.execute(select(func.count(Attack.id)))
        total_attacks = total_result.scalar() or 0

        today_result = await session.execute(
            select(func.count(Attack.id)).where(Attack.timestamp >= today_start)
        )
        attacks_today = today_result.scalar() or 0

        week_result = await session.execute(
            select(func.count(Attack.id)).where(Attack.timestamp >= week_start)
        )
        attacks_this_week = week_result.scalar() or 0

        unique_ips_result = await session.execute(
            select(func.count(distinct(Attack.source_ip)))
        )
        unique_ips = unique_ips_result.scalar() or 0

        top_type_result = await session.execute(
            select(Attack.attack_type, func.count(Attack.id).label("count"))
            .where(Attack.attack_type.isnot(None))
            .group_by(Attack.attack_type)
            .order_by(desc("count"))
            .limit(1)
        )
        top_type_row = top_type_result.first()
        top_attack_type = top_type_row[0] if top_type_row else None

        top_service_result = await session.execute(
            select(Attack.service_type, func.count(Attack.id).label("count"))
            .group_by(Attack.service_type)
            .order_by(desc("count"))
            .limit(1)
        )
        top_service_row = top_service_result.first()
        top_targeted_service = top_service_row[0] if top_service_row else None

        avg_severity_result = await session.execute(
            select(func.avg(Attack.severity)).where(Attack.severity.isnot(None))
        )
        avg_severity = float(avg_severity_result.scalar() or 0)

        return StatsOverview(
            total_attacks=total_attacks,
            attacks_today=attacks_today,
            attacks_this_week=attacks_this_week,
            unique_ips=unique_ips,
            top_attack_type=top_attack_type,
            top_targeted_service=top_targeted_service,
            avg_severity=round(avg_severity, 2),
        )


@router.get("/stats/timeline")
async def get_timeline(
    hours: int = Query(24, ge=1, le=168),
    interval: str = Query("hour", regex="^(hour|day)$"),
    service_type: Optional[str] = None,
    _: str = Depends(get_current_user),
):
    """Get attack timeline data for charts."""
    async with get_session() as session:
        now = datetime.utcnow()
        start_time = now - timedelta(hours=hours)

        if interval == "hour":
            time_trunc = func.date_trunc("hour", Attack.timestamp)
        else:
            time_trunc = func.date_trunc("day", Attack.timestamp)

        query = (
            select(time_trunc.label("time_bucket"), func.count(Attack.id).label("count"))
            .where(Attack.timestamp >= start_time)
            .group_by("time_bucket")
            .order_by("time_bucket")
        )

        if service_type:
            query = query.where(Attack.service_type == service_type)

        result = await session.execute(query)
        rows = result.all()

        return [
            TimelinePoint(timestamp=row.time_bucket, count=row.count)
            for row in rows
        ]


@router.get("/stats/geographic")
async def get_geographic_stats(
    limit: int = Query(20, ge=1, le=100),
    _: str = Depends(get_current_user),
):
    """Get attack origin geographic distribution."""
    async with get_session() as session:
        query = (
            select(
                Attack.country_code,
                Attack.country_name,
                func.count(Attack.id).label("count"),
                func.avg(Attack.latitude).label("lat"),
                func.avg(Attack.longitude).label("lng"),
            )
            .where(Attack.country_code.isnot(None))
            .group_by(Attack.country_code, Attack.country_name)
            .order_by(desc("count"))
            .limit(limit)
        )

        result = await session.execute(query)
        rows = result.all()

        return [
            GeoPoint(
                country_code=row.country_code,
                country_name=row.country_name or row.country_code,
                count=row.count,
                latitude=float(row.lat or 0),
                longitude=float(row.lng or 0),
            )
            for row in rows
        ]


@router.get("/stats/top-attackers")
async def get_top_attackers(
    limit: int = Query(10, ge=1, le=50),
    days: int = Query(7, ge=1, le=30),
    _: str = Depends(get_current_user),
):
    """Get top attacking IP addresses."""
    async with get_session() as session:
        start_time = datetime.utcnow() - timedelta(days=days)

        query = (
            select(
                Attack.source_ip,
                func.count(Attack.id).label("attack_count"),
                func.min(Attack.timestamp).label("first_seen"),
                func.max(Attack.timestamp).label("last_seen"),
                func.array_agg(distinct(Attack.service_type)).label("services"),
            )
            .where(Attack.timestamp >= start_time)
            .group_by(Attack.source_ip)
            .order_by(desc("attack_count"))
            .limit(limit)
        )

        result = await session.execute(query)
        rows = result.all()

        return [
            TopAttacker(
                ip=row.source_ip,
                attack_count=row.attack_count,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                services_targeted=list(row.services) if row.services else [],
            )
            for row in rows
        ]


@router.get("/stats/attack-types")
async def get_attack_type_distribution(
    days: int = Query(7, ge=1, le=30),
    _: str = Depends(get_current_user),
):
    """Get attack type distribution."""
    async with get_session() as session:
        start_time = datetime.utcnow() - timedelta(days=days)

        total_result = await session.execute(
            select(func.count(Attack.id)).where(Attack.timestamp >= start_time)
        )
        total = total_result.scalar() or 1

        query = (
            select(
                Attack.attack_type,
                func.count(Attack.id).label("count"),
            )
            .where(Attack.timestamp >= start_time)
            .where(Attack.attack_type.isnot(None))
            .group_by(Attack.attack_type)
            .order_by(desc("count"))
        )

        result = await session.execute(query)
        rows = result.all()

        return [
            AttackTypeDistribution(
                attack_type=row.attack_type,
                count=row.count,
                percentage=round((row.count / total) * 100, 2),
            )
            for row in rows
        ]


@router.get("/stats/services")
async def get_service_stats(
    _: str = Depends(get_current_user),
):
    """Get statistics by service type."""
    async with get_session() as session:
        query = (
            select(
                Attack.service_type,
                func.count(Attack.id).label("total_attacks"),
                func.count(distinct(Attack.source_ip)).label("unique_ips"),
                func.avg(Attack.severity).label("avg_severity"),
            )
            .group_by(Attack.service_type)
        )

        result = await session.execute(query)
        rows = result.all()

        return [
            {
                "service": row.service_type,
                "total_attacks": row.total_attacks,
                "unique_ips": row.unique_ips,
                "avg_severity": round(float(row.avg_severity or 0), 2),
            }
            for row in rows
        ]

"""
Attacks API Routes

Endpoints for querying and managing attack records.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth import get_current_user
from api.models import (
    AttackDetail,
    AttackListResponse,
    AttackResponse,
    SearchFilters,
)
from core.database import Attack, Command, Credential, HttpRequest, get_session

router = APIRouter()


@router.get("/attacks", response_model=AttackListResponse)
async def list_attacks(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    service_type: Optional[str] = None,
    attack_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    severity_min: Optional[int] = Query(None, ge=1, le=10),
    severity_max: Optional[int] = Query(None, ge=1, le=10),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    _: str = Depends(get_current_user),
):
    """
    List attacks with pagination and filtering.
    
    Supports filtering by service type, attack type, IP, severity, and date range.
    """
    async with get_session() as session:
        query = select(Attack).order_by(desc(Attack.timestamp))

        if service_type:
            query = query.where(Attack.service_type == service_type)
        if attack_type:
            query = query.where(Attack.attack_type == attack_type)
        if source_ip:
            query = query.where(Attack.source_ip == source_ip)
        if severity_min:
            query = query.where(Attack.severity >= severity_min)
        if severity_max:
            query = query.where(Attack.severity <= severity_max)
        if start_date:
            query = query.where(Attack.timestamp >= start_date)
        if end_date:
            query = query.where(Attack.timestamp <= end_date)

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await session.execute(count_query)
        total = total_result.scalar() or 0

        offset = (page - 1) * page_size
        query = query.offset(offset).limit(page_size)

        result = await session.execute(query)
        attacks = result.scalars().all()

        pages = (total + page_size - 1) // page_size

        return AttackListResponse(
            items=[AttackResponse.model_validate(a) for a in attacks],
            total=total,
            page=page,
            page_size=page_size,
            pages=pages,
        )


@router.get("/attacks/{attack_id}", response_model=AttackDetail)
async def get_attack(
    attack_id: int,
    _: str = Depends(get_current_user),
):
    """Get detailed information about a specific attack."""
    async with get_session() as session:
        query = (
            select(Attack)
            .where(Attack.id == attack_id)
            .options(
                selectinload(Attack.credentials),
                selectinload(Attack.commands),
                selectinload(Attack.http_requests),
            )
        )

        result = await session.execute(query)
        attack = result.scalar_one_or_none()

        if not attack:
            raise HTTPException(status_code=404, detail="Attack not found")

        return AttackDetail.model_validate(attack)


@router.post("/attacks/search", response_model=AttackListResponse)
async def search_attacks(
    filters: SearchFilters,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    _: str = Depends(get_current_user),
):
    """Advanced attack search with complex filters."""
    async with get_session() as session:
        query = select(Attack).order_by(desc(Attack.timestamp))

        if filters.source_ip:
            query = query.where(Attack.source_ip.ilike(f"%{filters.source_ip}%"))
        if filters.service_type:
            query = query.where(Attack.service_type == filters.service_type)
        if filters.attack_type:
            query = query.where(Attack.attack_type == filters.attack_type)
        if filters.severity_min:
            query = query.where(Attack.severity >= filters.severity_min)
        if filters.severity_max:
            query = query.where(Attack.severity <= filters.severity_max)
        if filters.start_date:
            query = query.where(Attack.timestamp >= filters.start_date)
        if filters.end_date:
            query = query.where(Attack.timestamp <= filters.end_date)
        if filters.country_code:
            query = query.where(Attack.country_code == filters.country_code)

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await session.execute(count_query)
        total = total_result.scalar() or 0

        offset = (page - 1) * page_size
        query = query.offset(offset).limit(page_size)

        result = await session.execute(query)
        attacks = result.scalars().all()

        pages = (total + page_size - 1) // page_size

        return AttackListResponse(
            items=[AttackResponse.model_validate(a) for a in attacks],
            total=total,
            page=page,
            page_size=page_size,
            pages=pages,
        )


@router.get("/attacks/{attack_id}/credentials")
async def get_attack_credentials(
    attack_id: int,
    _: str = Depends(get_current_user),
):
    """Get credentials associated with an attack."""
    async with get_session() as session:
        query = select(Credential).where(Credential.attack_id == attack_id)
        result = await session.execute(query)
        credentials = result.scalars().all()

        return [
            {
                "id": c.id,
                "timestamp": c.timestamp,
                "username": c.username,
                "password": c.password,
                "auth_method": c.auth_method,
                "success": c.success,
            }
            for c in credentials
        ]


@router.get("/attacks/{attack_id}/commands")
async def get_attack_commands(
    attack_id: int,
    _: str = Depends(get_current_user),
):
    """Get commands associated with an attack."""
    async with get_session() as session:
        query = select(Command).where(Command.attack_id == attack_id)
        result = await session.execute(query)
        commands = result.scalars().all()

        return [
            {
                "id": c.id,
                "timestamp": c.timestamp,
                "command": c.command,
                "arguments": c.arguments,
                "command_type": c.command_type,
                "is_malicious": c.is_malicious,
                "output": c.output,
            }
            for c in commands
        ]


@router.delete("/attacks/{attack_id}")
async def delete_attack(
    attack_id: int,
    _: str = Depends(get_current_user),
):
    """Delete an attack record."""
    async with get_session() as session:
        query = select(Attack).where(Attack.id == attack_id)
        result = await session.execute(query)
        attack = result.scalar_one_or_none()

        if not attack:
            raise HTTPException(status_code=404, detail="Attack not found")

        await session.delete(attack)

        return {"status": "deleted", "id": attack_id}

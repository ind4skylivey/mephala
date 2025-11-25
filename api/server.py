"""
FastAPI Server Module

Main API application with CORS, lifecycle events, and route registration.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import attacks, stats, websocket
from core.config import get_config
from core.database import close_database, init_database
from core.logger import get_logger, setup_logging

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler for startup and shutdown."""
    config = get_config()

    setup_logging(
        level=config.logging.level,
        log_format=config.logging.format,
        log_file=config.logging.file,
    )

    logger.info("Starting Mephala API server")

    await init_database(
        database_url=config.database.url,
        pool_size=config.database.pool_size,
        max_overflow=config.database.max_overflow,
    )
    logger.info("Database connection established")

    yield

    await close_database()
    logger.info("API server shutdown complete")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    config = get_config()

    app = FastAPI(
        title="Mephala API",
        description="Intelligent Honeypot System API",
        version="1.0.0",
        docs_url="/docs" if config.api.debug else None,
        redoc_url="/redoc" if config.api.debug else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(attacks.router, prefix="/api/v1", tags=["Attacks"])
    app.include_router(stats.router, prefix="/api/v1", tags=["Statistics"])
    app.include_router(websocket.router, prefix="/ws", tags=["WebSocket"])

    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "service": "mephala-api"}

    return app


app = create_app()

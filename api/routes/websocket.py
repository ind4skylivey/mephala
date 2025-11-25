"""
WebSocket Routes

Real-time attack feed via WebSocket connections.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.logger import get_logger

logger = get_logger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        self._active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self._active_connections.append(websocket)
        logger.info("WebSocket client connected", total=len(self._active_connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            if websocket in self._active_connections:
                self._active_connections.remove(websocket)
        logger.info("WebSocket client disconnected", total=len(self._active_connections))

    async def broadcast(self, message: dict) -> None:
        """Broadcast a message to all connected clients."""
        if not self._active_connections:
            return

        message_json = json.dumps(message, default=str)
        disconnected = []

        async with self._lock:
            for connection in self._active_connections:
                try:
                    await connection.send_text(message_json)
                except Exception:
                    disconnected.append(connection)

            for conn in disconnected:
                if conn in self._active_connections:
                    self._active_connections.remove(conn)

    async def send_to_client(self, websocket: WebSocket, message: dict) -> None:
        """Send a message to a specific client."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error("Failed to send WebSocket message", error=str(e))

    @property
    def connection_count(self) -> int:
        """Get the number of active connections."""
        return len(self._active_connections)


manager = ConnectionManager()


def get_connection_manager() -> ConnectionManager:
    """Get the global connection manager instance."""
    return manager


@router.websocket("/live")
async def websocket_live_feed(websocket: WebSocket):
    """
    WebSocket endpoint for real-time attack feed.
    
    Clients receive attack events as they occur.
    """
    await manager.connect(websocket)

    try:
        await manager.send_to_client(websocket, {
            "event": "connected",
            "message": "Connected to Mephala live feed",
            "timestamp": datetime.utcnow().isoformat(),
        })

        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )

                message = json.loads(data)

                if message.get("type") == "ping":
                    await manager.send_to_client(websocket, {
                        "event": "pong",
                        "timestamp": datetime.utcnow().isoformat(),
                    })

                elif message.get("type") == "subscribe":
                    filters = message.get("filters", {})
                    await manager.send_to_client(websocket, {
                        "event": "subscribed",
                        "filters": filters,
                        "timestamp": datetime.utcnow().isoformat(),
                    })

            except asyncio.TimeoutError:
                await manager.send_to_client(websocket, {
                    "event": "heartbeat",
                    "timestamp": datetime.utcnow().isoformat(),
                })

            except json.JSONDecodeError:
                await manager.send_to_client(websocket, {
                    "event": "error",
                    "message": "Invalid JSON",
                })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WebSocket error", error=str(e))
    finally:
        await manager.disconnect(websocket)


async def broadcast_attack(attack_data: dict) -> None:
    """
    Broadcast a new attack to all connected WebSocket clients.
    
    Called by honeypot services when attacks are detected.
    """
    event = {
        "event": "attack",
        "data": attack_data,
        "timestamp": datetime.utcnow().isoformat(),
    }
    await manager.broadcast(event)


async def broadcast_alert(alert_data: dict) -> None:
    """Broadcast an alert to all connected clients."""
    event = {
        "event": "alert",
        "data": alert_data,
        "timestamp": datetime.utcnow().isoformat(),
    }
    await manager.broadcast(event)

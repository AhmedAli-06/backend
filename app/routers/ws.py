"""
WebSocket Router - Real-time data streaming

Provides real-time updates for:
  - Active sessions (every 3 seconds)
  - New access events (instant push)
  - Alert notifications (instant push)
  - Session revocations (instant push)
"""

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.access import AccessEvent, AccessSession
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.user import User

router = APIRouter(tags=["Websockets"])


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Broadcast a JSON message to all connected clients."""
        if not self.active_connections:
            return

        message_json = json.dumps(message, default=str)
        for connection in self.active_connections:
            try:
                await connection.send_text(message_json)
            except Exception:
                pass

    async def send_personal(self, websocket: WebSocket, message: dict):
        """Send a message to a specific client."""
        try:
            await websocket.send_text(json.dumps(message, default=str))
        except Exception:
            pass


manager = ConnectionManager()


async def get_active_sessions_data() -> list[dict]:
    """Get active sessions with user and asset info."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AccessSession, User, Asset)
            .join(User, AccessSession.user_id == User.id)
            .join(Asset, AccessSession.asset_id == Asset.id)
            .where(AccessSession.status == "active")
        )
        rows = result.all()

        sessions = []
        for session, user, asset in rows:
            sessions.append({
                "id": str(session.id),
                "user_id": str(user.id),
                "user_name": user.full_name,
                "department": user.department,
                "asset_id": str(asset.id),
                "asset_name": asset.name,
                "asset_location": asset.location,
                "started_at": session.started_at.isoformat() if session.started_at else None,
                "avg_trust_score": session.avg_trust_score,
                "min_trust_score": session.min_trust_score,
                "alert_count": session.alert_count
            })
        return sessions


async def get_recent_events_data(limit: int = 10) -> list[dict]:
    """Get recent access events."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AccessEvent, User, Asset)
            .join(User, AccessEvent.user_id == User.id, isouter=True)
            .join(Asset, AccessEvent.asset_id == Asset.id)
            .order_by(AccessEvent.occurred_at.desc())
            .limit(limit)
        )
        rows = result.all()

        events = []
        for event, user, asset in rows:
            events.append({
                "id": str(event.id),
                "user_name": user.full_name if user else "Unknown",
                "asset_name": asset.name,
                "event_type": event.event_type,
                "trust_score": event.trust_score,
                "decision": event.decision,
                "occurred_at": event.occurred_at.isoformat() if event.occurred_at else None
            })
        return events


async def get_open_alerts_data(limit: int = 5) -> list[dict]:
    """Get recent open alerts."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Alert, User, Asset)
            .join(User, Alert.user_id == User.id, isouter=True)
            .join(Asset, Alert.asset_id == Asset.id)
            .where(Alert.status == "open")
            .order_by(Alert.triggered_at.desc())
            .limit(limit)
        )
        rows = result.all()

        alerts = []
        for alert, user, asset in rows:
            alerts.append({
                "id": str(alert.id),
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "alert_type": alert.alert_type,
                "user_name": user.full_name if user else "Unknown",
                "asset_name": asset.name,
                "trust_score": alert.trust_score_at_trigger,
                "triggered_at": alert.triggered_at.isoformat() if alert.triggered_at else None
            })
        return alerts


@router.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time dashboard updates.

    Sends:
      - Active sessions every 3 seconds
      - Immediate broadcasts for new events/alerts/revocations
    """
    await manager.connect(websocket)

    try:
        # Send initial data
        await websocket.send_text(json.dumps({
            "type": "initial",
            "sessions": await get_active_sessions_data(),
            "recent_events": await get_recent_events_data(5),
            "alerts": await get_open_alerts_data(5)
        }, default=str))

        # Send periodic updates
        while True:
            await asyncio.sleep(3)

            sessions_data = await get_active_sessions_data()
            await websocket.send_text(json.dumps({
                "type": "sessions_update",
                "data": sessions_data
            }, default=str))

    except WebSocketDisconnect:
        manager.disconnect(websocket)


@router.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint specifically for access events.
    Faster updates (every 1 second) for event monitoring.
    """
    await manager.connect(websocket)

    try:
        while True:
            await asyncio.sleep(1)

            events_data = await get_recent_events_data(10)
            await websocket.send_text(json.dumps({
                "type": "events_update",
                "data": events_data
            }, default=str))

    except WebSocketDisconnect:
        manager.disconnect(websocket)

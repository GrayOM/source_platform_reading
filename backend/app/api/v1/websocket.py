"""Real-time scan progress via WebSocket + Redis pub/sub."""
import asyncio
import json
import uuid

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError
from sqlalchemy import select

from app.core.config import get_settings
from app.core.database import AsyncSessionLocal
from app.core.security import decode_token
from app.models.project import Project
from app.models.scan import Scan

router = APIRouter(tags=["websocket"])
settings = get_settings()


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: uuid.UUID) -> None:
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001)
        return
    try:
        claims = decode_token(token)
        if claims.get("type") != "access":
            raise JWTError("not an access token")
        user_id = uuid.UUID(claims["sub"])
    except (JWTError, KeyError, ValueError):
        await websocket.close(code=4001)
        return

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Scan.id).join(Project).where(Scan.id == scan_id, Project.user_id == user_id)
        )
        if result.scalar_one_or_none() is None:
            await websocket.close(code=4003)
            return

    await websocket.accept()
    r = aioredis.from_url(settings.redis_url)
    channel = f"scan:{scan_id}:progress"
    pubsub = r.pubsub()
    await pubsub.subscribe(channel)

    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                if isinstance(data, bytes):
                    data = data.decode("utf-8")
                await websocket.send_text(data)
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await r.aclose()


async def publish_progress(scan_id: str, data: dict) -> None:
    """Publish progress update; called from Celery workers via sync Redis."""
    import redis as sync_redis
    r = sync_redis.from_url(settings.redis_url)
    r.publish(f"scan:{scan_id}:progress", json.dumps(data))
    r.close()

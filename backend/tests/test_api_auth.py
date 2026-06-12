"""Unit tests for auth API endpoints."""
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app


@pytest.mark.asyncio
async def test_register_and_login():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Register
        r = await client.post("/api/v1/auth/register", json={
            "email": "test@example.com",
            "password": "strongpassword123",
            "full_name": "Test User",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["email"] == "test@example.com"

        # Login
        r = await client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "strongpassword123",
        })
        assert r.status_code == 200
        tokens = r.json()
        assert "access_token" in tokens
        assert "refresh_token" in tokens

        # Get me
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert r.status_code == 200
        assert r.json()["email"] == "test@example.com"


@pytest.mark.asyncio
async def test_invalid_login():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/api/v1/auth/login", json={
            "email": "nobody@example.com",
            "password": "wrongpass",
        })
        assert r.status_code == 401

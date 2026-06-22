"""Pytest configuration and fixtures."""
import asyncio
import os
import pytest

# Point to test database and stub secrets before any app import
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://sss:change_me_strong_password@localhost:5432/sss_test",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")
os.environ.setdefault("SECRET_KEY", "test_secret_key_at_least_32_chars!!")
os.environ.setdefault("FERNET_KEY", "YlVYalI0YW9QY2tOalR4OTBNeURuMERvcElLd29OWlE=")
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-ant-test")
os.environ.setdefault("SCAN_DATA_PATH", "/tmp/sss_test_scans")


async def _reset_test_db() -> None:
    import app.models  # noqa: F401 - register SQLAlchemy models
    from app.core.database import Base, engine

    if "sss_test" not in str(engine.url):
        raise RuntimeError("Refusing to reset a non-test database")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()


def pytest_sessionstart(session: pytest.Session) -> None:
    asyncio.run(_reset_test_db())

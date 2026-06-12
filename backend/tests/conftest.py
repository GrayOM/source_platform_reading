"""Pytest configuration and fixtures."""
import os
import pytest

# Point to test database and stub secrets before any app import
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://sss:test@localhost:5432/sss_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")
os.environ.setdefault("SECRET_KEY", "test_secret_key_at_least_32_chars!!")
os.environ.setdefault("FERNET_KEY", "YlVYalI0YW9QY2tOalR4OTBNeURuMERvcElLd29OWlE=")
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-ant-test")
os.environ.setdefault("SCAN_DATA_PATH", "/tmp/sss_test_scans")

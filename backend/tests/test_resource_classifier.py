"""Unit tests for resource classifier."""
import pytest
from app.services.collector.resource_classifier import classify_url, classify_mime
from app.models.resource import ResourceType


@pytest.mark.parametrize("url,expected", [
    ("https://example.com/app.js", ResourceType.JS),
    ("https://example.com/app.min.js", ResourceType.JS),
    ("https://example.com/bundle.css", ResourceType.CSS),
    ("https://example.com/index.html", ResourceType.HTML),
    ("https://example.com/data.json", ResourceType.JSON),
    ("https://example.com/app.js.map", ResourceType.SOURCE_MAP),
    ("https://example.com/logo.png", ResourceType.IMAGE),
    ("https://example.com/font.woff2", ResourceType.FONT),
])
def test_classify_url(url, expected):
    assert classify_url(url) == expected


@pytest.mark.parametrize("mime,expected", [
    ("application/javascript", ResourceType.JS),
    ("text/javascript", ResourceType.JS),
    ("text/html", ResourceType.HTML),
    ("text/css", ResourceType.CSS),
    ("application/json", ResourceType.JSON),
    ("image/png", ResourceType.IMAGE),
])
def test_classify_mime(mime, expected):
    assert classify_mime(mime) == expected


def test_classify_url_unknown():
    assert classify_url("https://example.com/data") is None


def test_classify_mime_unknown():
    assert classify_mime("application/octet-stream") is None

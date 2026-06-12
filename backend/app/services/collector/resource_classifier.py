import urllib.parse
from pathlib import Path

from app.models.resource import ResourceType

_EXT_MAP: dict[str, ResourceType] = {
    ".js": ResourceType.JS,
    ".mjs": ResourceType.JS,
    ".cjs": ResourceType.JS,
    ".jsx": ResourceType.JS,
    ".ts": ResourceType.JS,
    ".tsx": ResourceType.JS,
    ".html": ResourceType.HTML,
    ".htm": ResourceType.HTML,
    ".css": ResourceType.CSS,
    ".json": ResourceType.JSON,
    ".map": ResourceType.SOURCE_MAP,
    ".png": ResourceType.IMAGE,
    ".jpg": ResourceType.IMAGE,
    ".jpeg": ResourceType.IMAGE,
    ".gif": ResourceType.IMAGE,
    ".svg": ResourceType.IMAGE,
    ".webp": ResourceType.IMAGE,
    ".woff": ResourceType.FONT,
    ".woff2": ResourceType.FONT,
    ".ttf": ResourceType.FONT,
    ".eot": ResourceType.FONT,
    ".pdf": ResourceType.DOCUMENT,
    ".xml": ResourceType.DOCUMENT,
}

_MIME_MAP: dict[str, ResourceType] = {
    "application/javascript": ResourceType.JS,
    "text/javascript": ResourceType.JS,
    "application/x-javascript": ResourceType.JS,
    "text/html": ResourceType.HTML,
    "text/css": ResourceType.CSS,
    "application/json": ResourceType.JSON,
    "application/json+map": ResourceType.SOURCE_MAP,
    "image/png": ResourceType.IMAGE,
    "image/jpeg": ResourceType.IMAGE,
    "image/gif": ResourceType.IMAGE,
    "image/svg+xml": ResourceType.IMAGE,
    "image/webp": ResourceType.IMAGE,
    "font/woff2": ResourceType.FONT,
    "font/woff": ResourceType.FONT,
    "application/pdf": ResourceType.DOCUMENT,
}

ANALYZABLE_TYPES = {ResourceType.JS, ResourceType.HTML, ResourceType.JSON, ResourceType.SOURCE_MAP}


def classify_url(url: str) -> ResourceType | None:
    path = urllib.parse.urlparse(url).path
    ext = Path(path).suffix.lower()
    return _EXT_MAP.get(ext)


def classify_mime(mime: str) -> ResourceType | None:
    return _MIME_MAP.get(mime.lower().split(";")[0].strip())


def is_analyzable(resource_type: ResourceType) -> bool:
    return resource_type in ANALYZABLE_TYPES

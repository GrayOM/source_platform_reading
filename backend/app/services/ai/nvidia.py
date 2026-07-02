"""NVIDIA NIM API adapters.

NVIDIA exposes several model families behind different endpoints. This module
keeps those request shapes in one place so scanner agents do not need to know
which models are chat-compatible, embedding-compatible, or retrieval-specific.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.config import Settings, get_settings


@dataclass(frozen=True)
class PIIEntity:
    text: str
    label: str
    start: int | None = None
    end: int | None = None
    score: float | None = None


class NvidiaNIMClient:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    @property
    def base_url(self) -> str:
        return str(self.settings.nvidia_base_url).rstrip("/")

    def chat_completion(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        api_key: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.1,
        extra_body: dict[str, Any] | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if extra_body:
            payload.update(extra_body)
        data = self._post_json(
            f"{self.base_url}/chat/completions",
            api_key or self.settings.nvidia_key_for("chat"),
            payload,
        )
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("NVIDIA chat response did not include message content") from exc
        if isinstance(content, list):
            return "\n".join(str(item.get("text", item)) if isinstance(item, dict) else str(item) for item in content)
        return str(content)

    def detect_pii(self, text: str, *, model: str | None = None) -> list[PIIEntity]:
        raw = self.chat_completion(
            model=model or self.settings.nvidia_pii_model,
            api_key=self.settings.nvidia_key_for("pii"),
            messages=[
                {
                    "role": "user",
                    "content": f"Find PII spans in this text and return JSON only:\n{text}",
                }
            ],
            max_tokens=2048,
            temperature=0,
        )
        return self._parse_pii_entities(raw)

    def embed(
        self,
        texts: list[str],
        *,
        model: str | None = None,
        purpose: str = "embed",
        input_type: str | None = None,
    ) -> list[list[float]]:
        payload: dict[str, Any] = {
            "model": model or self.settings.nvidia_embed_model,
            "input": texts,
            "encoding_format": "float",
        }
        if input_type:
            payload["input_type"] = input_type
        data = self._post_json(
            f"{self.base_url}/embeddings",
            self.settings.nvidia_key_for(purpose),
            payload,
        )
        return [item["embedding"] for item in data.get("data", []) if isinstance(item.get("embedding"), list)]

    def embed_code(self, texts: list[str], *, input_type: str = "passage") -> list[list[float]]:
        return self.embed(
            texts,
            model=self.settings.nvidia_code_embed_model,
            purpose="code_embed",
            input_type=input_type,
        )

    def rerank(self, query: str, passages: list[str]) -> list[dict[str, Any]]:
        payload = {
            "model": self.settings.nvidia_rerank_model,
            "query": {"text": query},
            "passages": [{"text": passage} for passage in passages],
        }
        data = self._post_json(
            self.settings.nvidia_rerank_url,
            self.settings.nvidia_key_for("rerank"),
            payload,
        )
        return list(data.get("rankings") or [])

    def _post_json(self, url: str, api_key: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not api_key:
            raise RuntimeError("NVIDIA API key is not configured")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=120.0) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            return response.json()

    @staticmethod
    def _parse_pii_entities(raw: str) -> list[PIIEntity]:
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start < 0 or end <= 0:
            return []
        try:
            data = json.loads(raw[start:end])
        except json.JSONDecodeError:
            return []
        entities = data.get("entities") if isinstance(data, dict) else None
        if not isinstance(entities, list):
            return []
        parsed: list[PIIEntity] = []
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            text = str(entity.get("text") or "")
            label = str(entity.get("label") or entity.get("type") or "pii")
            if not text:
                continue
            parsed.append(
                PIIEntity(
                    text=text,
                    label=label,
                    start=entity.get("start") if isinstance(entity.get("start"), int) else None,
                    end=entity.get("end") if isinstance(entity.get("end"), int) else None,
                    score=float(entity["score"]) if isinstance(entity.get("score"), (int, float)) else None,
                )
            )
        return parsed

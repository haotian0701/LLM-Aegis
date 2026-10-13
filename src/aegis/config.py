"""Validated process configuration."""

from __future__ import annotations

import json
import os
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    database_url: str
    api_keys: dict[str, str]
    hmac_key: str = Field(min_length=32)
    run_mode: Literal["strict", "demo"] = "strict"
    demo_provider: Literal["mock"] | None = None
    model_aliases: dict[str, str] = Field(default_factory=lambda: {"aegis-mock": "mock-v1"})
    policy_path: str | None = None
    semantic_url: str | None = None
    semantic_api_key: str | None = None
    semantic_model: str | None = None
    cloud_base_url: str | None = None
    cloud_api_key: str | None = None

    @model_validator(mode="after")
    def validate_security_settings(self) -> Settings:
        if not self.database_url.startswith("postgresql+psycopg://"):
            raise ValueError("database_url must use postgresql+psycopg")
        if not self.api_keys or any(
            not principal or not token for principal, token in self.api_keys.items()
        ):
            raise ValueError("at least one non-empty API token is required")
        if len(set(self.api_keys.values())) != len(self.api_keys):
            raise ValueError("API tokens must be unique across principals")
        if not self.model_aliases or any(
            not alias or not model for alias, model in self.model_aliases.items()
        ):
            raise ValueError("at least one model alias is required")
        if self.run_mode == "strict" and self.demo_provider is not None:
            raise ValueError("strict mode cannot load a demo provider")
        if self.run_mode == "demo" and self.demo_provider != "mock":
            raise ValueError("demo mode requires AEGIS_DEMO_PROVIDER=mock")
        semantic_values = (self.semantic_url, self.semantic_api_key, self.semantic_model)
        if any(semantic_values) and not all(semantic_values):
            raise ValueError("semantic URL, API key and model must all be configured")
        if self.run_mode == "strict" and any(semantic_values):
            raise ValueError("strict mode cannot load an external semantic detector")
        if self.semantic_url is not None:
            self._validate_endpoint(self.semantic_url, "semantic URL")
        if bool(self.cloud_base_url) != bool(self.cloud_api_key):
            raise ValueError("cloud base URL and API key must be configured together")
        if self.run_mode == "strict" and self.cloud_base_url is not None:
            raise ValueError("strict mode cannot load an external cloud provider")
        if self.cloud_base_url is not None:
            self._validate_endpoint(self.cloud_base_url, "cloud base URL")
        return self

    @staticmethod
    def _validate_endpoint(value: str, name: str) -> None:
        parsed = urlsplit(value)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError(f"{name} cannot contain credentials, query or fragment")
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError(f"{name} must use HTTPS outside loopback")
        if not parsed.hostname:
            raise ValueError(f"{name} needs a hostname")

    @classmethod
    def from_env(cls) -> Settings:
        required = ("AEGIS_DATABASE_URL", "AEGIS_API_KEYS_JSON", "AEGIS_HMAC_KEY")
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise ValueError(f"missing required configuration: {', '.join(missing)}")
        try:
            api_keys = json.loads(os.environ["AEGIS_API_KEYS_JSON"])
            model_aliases = json.loads(
                os.environ.get("AEGIS_MODEL_ALIASES_JSON", '{"aegis-mock":"mock-v1"}')
            )
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSON in Aegis configuration") from exc
        return cls.model_validate(
            {
                "database_url": os.environ["AEGIS_DATABASE_URL"],
                "api_keys": api_keys,
                "hmac_key": os.environ["AEGIS_HMAC_KEY"],
                "run_mode": os.environ.get("AEGIS_RUN_MODE", "strict"),
                "demo_provider": os.environ.get("AEGIS_DEMO_PROVIDER") or None,
                "model_aliases": model_aliases,
                "policy_path": os.environ.get("AEGIS_POLICY_PATH") or None,
                "semantic_url": os.environ.get("AEGIS_SEMANTIC_URL") or None,
                "semantic_api_key": os.environ.get("AEGIS_SEMANTIC_API_KEY") or None,
                "semantic_model": os.environ.get("AEGIS_SEMANTIC_MODEL") or None,
                "cloud_base_url": os.environ.get("AEGIS_CLOUD_BASE_URL") or None,
                "cloud_api_key": os.environ.get("AEGIS_CLOUD_API_KEY") or None,
            }
        )

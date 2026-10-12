"""Validated process configuration."""

from __future__ import annotations

import json
import os
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    database_url: str
    api_keys: dict[str, str]
    hmac_key: str = Field(min_length=32)
    run_mode: Literal["strict", "demo"] = "strict"
    demo_provider: Literal["mock"] | None = None
    model_aliases: dict[str, str] = Field(default_factory=lambda: {"aegis-mock": "mock-v1"})

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
        return self

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
            }
        )

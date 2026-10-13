"""Validated policy configuration and deterministic action precedence."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, model_validator


class Category(StrEnum):
    API_KEY = "API_KEY"
    SECRET = "SECRET"
    BUSINESS_SECRET = "BUSINESS_SECRET"
    EMAIL = "EMAIL"
    IBAN = "IBAN"
    PHONE = "PHONE"
    IP_ADDRESS = "IP_ADDRESS"
    PERSON = "PERSON"
    ORGANIZATION = "ORGANIZATION"
    LOCATION = "LOCATION"


class Action(StrEnum):
    CLOUD = "CLOUD"
    MASK_CLOUD = "MASK_CLOUD"
    LOCAL = "LOCAL"
    BLOCK = "BLOCK"


PRECEDENCE = {Action.CLOUD: 0, Action.MASK_CLOUD: 1, Action.LOCAL: 2, Action.BLOCK: 3}
UPGRADE_CATEGORIES = frozenset({Category.API_KEY, Category.SECRET, Category.BUSINESS_SECRET})


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: Category
    action: Action


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_action: Action
    rules: list[PolicyRule]

    @model_validator(mode="after")
    def require_complete_unique_rules(self) -> PolicyConfig:
        categories = [rule.category for rule in self.rules]
        if len(categories) != len(set(categories)) or set(categories) != set(Category):
            raise ValueError("policy needs one rule for every supported category")
        return self


class PolicyEngine:
    def __init__(self, config: PolicyConfig) -> None:
        self.default_action = config.default_action
        self.actions = {rule.category: rule.action for rule in config.rules}

    @classmethod
    def load(cls, path: str | None = None) -> PolicyEngine:
        raw = (
            Path(path).read_text(encoding="utf-8")
            if path is not None
            else files("aegis").joinpath("default_policy.yaml").read_text(encoding="utf-8")
        )
        try:
            parsed = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise ValueError("invalid policy YAML") from exc
        return cls(PolicyConfig.model_validate(parsed))

    def decide(self, categories: Iterable[Category], *, was_sensitive: bool) -> Action:
        actions = [self.default_action]
        actions.extend(self.actions[category] for category in categories)
        if was_sensitive:
            actions.append(Action.LOCAL)
        return max(actions, key=PRECEDENCE.__getitem__)

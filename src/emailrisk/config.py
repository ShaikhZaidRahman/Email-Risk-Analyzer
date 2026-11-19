"""Scoring weights, thresholds and runtime options."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_WEIGHTS: dict[str, int] = {
    # Authentication
    "AUTH-SPF-FAIL": 20,
    "AUTH-SPF-SOFTFAIL": 10,
    "AUTH-SPF-NONE": 8,
    "AUTH-DKIM-FAIL": 20,
    "AUTH-DKIM-NONE": 8,
    "AUTH-DMARC-FAIL": 15,
    "AUTH-DKIM-ALIGN": 8,
    "AUTH-DKIM-WEAK": 4,
    # Header consistency
    "HDR-REPLYTO": 18,
    "HDR-RETURNPATH": 6,
    "HDR-DISPLAYNAME": 15,
    "HDR-MSGID": 3,
    "HDR-NORECEIVED": 5,
    "HDR-TIMESKEW": 5,
    # Links
    "LNK-UNRELATED": 10,
    "LNK-RESERVED-TLD": 10,
    "LNK-SUSPICIOUS-TLD": 6,
    "LNK-IP": 20,
    "LNK-USERINFO": 20,
    "LNK-PUNYCODE": 18,
    "LNK-SHORTENER": 8,
    "LNK-MISMATCH": 20,
    "LNK-LOOKALIKE": 20,
    "LNK-BRAND": 15,
    "LNK-HTTP": 4,
    "LNK-DEEPSUB": 4,
    "BODY-FORM": 15,
    # Language
    "BODY-URGENCY": 8,
    "BODY-THREAT": 8,
    "BODY-CREDENTIAL": 10,
    # Attachments
    "ATT-RISKY": 25,
    "ATT-DOUBLEEXT": 25,
    "ATT-ARCHIVE": 10,
    "ATT-GENERIC": 8,
}


class ConfigError(ValueError):
    """Raised for an invalid configuration file."""


@dataclass(frozen=True, slots=True)
class Config:
    weights: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    medium_threshold: int = 25
    high_threshold: int = 60
    trusted_domains: frozenset[str] = frozenset()
    authserv_ids: frozenset[str] = frozenset()
    max_urls: int = 200
    max_message_bytes: int = 25 * 1024 * 1024

    def w(self, rule: str) -> int:
        return self.weights[rule]

    def level_for(self, score: int) -> str:
        if score >= self.high_threshold:
            return "High"
        return "Medium" if score >= self.medium_threshold else "Low"

    @classmethod
    def from_file(cls, path: Path, **overrides: Any) -> Config:
        """Load a JSON file with optional ``weights``, ``thresholds`` and ``trusted_domains``."""
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read config {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError("config must be a JSON object")
        unknown_top = set(raw) - {"weights", "thresholds", "trusted_domains"}
        if unknown_top:
            raise ConfigError(f"unknown config keys: {sorted(unknown_top)}")
        weights = dict(DEFAULT_WEIGHTS)
        for key, value in (raw.get("weights") or {}).items():
            if key not in DEFAULT_WEIGHTS:
                raise ConfigError(f"unknown rule id in weights: {key}")
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100:
                raise ConfigError(f"weight for {key} must be an integer 0-100")
            weights[key] = value
        thresholds = raw.get("thresholds") or {}
        medium = thresholds.get("medium", 25)
        high = thresholds.get("high", 60)
        if not (isinstance(medium, int) and isinstance(high, int) and 0 < medium < high <= 100):
            raise ConfigError("thresholds must satisfy 0 < medium < high <= 100")
        trusted = frozenset(str(d).lower() for d in raw.get("trusted_domains") or [])
        return cls(
            weights=weights,
            medium_threshold=medium,
            high_threshold=high,
            trusted_domains=trusted | overrides.get("trusted_domains", frozenset()),
            authserv_ids=overrides.get("authserv_ids", frozenset()),
        )

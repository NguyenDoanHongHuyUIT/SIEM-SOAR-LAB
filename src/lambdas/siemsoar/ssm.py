"""Cached SSM Parameter Store reads (secrets never live in env vars or Terraform state)."""

from __future__ import annotations

import time

from . import aws

_CACHE: dict[str, tuple[float, str]] = {}
TTL = 300


def get_param(name: str, default: str | None = None) -> str | None:
    hit = _CACHE.get(name)
    if hit and hit[0] > time.time():
        return hit[1]
    try:
        value = aws.client("ssm").get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    except aws.client("ssm").exceptions.ParameterNotFound:
        return default
    _CACHE[name] = (time.time() + TTL, value)
    return value


def clear() -> None:
    _CACHE.clear()

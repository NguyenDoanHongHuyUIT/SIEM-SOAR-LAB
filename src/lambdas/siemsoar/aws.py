"""Cached boto3 clients. Tests call reset() after patching credentials/env."""

from __future__ import annotations

import os
from functools import cache

import boto3
from botocore.config import Config

_CFG = Config(retries={"max_attempts": 5, "mode": "standard"}, connect_timeout=3, read_timeout=10)
_FAST_CFG = Config(retries={"total_max_attempts": 1, "mode": "standard"}, connect_timeout=1, read_timeout=1)


def region() -> str:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"


@cache
def client(service: str):
    return boto3.client(service, region_name=region(), config=_CFG)


@cache
def fast_client(service: str):
    """One attempt and short timeouts, for a call that must never hold up the caller (a best-effort follow-up)."""
    return boto3.client(service, region_name=region(), config=_FAST_CFG)


@cache
def resource(service: str):
    return boto3.resource(service, region_name=region(), config=_CFG)


def reset() -> None:
    client.cache_clear()
    fast_client.cache_clear()
    resource.cache_clear()

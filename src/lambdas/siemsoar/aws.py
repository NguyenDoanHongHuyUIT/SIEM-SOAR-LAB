"""Cached boto3 clients. Tests call reset() after patching credentials/env."""

from __future__ import annotations

import os
from functools import cache

import boto3
from botocore.config import Config

_CFG = Config(retries={"max_attempts": 5, "mode": "standard"}, connect_timeout=3, read_timeout=10)


def region() -> str:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "ap-southeast-1"


@cache
def client(service: str):
    return boto3.client(service, region_name=region(), config=_CFG)


@cache
def resource(service: str):
    return boto3.resource(service, region_name=region(), config=_CFG)


def reset() -> None:
    client.cache_clear()
    resource.cache_clear()

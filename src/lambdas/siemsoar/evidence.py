"""Immutable-ish evidence in S3 (versioning + Object Lock on the bucket, write-once by convention)."""

from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from . import aws
from .config import settings


class EvidenceExists(Exception):
    pass


def put_json(case_id: str, name: str, obj: dict) -> dict:
    """Write cases/<case>/<name>.json exactly once: S3 conditional write (If-None-Match) makes the first capture win
    atomically, with no check-then-write race. Raises EvidenceExists when the object is already there."""
    bucket = settings().evidence_bucket
    key = f"cases/{case_id}/{name}.json"
    body = json.dumps(obj, indent=2, sort_keys=True, default=str).encode()
    digest = hashlib.sha256(body).hexdigest()
    try:
        aws.client("s3").put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/json",
                                    Metadata={"sha256": digest, "case-id": case_id}, IfNoneMatch="*")
    except ClientError as err:
        if err.response["Error"]["Code"] in {"PreconditionFailed", "ConditionalRequestConflict"}:
            raise EvidenceExists(key) from err
        raise
    return {"bucket": bucket, "key": key, "sha256": digest}


def get_json(case_id: str, name: str) -> tuple[dict, str]:
    """Returns (object, sha256 computed from the stored bytes)."""
    res = aws.client("s3").get_object(Bucket=settings().evidence_bucket, Key=f"cases/{case_id}/{name}.json")
    body = res["Body"].read()
    return json.loads(body), hashlib.sha256(body).hexdigest()

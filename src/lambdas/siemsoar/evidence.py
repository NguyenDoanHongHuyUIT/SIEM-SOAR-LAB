"""Immutable-ish evidence in S3 (versioning + Object Lock on the bucket, write-once by convention)."""

from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from . import aws
from .config import settings


class EvidenceExists(Exception):
    pass


def put_json(case_id: str, name: str, obj: dict, overwrite: bool = False) -> dict:
    """Write evidence/<case>/<name>.json. Refuses to overwrite so the first capture is the truth."""
    bucket = settings().evidence_bucket
    key = f"cases/{case_id}/{name}.json"
    s3 = aws.client("s3")
    if not overwrite:
        try:
            s3.head_object(Bucket=bucket, Key=key)
            raise EvidenceExists(key)
        except ClientError as err:
            if err.response["Error"]["Code"] not in {"404", "NoSuchKey", "NotFound"}:
                raise
    body = json.dumps(obj, indent=2, sort_keys=True, default=str).encode()
    digest = hashlib.sha256(body).hexdigest()
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/json",
                  Metadata={"sha256": digest, "case-id": case_id})
    return {"bucket": bucket, "key": key, "sha256": digest}


def get_json(case_id: str, name: str) -> tuple[dict, str]:
    """Returns (object, sha256 computed from the stored bytes)."""
    res = aws.client("s3").get_object(Bucket=settings().evidence_bucket, Key=f"cases/{case_id}/{name}.json")
    body = res["Body"].read()
    return json.loads(body), hashlib.sha256(body).hexdigest()

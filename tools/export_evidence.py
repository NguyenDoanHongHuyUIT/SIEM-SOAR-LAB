"""Export everything needed for the thesis appendix BEFORE tearing the lab down (paper 5.2, group 8).

  python -m tools.export_evidence [--prefix siemsoar] [--out evidence-export]

Writes cases.json (cases + audit trail), runs.json, deployments.json, the S3 evidence objects, release manifests and
a SHA-256 manifest of every exported file, so the report can cite immutable artefacts after `terraform destroy`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src" / "lambdas"))


def export(prefix: str, out: Path) -> dict:
    os.environ.setdefault("NAME_PREFIX", prefix)
    os.environ.setdefault("CASES_TABLE", f"{prefix}-cases")
    from siemsoar import aws
    from siemsoar.store import CaseStore

    store = CaseStore()
    account = aws.client("sts").get_caller_identity()["Account"]
    out.mkdir(parents=True, exist_ok=True)

    cases = store.list_cases()
    for c in cases:
        c["audit"] = store.list_audit(c["case_id"])
    (out / "cases.json").write_text(json.dumps(cases, indent=2, default=str))
    (out / "runs.json").write_text(json.dumps(store.list_runs(), indent=2, default=str))

    s3, copied = aws.client("s3"), 0
    for bucket, prefix_key in ((f"{prefix}-evidence-{account}", ""), (f"{prefix}-rules-{account}", "releases/")):
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix_key):
            for obj in page.get("Contents", []):
                target = out / "s3" / bucket / obj["Key"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read())
                copied += 1

    deployments = [json.loads(p.read_text()) for p in (out / "s3").rglob("deployment.json")]
    (out / "deployments.json").write_text(json.dumps(deployments, indent=2))

    manifest = {"exported_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "account": account,
                "cases": len(cases), "s3_objects": copied,
                "files": {p.relative_to(out).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sorted(out.rglob("*")) if p.is_file() and p.name != "MANIFEST.json"}}
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", default="siemsoar")
    ap.add_argument("--out", default="evidence-export")
    args = ap.parse_args(argv)
    out = Path(args.out) / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    m = export(args.prefix, out)
    print(f"exported {m['cases']} cases and {m['s3_objects']} S3 objects to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Publish / deploy / roll back a rule release (used by .github/workflows/rules-deploy.yml).

  python -m tools.release publish  --dist dist --sha <sha> [--commit-time ISO] [--no-deploy]
  python -m tools.release rollback --sha <older sha>
  python -m tools.release status

S3 layout (rules bucket):  releases/<sha>/{wazuh,suricata,manifest.json,deployment.json}   releases/current.json
`current.json` only moves after EVERY reachable target accepted the release (host-side validation + auto rollback
happen in scripts/deploy_rules.sh). If the on-demand plane is off, the release is stored and picked up at next boot.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src" / "lambdas"))

from siemsoar import aws  # noqa: E402

TARGETS = {"manager": "wazuh-manager", "sensor": "suricata-sensor"}


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def bucket_name(prefix: str) -> str:
    return f"{prefix}-rules-{aws.client('sts').get_caller_identity()['Account']}"


def upload(dist: Path, sha: str, bucket: str) -> list[str]:
    s3, keys = aws.client("s3"), []
    base = dist / sha
    for path in sorted(base.rglob("*")):
        if path.is_file():
            key = f"releases/{sha}/{path.relative_to(base).as_posix()}"
            s3.upload_file(str(path), bucket, key)
            keys.append(key)
    return keys


def set_current(sha: str, bucket: str) -> None:
    aws.client("s3").put_object(Bucket=bucket, Key="releases/current.json", ContentType="application/json",
                                Body=json.dumps({"sha": sha, "set_at": _now()}).encode())


def get_current(bucket: str) -> str | None:
    try:
        body = aws.client("s3").get_object(Bucket=bucket, Key="releases/current.json")["Body"].read()
        return json.loads(body)["sha"]
    except aws.client("s3").exceptions.NoSuchKey:
        return None


def running_instances(role: str) -> list[str]:
    res = aws.client("ec2").describe_instances(Filters=[
        {"Name": "tag:siemsoar:role", "Values": [role]}, {"Name": "tag:siemsoar:plane", "Values": ["ondemand"]},
        {"Name": "instance-state-name", "Values": ["running"]}])
    return [i["InstanceId"] for r in res["Reservations"] for i in r["Instances"]]


def deploy_target(prefix: str, target: str, sha: str, timeout: int = 900, poll: float = 5.0) -> dict:
    ids = running_instances(TARGETS[target])
    if not ids:
        return {"target": target, "status": "skipped_lab_off", "instances": []}
    ssm = aws.client("ssm")
    cmd = ssm.send_command(InstanceIds=ids, DocumentName=f"{prefix}-deploy-rules",
                           Parameters={"Target": [target], "Release": [sha]}, TimeoutSeconds=600,
                           Comment=f"siemsoar rules {sha[:8]}")["Command"]["CommandId"]
    end, results = time.time() + timeout, {}
    while time.time() < end and len(results) < len(ids):
        for iid in ids:
            if iid in results:
                continue
            inv = ssm.get_command_invocation(CommandId=cmd, InstanceId=iid)
            if inv["Status"] in {"Success", "Failed", "Cancelled", "TimedOut"}:
                results[iid] = {"status": inv["Status"], "stderr": inv.get("StandardErrorContent", "")[-500:]}
        time.sleep(poll)
    ok = len(results) == len(ids) and all(r["status"] == "Success" for r in results.values())
    return {"target": target, "status": "deployed" if ok else "failed", "instances": results}


def record(bucket: str, sha: str, commit_time: str | None, results: list[dict]) -> dict:
    """deployment.json feeds the 'rule deployment lead time' metric (commit -> active on every reachable target)."""
    doc = {"sha": sha, "commit_time": commit_time, "deployed_at": _now(), "targets": results}
    aws.client("s3").put_object(Bucket=bucket, Key=f"releases/{sha}/deployment.json",
                                ContentType="application/json", Body=json.dumps(doc, indent=2).encode())
    return doc


def publish(prefix: str, dist: Path, sha: str, commit_time: str | None, deploy: bool = True) -> dict:
    bucket = bucket_name(prefix)
    upload(dist, sha, bucket)
    results = [deploy_target(prefix, t, sha) for t in TARGETS] if deploy else []
    if any(r["status"] == "failed" for r in results):
        record(bucket, sha, commit_time, results)
        raise SystemExit(f"deployment failed, `current` stays on {get_current(bucket)}: {json.dumps(results)[:800]}")
    set_current(sha, bucket)
    return record(bucket, sha, commit_time, results)


def rollback(prefix: str, sha: str) -> dict:
    bucket = bucket_name(prefix)
    if not aws.client("s3").list_objects_v2(Bucket=bucket, Prefix=f"releases/{sha}/manifest.json").get("Contents"):
        raise SystemExit(f"release {sha} not found in s3://{bucket}/releases/")
    results = [deploy_target(prefix, t, sha) for t in TARGETS]
    if any(r["status"] == "failed" for r in results):
        raise SystemExit(f"rollback deployment failed: {json.dumps(results)[:800]}")
    set_current(sha, bucket)
    return {"rolled_back_to": sha, "targets": results}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tools.release")
    ap.add_argument("--prefix", default=os.environ.get("NAME_PREFIX", "siemsoar"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("publish")
    p.add_argument("--dist", default="dist")
    p.add_argument("--sha", required=True)
    p.add_argument("--commit-time")
    p.add_argument("--no-deploy", action="store_true")
    r = sub.add_parser("rollback")
    r.add_argument("--sha", required=True)
    sub.add_parser("status")
    args = ap.parse_args(argv)
    if args.cmd == "publish":
        print(json.dumps(publish(args.prefix, Path(args.dist), args.sha, args.commit_time, not args.no_deploy), indent=2))
    elif args.cmd == "rollback":
        print(json.dumps(rollback(args.prefix, args.sha), indent=2))
    else:
        print(json.dumps({"current": get_current(bucket_name(args.prefix))}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

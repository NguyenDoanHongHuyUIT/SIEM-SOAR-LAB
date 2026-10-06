#!/usr/bin/env python3
"""Wazuh custom integration: forward an alert (rule groups siemsoar_active/siemsoar_enforce) to EventBridge.

Invoked by integratord as:  custom-eventbridge <alert_file> <api_key> <hook_url> [debug]
hook_url format:            eventbridge://<event-bus-name>?region=<aws-region>
"""

from __future__ import annotations

import json
import sys
import urllib.parse

MAX_DETAIL_BYTES = 200_000
FULL_LOG_LIMIT = 4000


def parse_hook(hook_url: str) -> tuple[str, str | None]:
    parsed = urllib.parse.urlparse(hook_url)
    if parsed.scheme != "eventbridge":
        raise ValueError(f"unsupported hook_url {hook_url!r}")
    bus = parsed.netloc or "default"
    region = urllib.parse.parse_qs(parsed.query).get("region", [None])[0]
    return bus, region


def build_entry(alert: dict, bus: str) -> dict:
    """Trim the alert so it always fits EventBridge's 256 KB limit, keeping the fields normalisation needs."""
    alert = dict(alert)
    if isinstance(alert.get("full_log"), str):
        alert["full_log"] = alert["full_log"][:FULL_LOG_LIMIT]
    detail = json.dumps(alert)
    if len(detail.encode()) > MAX_DETAIL_BYTES:
        for heavy in ("syscheck", "data"):
            alert.pop(heavy, None)
            detail = json.dumps(alert)
            if len(detail.encode()) <= MAX_DETAIL_BYTES:
                break
    return {"Source": "siemsoar.wazuh", "DetailType": "Wazuh Alert", "Detail": detail, "EventBusName": bus}


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: custom-eventbridge <alert_file> <api_key> <hook_url> [debug]", file=sys.stderr)
        return 2
    alert_file, _api_key, hook_url = argv[1:4]
    with open(alert_file, encoding="utf-8") as fh:
        alert = json.load(fh)
    bus, region = parse_hook(hook_url)

    import boto3  # imported late so the module can be unit tested without boto3 configured

    client = boto3.client("events", region_name=region)
    res = client.put_events(Entries=[build_entry(alert, bus)])
    if res.get("FailedEntryCount"):
        print(f"put_events failed: {res['Entries']}", file=sys.stderr)
        return 1
    if len(argv) > 4:
        print(f"forwarded alert {alert.get('id')} rule {alert.get('rule', {}).get('id')}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

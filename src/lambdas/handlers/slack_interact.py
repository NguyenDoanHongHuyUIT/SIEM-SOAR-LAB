"""API Gateway (HTTP API v2) endpoint for Slack interactive buttons.

Defence in depth: HMAC signature + 5 min replay window, approver allow-list, case-state guard,
single-use server-side task token. The Slack payload only carries `case_id|gate|decision`.
"""

from __future__ import annotations

import base64
import json

from siemsoar import slack
from siemsoar.config import settings
from siemsoar.decisions import DecisionRejected, apply_decision
from siemsoar.ssm import get_param
from siemsoar.store import CaseNotFound, CaseStore
from siemsoar.util import get_logger

log = get_logger("handlers.slack_interact")


def _resp(status: int, body: dict | None = None) -> dict:
    return {"statusCode": status, "headers": {"content-type": "application/json"}, "body": json.dumps(body or {})}


def _ephemeral(text: str) -> dict:
    return _resp(200, {"response_type": "ephemeral", "text": text})


def handler(event, context=None):
    prefix = settings().name_prefix
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode()

    secret = get_param(f"/{prefix}/slack/signing_secret")
    if not secret or secret == "CHANGE_ME" or not slack.verify_signature(
            secret, headers.get("x-slack-request-timestamp", ""), body, headers.get("x-slack-signature", "")):
        log.warning("rejected request: bad signature")
        return _resp(401, {"error": "invalid signature"})
    if headers.get("x-slack-retry-num"):  # Slack retry of a request we already handled
        return _resp(200)

    payload = slack.parse_interaction(body)
    if payload.get("type") != "block_actions" or not payload.get("actions"):
        return _resp(200)

    user = payload["user"]["id"]
    raw_approvers = get_param(f"/{prefix}/slack/approver_ids", "") or ""
    approvers = {a.strip() for a in raw_approvers.split(",") if a.strip() and a.strip() != "CHANGE_ME"}
    case_id, gate, decision = (payload["actions"][0]["value"].split("|") + ["", "", ""])[:3]
    store = CaseStore()
    if user not in approvers:
        try:
            store.audit(case_id, "decision_denied", f"slack:{user}", {"reason": "not_in_approver_list"})
        except Exception:
            log.warning("audit of denial failed", exc_info=True)
        return _ephemeral(":no_entry: You are not an authorised approver.")

    try:
        apply_decision(store, case_id, gate, decision, actor=f"slack:{user}", channel="slack")
    except (DecisionRejected, CaseNotFound) as err:
        return _ephemeral(f":warning: {err}")
    slack.respond(payload.get("response_url", ""), f"{case_id}: {decision}",
                  slack.decided_blocks(case_id, f"*{decision}* by <@{user}>"))
    return _resp(200)

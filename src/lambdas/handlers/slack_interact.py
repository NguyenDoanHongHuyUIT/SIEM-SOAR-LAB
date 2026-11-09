"""API Gateway (HTTP API v2) endpoint for Slack interactive buttons.

Defence in depth: HMAC signature + 5 min replay window, approver allow-list, case-state guard,
single-use server-side task token. The Slack payload only carries `case_id|gate|decision`.
"""

from __future__ import annotations

import base64
import json
import logging
import os

from siemsoar import aws, notifier, slack
from siemsoar.config import settings
from siemsoar.decisions import DecisionRejected, apply_decision
from siemsoar.ssm import get_param
from siemsoar.store import CaseNotFound, CaseStore

log = logging.getLogger("handlers.slack_interact")


def _resp(status: int, body: dict | None = None) -> dict:
    return {"statusCode": status, "headers": {"content-type": "application/json"}, "body": json.dumps(body or {})}


def _ephemeral(text: str) -> dict:
    return _resp(200, {"response_type": "ephemeral", "text": text})


def _defer_close_card(job: dict) -> None:
    """Slack wants the ack within 3 s and Lambda answers only when the handler returns, so the Slack HTTP calls that
    replace the card run in a second, asynchronous invocation of this function. The decision (single-use token, Step
    Functions callback) is already complete here. Best effort: a card left with its buttons only rejects a later click."""
    try:
        aws.fast_client("lambda").invoke(FunctionName=os.environ["AWS_LAMBDA_FUNCTION_NAME"], InvocationType="Event",
                                         Payload=json.dumps({"close_card": job}).encode())
    except Exception:  # noqa: BLE001 - the decision stands and Slack must still get its ack
        log.warning("could not schedule the slack card update", exc_info=True)


def _close_card(job: dict) -> dict:
    case_id, decision = job["case_id"], job["decision"]
    text = f"*{decision}* by <@{job['user']}>"
    if job["response_url"].startswith(slack.RESPONSE_URL_PREFIX):
        slack.respond(job["response_url"], f"{case_id}: {decision}", slack.decided_blocks(case_id, text))
    else:
        notifier.close_card(CaseStore().get_case(case_id), text)
    return {}


def handler(event, context=None):
    if "close_card" in event:  # our own follow-up (_defer_close_card): an API Gateway event has no such key
        return _close_card(event["close_card"])
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
        apply_decision(store, case_id, gate, decision, actor=f"slack:{user}", channel="slack", update_card=False)
    except (DecisionRejected, CaseNotFound) as err:
        return _ephemeral(f":warning: {err}")
    _defer_close_card({"case_id": case_id, "decision": decision, "user": user,
                       "response_url": payload.get("response_url", "")})
    return _resp(200)

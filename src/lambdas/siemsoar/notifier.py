"""Notifications: Slack (primary, interactive) + SNS email (always sent: fallback & audit copy)."""

from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from . import aws, faults, slack
from .config import settings
from .ssm import get_param

log = logging.getLogger("notify")


def sns_publish(subject: str, text: str) -> None:
    topic = settings().topic_arn
    if not topic:
        raise RuntimeError("NOTIFY_TOPIC_ARN not configured")
    aws.client("sns").publish(TopicArn=topic, Subject=subject[:100], Message=text)


def _slack_target() -> tuple[str | None, str | None]:
    prefix = settings().name_prefix
    token = get_param(f"/{prefix}/slack/bot_token")
    channel = settings().slack_channel or get_param(f"/{prefix}/slack/channel")
    if not token or token == "CHANGE_ME" or not channel or channel == "CHANGE_ME":
        return None, None
    return token, channel


def slack_post(case: dict, text: str, blocks: list[dict]) -> dict | None:
    """The posted message ({channel, ts}), or None (never raises) when Slack is down/misconfigured so SNS can carry
    the notice."""
    token, channel = _slack_target()
    if not token:
        log.warning("slack not configured; using SNS fallback only")
        return None
    try:
        faults.maybe_fail("notify.slack")
        out = slack.post_message(token, channel, text, blocks)
        return {"channel": out.get("channel", channel), "ts": out.get("ts")}
    except Exception:
        log.warning("slack post failed; using SNS fallback", exc_info=True)
        return None


def close_card(case: dict, text: str) -> bool:
    """Replace the case's decision card (buttons) by the outcome, whatever channel the decision came from: a card that
    still shows buttons after a CLI decision invites a click that can only be rejected. Best effort."""
    card = case.get("slack_card") or {}
    token, _ = _slack_target()
    if not (token and card.get("ts") and card.get("channel")):
        return False
    try:
        slack.update_message(token, card["channel"], card["ts"], text, slack.decided_blocks(case["case_id"], text))
        return True
    except Exception:
        log.warning("could not close the slack card", exc_info=True)
        return False


def approval_email(case: dict, gate: str) -> str:
    cid, prefix = case["case_id"], settings().name_prefix
    verbs = ("approve | dismiss" if case.get("response_plan", {}).get("type", "none") != "none"
             else "acknowledge | dismiss") if gate == "approval" else "restore_tp | restore_fp"
    return (
        f"{case['title']}\nCase: {cid}\nStatus: {case.get('status')}\nSource: {case['source']} "
        f"rule={case['rule_id']}\nResource: {case['resource'].get('type')} {case['resource'].get('id')}\n"
        f"Risk: {case.get('risk_score')}/100  Plan: {case.get('response_plan', {}).get('type')}\n\n"
        f"Fallback decision channel (needs AWS credentials, so it is not forgeable from email):\n"
        f"  python -m tools.soarctl decide {cid} --gate {gate} --decision <{verbs}> --approver <your Slack member id>\n"
        f"  (interactive: you retype the case id; only listed approvers are accepted)\n"
        f"(table prefix: {prefix})\n")


def notify_case(case: dict, kind: str, gate: str | None = None, extra: str = "") -> dict:
    titles = {"approval": ":warning: Approval required", "restore": ":shield: Restore decision required",
              "isolated": ":lock: Containment verified", "restored": ":white_check_mark: Restored",
              "expired": ":hourglass: Approval expired", "failed": ":x: Workflow failed (fail-safe)",
              "blocked": ":no_entry: Restore blocked", "acknowledged": ":ballot_box_with_check: Acknowledged",
              "dismissed": ":broom: Dismissed as false positive"}
    title = titles.get(kind, kind)
    if gate:
        blocks = slack.card_blocks(case, gate)
        body = approval_email(case, gate)
    else:
        blocks = slack.info_blocks(title, case, extra)
        body = f"{title.split(' ', 1)[-1]}\nCase: {case['case_id']}\n{extra}"
    posted = slack_post(case, f"{title}: {case['title']}", blocks)
    sent_slack = posted is not None
    try:
        sns_publish(f"[SIEM-SOAR] {kind}: {case['title']}", body + (f"\n{extra}" if extra and gate else ""))
        sent_sns = True
    except (ClientError, RuntimeError):
        log.error("sns publish failed", exc_info=True)
        sent_sns = False
    if not (sent_slack or sent_sns):
        raise RuntimeError("no notification channel available")
    out: dict = {"slack": sent_slack, "sns": sent_sns}
    if gate and posted and posted.get("ts"):
        out["card"] = {"gate": gate, **posted}  # popped by the caller and stored on the case
    return out

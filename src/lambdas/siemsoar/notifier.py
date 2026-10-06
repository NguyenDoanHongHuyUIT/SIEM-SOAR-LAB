"""Notifications: Slack (primary, interactive) + SNS email (always sent: fallback & audit copy)."""

from __future__ import annotations

from botocore.exceptions import ClientError

from . import aws, slack
from .config import settings
from .ssm import get_param
from .util import get_logger

log = get_logger("notify")


def sns_publish(subject: str, text: str) -> None:
    topic = settings().topic_arn
    if not topic:
        raise RuntimeError("NOTIFY_TOPIC_ARN not configured")
    aws.client("sns").publish(TopicArn=topic, Subject=subject[:100], Message=text)


def slack_post(case: dict, text: str, blocks: list[dict]) -> bool:
    """Returns False (never raises) when Slack is down/misconfigured so SNS can carry the notice."""
    prefix = settings().name_prefix
    token = get_param(f"/{prefix}/slack/bot_token")
    channel = settings().slack_channel or get_param(f"/{prefix}/slack/channel")
    if not token or token == "CHANGE_ME" or not channel:
        log.warning("slack not configured; using SNS fallback only")
        return False
    try:
        slack.post_message(token, channel, text, blocks)
        return True
    except Exception:
        log.warning("slack post failed; using SNS fallback", exc_info=True)
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
        f"  python -m tools.soarctl decide {cid} --gate {gate} --decision <{verbs}>\n"
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
    sent_slack = slack_post(case, f"{title}: {case['title']}", blocks)
    try:
        sns_publish(f"[SIEM-SOAR] {kind}: {case['title']}", body + (f"\n{extra}" if extra and gate else ""))
        sent_sns = True
    except (ClientError, RuntimeError):
        log.error("sns publish failed", exc_info=True)
        sent_sns = False
    if not (sent_slack or sent_sns):
        raise RuntimeError("no notification channel available")
    return {"slack": sent_slack, "sns": sent_sns}

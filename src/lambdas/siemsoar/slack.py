"""Slack integration (stdlib only): request signature check, Block Kit cards, message posting."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .util import get_logger

log = get_logger("slack")
SIG_TOLERANCE = 300

SEV_EMOJI = {"critical": ":rotating_light:", "high": ":red_circle:", "medium": ":large_orange_circle:",
             "low": ":large_yellow_circle:", "info": ":white_circle:"}


def verify_signature(signing_secret: str, timestamp: str, body: str, signature: str,
                     now: float | None = None) -> bool:
    """Slack v0 signing: reject stale timestamps (replay) and compare in constant time."""
    try:
        if abs((now or time.time()) - int(timestamp)) > SIG_TOLERANCE:
            return False
    except (TypeError, ValueError):
        return False
    base = f"v0:{timestamp}:{body}".encode()
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def parse_interaction(body: str) -> dict:
    """Slack sends application/x-www-form-urlencoded with a JSON `payload` field."""
    form = urllib.parse.parse_qs(body, keep_blank_values=True)
    return json.loads(form["payload"][0])


def _facts(case: dict) -> str:
    res = case.get("resource", {})
    plan = case.get("response_plan", {}).get("type", "none")
    enr = case.get("enrichment", {})
    lines = [
        f"*Source:* `{case['source']}`  *Rule:* `{case['rule_id']}`",
        f"*Resource:* `{res.get('type')}` `{res.get('id')}`"
        + (f"  _{enr.get('name')}_" if enr.get("name") else ""),
        f"*Risk:* {case.get('risk_score', '?')}/100 ({case.get('severity_label')})  "
        f"*Alerts:* {case.get('alert_count', 1)}",
        f"*Planned response:* `{plan}`",
    ]
    if case.get("mitre"):
        lines.append("*ATT&CK:* " + ", ".join(case["mitre"]))
    return "\n".join(lines)


def _button(text: str, value: str, action_id: str, style: str | None = None, confirm: str | None = None) -> dict:
    btn: dict = {"type": "button", "text": {"type": "plain_text", "text": text}, "value": value,
                 "action_id": action_id}
    if style:
        btn["style"] = style
    if confirm:
        btn["confirm"] = {"title": {"type": "plain_text", "text": "Are you sure?"},
                          "text": {"type": "mrkdwn", "text": confirm},
                          "confirm": {"type": "plain_text", "text": "Yes"},
                          "deny": {"type": "plain_text", "text": "Cancel"}}
    return btn


def card_blocks(case: dict, gate: str) -> list[dict]:
    """Cards carry only case_id|gate|decision. The Step Functions task token stays server side."""
    cid = case["case_id"]
    emoji = SEV_EMOJI.get(case.get("severity_label", "info"), ":white_circle:")
    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{case['title']}"[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"{emoji} *Case* `{cid}`\n{_facts(case)}"}},
    ]
    if case.get("description"):
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": case["description"][:280]}]})
    if gate == "approval":
        if case.get("response_plan", {}).get("type", "none") == "none":
            actions = [_button("Acknowledge", f"{cid}|approval|acknowledge", "decide", "primary"),
                       _button("False positive", f"{cid}|approval|dismiss", "decide")]
        else:
            actions = [_button("Approve containment", f"{cid}|approval|approve", "decide", "danger",
                               "This will isolate/disable the resource."),
                       _button("Dismiss (false positive)", f"{cid}|approval|dismiss", "decide")]
    else:
        actions = [_button("Restore: threat remediated", f"{cid}|restore|restore_tp", "decide", "primary",
                           "Restore original access after remediation?"),
                   _button("Restore: false positive", f"{cid}|restore|restore_fp", "decide")]
    blocks.append({"type": "actions", "block_id": f"{gate}:{cid}", "elements": actions})
    return blocks


def info_blocks(title: str, case: dict, text: str) -> list[dict]:
    return [{"type": "section", "text": {"type": "mrkdwn",
                                         "text": f"*{title}* `{case['case_id']}`\n{text}\n{_facts(case)}"}}]


def decided_blocks(case_id: str, text: str) -> list[dict]:
    return [{"type": "section", "text": {"type": "mrkdwn", "text": f"`{case_id}` {text}"}}]


def _request(url: str, payload: dict, headers: dict, timeout: float = 3.0) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only, fixed hosts)
        body = resp.read().decode() or "{}"
    return json.loads(body) if body.startswith("{") else {"ok": True}


def post_message(bot_token: str, channel: str, text: str, blocks: list[dict]) -> dict:
    out = _request("https://slack.com/api/chat.postMessage",
                   {"channel": channel, "text": text, "blocks": blocks},
                   {"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json; charset=utf-8"})
    if not out.get("ok"):
        raise RuntimeError(f"slack api error: {out.get('error')}")
    return out


def respond(response_url: str, text: str, blocks: list[dict]) -> None:
    """Replace the original card after a decision (best effort)."""
    if not response_url.startswith("https://hooks.slack.com/"):
        return
    try:
        _request(response_url, {"replace_original": True, "text": text, "blocks": blocks},
                 {"Content-Type": "application/json"})
    except (urllib.error.URLError, TimeoutError, OSError):
        log.warning("response_url update failed", exc_info=True)

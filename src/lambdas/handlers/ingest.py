"""EventBridge target: GuardDuty findings and Wazuh/Suricata alerts -> normalised case + workflow."""

from __future__ import annotations

import logging

from siemsoar.pipeline import ingest
from siemsoar.schema import UnsupportedEvent, normalize_event

log = logging.getLogger("handlers.ingest")


def handler(event, context=None):
    try:
        alert = normalize_event(event)
    except UnsupportedEvent as err:
        log.warning("ignored event", extra={"ctx": {"reason": str(err)}})
        return {"action": "ignored", "reason": str(err)}
    result = ingest(alert)
    # every outcome is logged: a silently dropped event is indistinguishable from an event that never arrived
    log.info("ingest %s", result["action"], extra={"ctx": {**result, "source": alert["source"],
                                                           "rule_id": alert["rule_id"]}})
    return result

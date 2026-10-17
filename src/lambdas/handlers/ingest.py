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
    return ingest(alert)

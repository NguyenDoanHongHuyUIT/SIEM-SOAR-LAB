"""Helpers shared by Step Functions task handlers (input shape: {"op":..., "state": <execution state>})."""

from __future__ import annotations

from siemsoar.store import CaseStore


def state_of(event: dict) -> dict:
    return event.get("state", event)


def case_id_of(event: dict) -> str:
    return state_of(event)["case_id"]


def config_of(event: dict) -> dict:
    return state_of(event).get("config", {})


def dry_run_of(event: dict) -> bool:
    return bool(config_of(event).get("dry_run", False))


def load(event: dict) -> tuple[CaseStore, dict]:
    store = CaseStore()
    return store, store.get_case(case_id_of(event))

"""Fault injection seam for the robustness scenarios (paper 5.4). Inert unless explicitly enabled.

Enabled by Terraform var `enable_fault_injection` (LAB_FAULTS_ENABLED=true). The simulation runner then sets
FAULT_INJECT=<point>[,<point>] on the function configuration for the duration of one scenario.
Points: contain.revoke_sessions (fails after the network was already isolated), notify.slack (Slack down).
"""

from __future__ import annotations

import os


class InjectedFault(RuntimeError):
    """Deliberate failure used to prove the fail-safe path."""


def active(point: str) -> bool:
    return os.environ.get("LAB_FAULTS_ENABLED") == "true" and point in os.environ.get("FAULT_INJECT", "").split(",")


def maybe_fail(point: str) -> None:
    if active(point):
        raise InjectedFault(f"injected fault at {point}")

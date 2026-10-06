"""Tiny Amazon States Language interpreter for tests.

Executes the real generated state machine against the real handlers (moto-backed), so JSONPath wiring,
Choice branches and Catch routing are tested, not just the individual Lambdas. Supports the subset the
workflow uses: Task (lambda:invoke and .waitForTaskToken), Choice, Pass, Succeed, Fail, Catch/ResultPath.
"""

from __future__ import annotations

import copy
import importlib
import json
from pathlib import Path

ASL = Path(__file__).resolve().parent.parent / "statemachine" / "case_workflow.asl.json"
FN = {"enrich": "enrich", "notify": "notify", "preflight": "preflight", "save_state": "save_state",
      "contain": "contain", "restore": "restore", "case_ops": "case_ops"}


class Timeout(Exception):
    """Raised by a gate callback to simulate States.Timeout."""


def _get(path: str, data, ctx):
    if path == "$":
        return data
    if path.startswith("$$."):
        cur = ctx
        path = path[3:]
    else:
        cur = data
        path = path[2:]
    for part in path.split("."):
        cur = cur[part]
    return cur


def _set(data: dict, path: str, value) -> dict:
    if path == "$":
        return value
    data = copy.deepcopy(data)
    cur = data
    parts = path[2:].split(".")
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value
    return data


def _resolve(params, data, ctx):
    if isinstance(params, dict):
        out = {}
        for k, v in params.items():
            if k.endswith(".$"):
                out[k[:-2]] = _get(v, data, ctx)
            else:
                out[k] = _resolve(v, data, ctx)
        return out
    return params


def _choice(state, data):
    for rule in state.get("Choices", []):
        try:
            val = _get(rule["Variable"], data, {})
        except KeyError:
            continue
        if "StringEquals" in rule and val == rule["StringEquals"]:
            return rule["Next"]
        if "BooleanEquals" in rule and val is rule["BooleanEquals"]:
            return rule["Next"]
    return state["Default"]


def run(case_id: str, config: dict, gate_callback, max_steps: int = 80):
    """gate_callback(gate, data) -> None (decision delivered via apply_decision) or raises Timeout.
    Returns (outcome, final_data, visited_states). outcome: Succeed | Fail:<Error>."""
    asl = json.loads(ASL.read_text())
    states, current, visited = asl["States"], asl["StartAt"], []
    data = {"case_id": case_id, "config": config}
    for _ in range(max_steps):
        visited.append(current)
        st = states[current]
        t = st["Type"]
        if t == "Succeed":
            return "Succeed", data, visited
        if t == "Fail":
            return f"Fail:{st['Error']}", data, visited
        if t == "Choice":
            current = _choice(st, data)
            continue
        if t == "Pass":
            data = _set(data, st.get("ResultPath", "$"), st["Result"])
            current = st["Next"]
            continue
        assert t == "Task", t
        fn_key = st["Parameters"]["FunctionName"].removeprefix("${fn_").removesuffix("}")
        module = importlib.import_module(f"handlers.{FN[fn_key]}")
        waiting = st["Resource"].endswith("waitForTaskToken")
        ctx = {"Task": {"Token": f"TOKEN-{case_id}-{current}"}}
        payload = _resolve(st["Parameters"]["Payload"], data, ctx)
        try:
            result = module.handler(payload, None)
            if waiting:
                gate_callback(payload["gate"], data, ctx["Task"]["Token"])
                from siemsoar import aws
                result = aws.client("stepfunctions").success[-1][1]
                data = _set(data, st["ResultPath"], result)
            else:
                shaped = _resolve(st["ResultSelector"], {"Payload": json.loads(json.dumps(result, default=str))}, ctx)
                data = _set(data, st["ResultPath"], shaped)
            current = st["Next"]
        except Exception as err:  # noqa: BLE001
            name = "States.Timeout" if isinstance(err, Timeout) else type(err).__name__
            for catch in st.get("Catch", []):
                if any(e in {name, "States.ALL"} for e in catch["ErrorEquals"]):
                    data = _set(data, catch["ResultPath"], {"Error": name, "Cause": str(err)})
                    current = catch["Next"]
                    break
            else:
                raise
    raise AssertionError(f"state machine did not terminate: {visited}")

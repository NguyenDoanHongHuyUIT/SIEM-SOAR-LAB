"""Tiny Amazon States Language interpreter for tests.

Executes the real generated state machine against the real handlers (moto-backed), so JSONPath wiring,
Choice branches and Catch routing are tested, not just the individual Lambdas. Supports the subset the
workflow uses: Task (lambda:invoke, .waitForTaskToken, dynamodb:* and aws-sdk:* integrations run through boto3),
Choice (And/Or/Not), Pass, Succeed, Fail, Catch/ResultPath, and the intrinsics States.Format/UUID/Array.

It is a fast offline harness, NOT a conformance test of ASL (no Retry, no timeouts). Conformance of individual
states (JSONPath, Retry/Catch, intrinsics) against the real service is covered by tests/contract/test_teststate.py,
which uses the AWS TestState API.
"""

from __future__ import annotations

import copy
import importlib
import json
import os
import re
import uuid
from datetime import UTC, datetime
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


def _split_args(raw: str) -> list[str]:
    out, cur, depth, quote = [], [], 0, False
    for ch in raw:
        if ch == "'":
            quote = not quote
        if not quote and ch == "(":
            depth += 1
        if not quote and ch == ")":
            depth -= 1
        if ch == "," and depth == 0 and not quote:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def _arg(text: str, data, ctx):
    if text.startswith("'"):
        return text[1:-1]
    if text.startswith("States."):
        return _intrinsic(text, data, ctx)
    return _get(text, data, ctx)


def _intrinsic(expr: str, data, ctx):
    name, raw = re.fullmatch(r"States\.(\w+)\((.*)\)", expr.strip(), re.S).groups()
    vals = [_arg(a, data, ctx) for a in _split_args(raw)]
    if name == "Format":
        out = vals[0]
        for v in vals[1:]:
            out = out.replace("{}", str(v), 1)
        return out
    if name == "UUID":
        return str(uuid.uuid4())
    if name == "Array":
        return list(vals)
    raise NotImplementedError(f"intrinsic States.{name}")


def _resolve(params, data, ctx):
    if isinstance(params, dict):
        out = {}
        for k, v in params.items():
            if k.endswith(".$"):
                out[k[:-2]] = _intrinsic(v, data, ctx) if v.startswith("States.") else _get(v, data, ctx)
            else:
                out[k] = _resolve(v, data, ctx)
        return out
    return params


def _cond(rule, data) -> bool:
    if "And" in rule:
        return all(_cond(r, data) for r in rule["And"])
    if "Or" in rule:
        return any(_cond(r, data) for r in rule["Or"])
    if "Not" in rule:
        return not _cond(rule["Not"], data)
    try:
        val = _get(rule["Variable"], data, {})
    except KeyError:
        return False
    if "StringEquals" in rule:
        return val == rule["StringEquals"]
    if "BooleanEquals" in rule:
        return val is rule["BooleanEquals"]
    raise NotImplementedError(f"choice operator in {rule}")


def _choice(state, data):
    for rule in state.get("Choices", []):
        if _cond(rule, data):
            return rule["Next"]
    return state["Default"]


def iso_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _call_sdk(resource: str, params: dict):
    """arn:aws:states:::dynamodb:putItem | arn:aws:states:::aws-sdk:ec2:stopInstances -> boto3 call (moto in tests)."""
    from siemsoar import aws
    tail = resource.split(":::", 1)[1].split(":")
    service, action = (tail[1], tail[2]) if tail[0] == "aws-sdk" else (tail[0], tail[1])
    res = getattr(aws.client(service), _snake(action))(**params)
    res.pop("ResponseMetadata", None)
    return json.loads(json.dumps(res, default=str))


def run(case_id: str, config: dict, gate_callback, max_steps: int = 80):
    """gate_callback(gate, data) -> None (decision delivered via apply_decision) or raises Timeout.
    Returns (outcome, final_data, visited_states). outcome: Succeed | Fail:<Error>."""
    asl = json.loads(ASL.read_text().replace("${table_name}", os.environ["CASES_TABLE"]))
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
        if "lambda" not in st["Resource"]:  # dynamodb:* / aws-sdk:* integration
            ctx = {"State": {"EnteredTime": iso_now()}}
            try:
                result = _call_sdk(st["Resource"], _resolve(st["Parameters"], data, ctx))
                if st.get("ResultPath", "$") is not None:
                    data = _set(data, st["ResultPath"], result)
                current = st["Next"]
            except Exception as err:  # noqa: BLE001
                for catch in st.get("Catch", []):
                    if any(e in {type(err).__name__, "States.ALL"} for e in catch["ErrorEquals"]):
                        data = _set(data, catch["ResultPath"], {"Error": type(err).__name__, "Cause": str(err)})
                        current = catch["Next"]
                        break
                else:
                    raise
            continue
        fn_key = st["Parameters"]["FunctionName"].removeprefix("${fn_").removesuffix("}")
        module = importlib.import_module(f"handlers.{FN[fn_key]}")
        waiting = st["Resource"].endswith("waitForTaskToken")
        ctx = {"Task": {"Token": f"TOKEN-{case_id}-{current}"}, "State": {"EnteredTime": iso_now()}}
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

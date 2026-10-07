"""The offline ASL harness must implement exactly the intrinsics/choice semantics the generated ASL relies on."""

import re

from tests import asl_runner as r


def test_format_uuid_array_and_nested_paths():
    data, ctx = {"case_id": "C-1", "x": {"y": "i-123"}}, {"State": {"EnteredTime": "2026-10-07T10:00:00.000Z"}}
    assert r._intrinsic("States.Format('CASE#{}', $.case_id)", data, ctx) == "CASE#C-1"
    assert r._intrinsic("States.Array($.x.y)", data, ctx) == ["i-123"]
    out = r._intrinsic("States.Format('AUDIT#{}#{}', $$.State.EnteredTime, States.UUID())", data, ctx)
    assert re.fullmatch(r"AUDIT#2026-10-07T10:00:00\.000Z#[0-9a-f-]{36}", out)


def test_resolve_builds_dynamodb_typed_values():
    out = r._resolve({"Key": {"pk": {"S.$": "States.Format('CASE#{}', $.case_id)"}, "sk": {"S": "META"}}},
                     {"case_id": "C-9"}, {})
    assert out == {"Key": {"pk": {"S": "CASE#C-9"}, "sk": {"S": "META"}}}


def test_choice_and_default():
    state = {"Default": "skip", "Choices": [{"And": [{"Variable": "$.a", "BooleanEquals": False},
                                                     {"Variable": "$.b", "BooleanEquals": True}], "Next": "go"}]}
    assert r._choice(state, {"a": False, "b": True}) == "go"
    assert r._choice(state, {"a": True, "b": True}) == "skip"
    assert r._choice(state, {"a": False}) == "skip"  # missing variable -> condition false


def test_snake_case_mapping_for_sdk_actions():
    assert r._snake("stopInstances") == "stop_instances" and r._snake("updateAccessKey") == "update_access_key"
    assert r._snake("putItem") == "put_item"

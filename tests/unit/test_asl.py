import json
import re
from pathlib import Path

from tools import gen_asl

ASL = json.loads((Path(__file__).resolve().parents[2] / "statemachine" / "case_workflow.asl.json").read_text())
STATES = ASL["States"]


def _targets(state):
    out = [state.get("Next"), state.get("Default")]
    out += [c["Next"] for c in state.get("Choices", [])] + [c["Next"] for c in state.get("Catch", [])]
    return [t for t in out if t]


def test_committed_asl_matches_generator():
    assert gen_asl.render() == (Path(gen_asl.OUT)).read_text(), "run: python -m tools.gen_asl"


def test_all_targets_exist_and_all_states_reachable():
    for name, st in STATES.items():
        for t in _targets(st):
            assert t in STATES, f"{name} -> {t}"
    seen, stack = set(), [ASL["StartAt"]]
    while stack:
        n = stack.pop()
        if n not in seen:
            seen.add(n)
            stack.extend(_targets(STATES[n]))
    assert seen == set(STATES)


def test_every_task_has_catch_to_failsafe_or_a_documented_exception():
    notify_states = {"NotifyExpired", "NotifyIsolated", "NotifyBlocked", "NotifyRestored"}
    for name, st in STATES.items():
        if st["Type"] != "Task" or name in {"FailSafe"}:
            continue
        assert st.get("Catch"), name
        if name not in notify_states:
            assert any(c["Next"] == "FailSafe" or c["Next"] == "MarkExpired" for c in st["Catch"]), name


def test_human_gates_have_timeouts_and_task_token():
    for name in ("NotifyApproval", "WaitRestoreDecision"):
        st = STATES[name]
        assert st["Resource"].endswith("waitForTaskToken")
        assert "TimeoutSecondsPath" in st
        assert st["Parameters"]["Payload"]["task_token.$"] == "$$.Task.Token"
    assert any(c["ErrorEquals"] == ["States.Timeout"] and c["Next"] == "MarkExpired"
               for c in STATES["NotifyApproval"]["Catch"])


def test_terminal_states_and_failure_is_visible_to_cloudwatch():
    ends = {n for n, s in STATES.items() if s["Type"] in {"Succeed", "Fail"}}
    assert ends == {"DoneAcknowledged", "DoneDismissed", "DoneExpired", "DoneRestored", "CaseFailed"}
    assert STATES["CaseFailed"]["Type"] == "Fail"  # drives the ExecutionsFailed alarm


def test_function_placeholders_match_terraform_template_inputs():
    used = set(re.findall(r"\$\{(fn_\w+)\}", json.dumps(ASL)))
    tf = (Path(__file__).resolve().parents[2] / "infra/modules/serverless-core/stepfunctions.tf").read_text()
    provided = set(re.findall(r"^\s+(fn_\w+)\s+=", tf, re.M))
    assert used == provided


def test_no_task_token_or_secret_in_state_names_or_results():
    blob = json.dumps(ASL)
    assert "secret" not in blob.lower() and "password" not in blob.lower()


def test_containment_happens_only_after_approval_and_preflight():
    order = []
    cur = "Preflight"
    while cur not in {"VerifyContainment"} and len(order) < 20:
        order.append(cur)
        st = STATES[cur]
        cur = st.get("Next") or st["Choices"][0]["Next"]
    assert order[:3] == ["Preflight", "SaveState", "PlanChoice"]
    reach_approve = [c["Next"] for c in STATES["ApprovalChoice"]["Choices"] if c["StringEquals"] == "approve"]
    assert reach_approve == ["Preflight"]

import json

import pytest
from handlers import ingest as ingest_handler
from siemsoar.states import Status

from evaluation import evaluate as ev
from simulation import runner
from tests.fixtures import events as fx
from tools import rulesctl, soarctl


# ------------------------------------------------------------------ scenarios stay consistent with rule lifecycle
def test_scenarios_are_well_formed_and_consistent_with_rule_states():
    meta = rulesctl.load_metadata()
    scenarios = runner.load_scenarios()
    assert len(scenarios) >= 12
    for sid, s in scenarios.items():
        assert s["id"] == sid == s["_file"].removesuffix(".yml")
        assert s["kind"] in {"ssm_shell", "atomic", "guardduty_sample", "stratus", "pcap_replay", "robustness"}
        assert "title" in s and "malicious" in s
        for e in s.get("expect", []):
            if e["source"] == "guardduty":
                continue
            rid = int(e["rule_id"])
            key = f"wazuh-{rid}" if e["source"] == "wazuh" else f"suricata-{9000000 + rid - 110000}"
            assert key in meta, f"{sid}: expectation on unknown rule {key}"
            live = meta[key]["state"] in ("active", "enforce")
            assert e.get("case", True) == live, (
                f"{sid}: expects case={e.get('case', True)} but {key} is {meta[key]['state']}")


def test_every_active_rule_is_exercised_by_a_scenario():
    meta = rulesctl.load_metadata()
    covered = set()
    for s in runner.load_scenarios().values():
        for e in s.get("expect", []):
            if e["source"] == "wazuh":
                covered.add(f"wazuh-{e['rule_id']}")
            elif e["source"] == "suricata":
                covered.add(f"suricata-{9000000 + int(e['rule_id']) - 110000}")
    for key in meta:
        assert key in covered, f"{key} has no simulation scenario"


def test_run_ids_match_the_normaliser_regex_and_templating():
    from siemsoar.schema import RUN_ID_RE
    rid = runner.new_run_id("host-useradd")
    assert RUN_ID_RE.search(f"x run_id={rid} y").group(1) == rid
    assert runner.render("echo {run_id} {short}", "run-1-a-beef") == "echo run-1-a-beef beef"


def test_pcap_scenarios_reference_generated_pcaps():
    from tools import make_pcaps
    for s in runner.load_scenarios().values():
        if s["kind"] == "pcap_replay":
            assert s["pcap"] in make_pcaps.PCAPS


def test_match_expectations():
    cases = [{"case_id": "C1", "rule_id": "100100", "source": "wazuh"}]
    ok = runner.match_expectations([{"source": "wazuh", "rule_id": "100100", "case": True},
                                    {"source": "wazuh", "rule_id": "100101", "case": False}], cases)
    assert all(c["ok"] for c in ok)
    bad = runner.match_expectations([{"source": "wazuh", "rule_id": "100100", "case": False},
                                     {"source": "wazuh", "rule_id": "9", "case": True},
                                     {"source": "wazuh", "rule_id": "9", "case": True, "optional": True}], cases)
    assert [c["ok"] for c in bad] == [False, False, True]


# ------------------------------------------------------------------ evaluation metrics
def _case(i, rule="100100", source="wazuh", status="RESTORED", created="2026-10-06T10:00:30.000Z",
          event="2026-10-06T10:00:00.000Z", **kw):
    return {"case_id": f"C{i}", "rule_id": rule, "source": source, "status": status, "created_at": created,
            "event_time": event, "alert_count": 1, **kw}


RUNS = [
    {"run_id": "run-a-1", "scenario": "host-fim", "kind": "ssm_shell", "malicious": True, "techniques": ["T1136.001"],
     "started_at": "2026-10-06T09:59:50.000Z", "ended_at": "2026-10-06T10:00:00.000Z",
     "expect": [{"source": "wazuh", "rule_id": "100100", "case": True}]},
    {"run_id": "run-b-2", "scenario": "canary", "kind": "ssm_shell", "malicious": False, "techniques": [],
     "started_at": "2026-10-06T11:00:00.000Z", "ended_at": "2026-10-06T11:00:05.000Z",
     "expect": [{"source": "wazuh", "rule_id": "100101", "case": False}]},
    {"run_id": "run-c-3", "scenario": "net-traversal", "kind": "pcap_replay", "malicious": True, "techniques": ["T1190"],
     "started_at": "2026-10-06T12:00:00.000Z", "ended_at": "2026-10-06T12:00:05.000Z",
     "expect": [{"source": "suricata", "rule_id": "110001", "case": True}]},
    {"run_id": "run-r-4", "scenario": "robust-double-click", "kind": "robustness", "malicious": True,
     "started_at": "2026-10-06T13:00:00.000Z", "expect": [],
     "result": {"pass": True, "checks": [{"name": "one click", "ok": True}]}},
]


def test_metrics_ground_truth_labelling():
    cases = [
        _case(1, run_id="run-a-1", alert_count=3, containment_seconds=12.5, evidence_seconds=4.0, restore_seconds=30.0),
        _case(2, rule="100101", created="2026-10-06T11:00:20.000Z", event="2026-10-06T11:00:10.000Z"),  # shadow violation
        # suricata case matched by time window only (no run_id in EVE), 20 s after replay started
        _case(3, rule="110001", source="suricata", created="2026-10-06T12:00:20.000Z",
              event="2026-10-06T12:00:03.000Z"),
        _case(4, rule="100130", status="DISMISSED", created="2026-10-06T15:00:00.000Z"),  # human FP, no run
        _case(5, rule="100110", status="NOTIFIED", created="2026-10-06T16:00:00.000Z"),  # unlabelled
    ]
    m = ev.compute_metrics(cases, RUNS, rulesctl.load_metadata())
    q = m["rule_quality"]
    assert q["100100"]["tp"] == 1 and q["100100"]["precision"] == 1.0
    assert q["100101"]["shadow_violation"] == 1 and q["100101"]["precision"] is None or q["100101"]["precision"] == 0.0
    assert q["110001"]["tp"] == 1
    assert "100130" not in q  # canary rule: never counted as detection quality
    assert q["100110"]["unlabelled"] == 1
    assert m["alert_duplication_reduction"] == {"alerts": 7, "cases": 5, "reduction": round(1 - 5 / 7, 3)}
    assert m["time_to_containment_s"]["p50"] == 12.5 and m["time_to_evidence_preservation_s"]["n"] == 1
    assert m["detection_latency_by_source_s"]["alert_to_case"]["wazuh"]["n"] >= 3
    assert m["detection_latency_by_source_s"]["run_start_to_case"]["suricata"]["p50"] == 20.0
    cov = m["attack_coverage"]
    assert set(cov["techniques_detected"]) == {"T1136.001", "T1190"} and cov["coverage_of_exercised"] == 1.0
    assert m["robustness"] == {"runs": 1, "passed": 1, "detail": m["robustness"]["detail"]}


def test_metrics_false_negative_and_shadow_ok():
    m = ev.compute_metrics([], RUNS, rulesctl.load_metadata())
    q = m["rule_quality"]
    assert q["100100"]["fn"] == 1 and q["100100"]["recall"] == 0.0
    assert q["100101"]["shadow_ok"] == 1
    assert m["attack_coverage"]["coverage_of_exercised"] == 0.0


def test_metrics_empty_dataset_does_not_crash():
    m = ev.compute_metrics([], [], {})
    assert m["counts"]["cases"] == 0 and m["alert_duplication_reduction"]["reduction"] is None
    assert "Báo cáo đánh giá" in ev.render_markdown(m)


def test_percentiles_and_summary():
    assert ev.percentile([1, 2, 3, 4, 100], 50) == 3 and ev.percentile([], 50) is None
    assert ev.percentile([10], 95) == 10 and ev.summary([])["n"] == 0
    s = ev.summary([1.0, 2.0, 3.0, 4.0])
    assert s["p50"] == 2.5 and s["max"] == 4.0


def test_cost_estimate_and_baseline():
    c = ev.estimate_cost([{"start": "x", "hours": 4, "manager_type": "t3.large", "sensor_type": "t3.small"}])
    assert 0.4 < c["total_usd_estimate"] < 0.7
    assert ev.baseline_comparison([], {"p50": 10})["available"] is False
    b = ev.baseline_comparison([{"seconds_to_contain": "300", "manual_steps": "9"},
                                {"seconds_to_contain": "500", "manual_steps": "7"}], {"p50": 20.0})
    assert b["baseline_contain_p50_s"] == 400.0 and b["contain_time_delta_s"] == 380.0 and b["soar_manual_steps"] == 2


def test_markdown_report_renders_all_sections():
    cases = [_case(1, run_id="run-a-1", containment_seconds=9.0)]
    md = ev.render_markdown(ev.compute_metrics(cases, RUNS, rulesctl.load_metadata(),
                                               sessions=[{"hours": 2, "manager_type": "t3.large",
                                                          "sensor_type": "t3.small"}],
                                               deployments=[{"commit_time": "2026-10-06T10:00:00Z",
                                                             "deployed_at": "2026-10-06T10:05:00Z"}]))
    for h in ("Detection latency", "Chất lượng rule", "Độ phủ ATT&CK", "Robustness", "Chi phí", "baseline",
              "Rule deployment lead time"):
        assert h in md
    assert "p50 300.0s" in md


# ------------------------------------------------------------------ soarctl
def test_soarctl_list_show_decide_feedback(store, sfn, capsys, monkeypatch):
    from handlers import notify
    cid = ingest_handler.handler(fx.guardduty_instance())["case_id"]
    notify.handler({"op": "request", "gate": "approval", "task_token": "TOK",
                    "state": {"case_id": cid, "config": {"approval_timeout": 60}}})
    assert soarctl.main(["list", "--status", "NOTIFIED"]) == 0
    assert cid in capsys.readouterr().out
    assert soarctl.main(["show", cid]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["case"]["case_id"] == cid and shown["audit"] and "raw" not in shown["case"]
    assert soarctl.main(["show", "C-nope"]) == 1
    assert soarctl.main(["decide", cid, "--gate", "approval", "--decision", "dismiss"]) == 0
    assert store.get_case(cid)["status"] == Status.DISMISSED
    assert sfn.success[0][1]["channel"] == "cli" and sfn.success[0][1]["actor"].startswith("cli:arn:aws")
    assert soarctl.main(["decide", cid, "--gate", "approval", "--decision", "dismiss"]) == 1  # rejected: already handled
    stats = soarctl.feedback_stats(store)
    assert stats["UnauthorizedAccess:EC2/SSHBruteForce"] == {"cases": 1, "false_positive": 1}
    suggestions = rulesctl.tune({"100100": {"cases": 3, "false_positive": 3}})
    assert suggestions and "demote" in suggestions[0]


# ------------------------------------------------------------------ fault injection seam
def test_faults_inert_unless_enabled(monkeypatch):
    from siemsoar import faults
    monkeypatch.setenv("FAULT_INJECT", "contain.revoke_sessions")
    faults.maybe_fail("contain.revoke_sessions")  # LAB_FAULTS_ENABLED not set: no effect
    monkeypatch.setenv("LAB_FAULTS_ENABLED", "true")
    with pytest.raises(faults.InjectedFault):
        faults.maybe_fail("contain.revoke_sessions")
    faults.maybe_fail("other.point")


# ------------------------------------------------------------------ canary rules and Atomic Red Team execution
def test_canary_rule_is_reported_separately_and_never_counted_as_detection_quality():
    runs = [{"run_id": "run-k-1", "scenario": "host-marker", "kind": "ssm_shell", "malicious": True, "canary": True,
             "techniques": ["T1059.004"], "started_at": "2026-10-06T09:59:50.000Z", "ended_at": "2026-10-06T10:00:00.000Z",
             "expect": [{"source": "wazuh", "rule_id": "100130", "case": True}]}]
    cases = [_case(1, rule="100130", run_id="run-k-1", created="2026-10-06T10:00:20.000Z")]
    m = ev.compute_metrics(cases, runs, rulesctl.load_metadata())
    assert "100130" not in m["rule_quality"]
    assert m["pipeline_canary"] == {"rules": ["100130"], "expected": 1, "observed": 1, "pipeline_ok": True}
    assert m["attack_coverage"]["techniques_exercised"] == []  # a self-written marker is not an exercised technique
    assert "Canary pipeline" in ev.render_markdown(m)
    missed = ev.compute_metrics([], runs, rulesctl.load_metadata())
    assert missed["pipeline_canary"]["pipeline_ok"] is False  # no case for the marker: the pipeline is broken


def test_marker_rule_100130_is_declared_canary_in_metadata():
    assert rulesctl.load_metadata()["wazuh-100130"].get("canary") is True


def _runner_with_fake_ssm(monkeypatch, fail_verify=False):
    calls = []
    r = object.__new__(runner.Runner)
    monkeypatch.setattr(r, "instance", lambda role: "i-sensor", raising=False)

    def fake(instance_id, commands, timeout=120):
        calls.append(commands[0])
        if fail_verify and commands[0].startswith("getent"):
            raise RuntimeError("ssm command Failed")
        return "{}"

    monkeypatch.setattr(r, "ssm_run", fake, raising=False)
    return r, calls


def test_atomic_scenario_runs_upstream_atomic_then_verifies_then_cleans_up(monkeypatch):
    r, calls = _runner_with_fake_ssm(monkeypatch)
    s = runner.load_scenarios()["host-useradd"]
    out = r.exec_atomic(s, "run-20261007-host-useradd-beef")
    assert "run_atomic.py T1136.001 40d8eabd-e394-46f6-8785-b9bfa1d011d2 --arg username=siemsoar_sim_beef" in calls[0]
    assert calls[0].startswith("ART_REF=master /opt/siemsoar/art-venv/bin/python")
    assert calls[1] == "getent passwd siemsoar_sim_beef" and calls[2].startswith("userdel -r siemsoar_sim_beef")
    assert out["atomic"]["technique"] == "T1136.001"


def test_atomic_failure_is_an_execution_error_not_a_silent_false_negative(monkeypatch):
    r, calls = _runner_with_fake_ssm(monkeypatch, fail_verify=True)
    with pytest.raises(RuntimeError):
        r.exec_atomic(runner.load_scenarios()["host-useradd"], "run-x-beef")
    assert calls[-1].startswith("userdel")  # cleanup still ran

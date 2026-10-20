import json

import pytest
from handlers import ingest as ingest_handler
from siemsoar.states import Status

from evaluation import evaluate as ev
from simulation import catalog, runner
from tests.fixtures import events as fx
from tools import rulesctl, soarctl


# ------------------------------------------------------------------ scenarios stay consistent with rule lifecycle
def test_scenarios_are_well_formed_and_consistent_with_the_rules():
    meta = rulesctl.load_metadata()
    scenarios = runner.load_scenarios()
    assert len(scenarios) >= 14
    for sid, s in scenarios.items():
        assert s["id"] == sid == s["_file"].removesuffix(".yml")
        assert s["kind"] in catalog.SCENARIO_KINDS and "title" in s and "malicious" in s
    assert catalog.check_against_rules(scenarios, meta) == []


def test_techniques_of_public_procedures_are_derived_never_typed():
    sc = runner.load_scenarios()
    assert sc["host-sudoers"]["techniques"] == ["T1548.003"]
    assert sc["host-sudoers"]["technique_source"] == "Atomic Red Team index"
    assert sc["aws-stratus-cloudtrail-stop"]["techniques"] == ["T1685.002"]  # CTID mapping of the documented finding
    assert not sc["host-ssh-burst-existing"]["evidence"]  # a lab procedure never counts as mapping evidence
    assert all(s["evidence"] for s in sc.values() if s["kind"] in ("atomic", "stratus") and s["malicious"])


def _write(tmp_path, doc):
    (tmp_path / f"{doc['id']}.yml").write_text(json.dumps(doc))  # JSON is valid YAML


ATOMIC = {"id": "a", "title": "t", "kind": "atomic", "malicious": True,
          "atomic": {"technique": "T1136.001", "test_guid": "40d8eabd-e394-46f6-8785-b9bfa1d011d2",
                     "ref": "388942adbd9641f4dfdcf079d7efe9a75ec0ac43"}}


@pytest.mark.parametrize("change,message", [
    (lambda d: d["atomic"].update(technique="T1098"), "belongs to T1136.001, not T1098"),
    (lambda d: d["atomic"].update(test_guid="00000000-0000-0000-0000-000000000000"), "is not a Linux atomic"),
    (lambda d: d["atomic"].update(ref="a" * 40), "differs from the pinned index"),
    (lambda d: d.update(techniques=["T1059"]), "contradict Atomic Red Team index"),
    (lambda d: d.update(commands_extra=None, verify=["echo {password}"]), "placeholders"),
])
def test_scenario_ground_truth_is_checked_against_the_pinned_atomic_index(tmp_path, change, message):
    doc = json.loads(json.dumps(ATOMIC))
    change(doc)
    _write(tmp_path, doc)
    with pytest.raises(ValueError, match=message):
        runner.load_scenarios(tmp_path)


@pytest.mark.parametrize("change,message", [
    (lambda d: d["documented_detection"].update(url="https://example.com/"), "documented_detection.url"),
    (lambda d: d.update(expect=[]), "documented GuardDuty finding"),
    (lambda d: d["documented_detection"].update(finding_type="Made:Up/Finding") or d.update(
        expect=[{"source": "guardduty", "rule_id": "Made:Up/Finding"}]), "not an active GuardDuty type"),
])
def test_stratus_scenarios_must_expect_the_finding_stratus_documents(tmp_path, change, message):
    doc = json.loads((catalog.SCENARIO_DIR / "aws-stratus-cloudtrail-stop.yml").read_text().replace("'", '"')
                     if False else json.dumps(runner.load_scenarios()["aws-stratus-cloudtrail-stop"],
                                              default=str))
    doc = {k: v for k, v in doc.items() if not k.startswith("_") and k not in ("techniques", "technique_source",
                                                                               "evidence")}
    doc["id"] = "s"
    change(doc)
    _write(tmp_path, doc)
    with pytest.raises(ValueError, match=message):
        runner.load_scenarios(tmp_path)


def test_scenario_loader_rejects_invalid_ground_truth(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("id: bad\ntitle: bad\nkind: ssm_shell\nmalicious: true\n"
                    "evaluation_scope: pipeline_only\ntechniques: [T1059.004]\ncommands: ['true']\n")
    with pytest.raises(ValueError, match="pipeline_only"):
        runner.load_scenarios(tmp_path)
    path.write_text("id: bad\ntitle: bad\nkind: guardduty_sample\nmalicious: false\nfinding_types: ['Made:Up/X']\n")
    with pytest.raises(ValueError, match="not active GuardDuty finding types"):
        runner.load_scenarios(tmp_path)


def test_a_scenario_whose_technique_contradicts_the_rule_it_expects_is_reported():
    meta = rulesctl.load_metadata()
    s = {**runner.load_scenarios()["host-sudoers"], "id": "x", "techniques": ["T1046"]}
    errs = catalog.check_against_rules({"x": s}, meta)
    assert errs and "labelled ['T1548.003']" in errs[0]
    unknown = {**s, "expect": [{"source": "suricata", "rule_id": "119999", "case": False}]}
    assert "has no metadata" in catalog.check_against_rules({"x": unknown}, meta)[0]


def test_every_rule_is_exercised_by_a_scenario():
    meta = rulesctl.load_metadata()
    covered = {catalog.metadata_id(e, meta) for s in runner.load_scenarios().values() for e in s.get("expect", [])}
    for key, m in meta.items():
        if m["state"] != "deprecated":
            assert key in covered, f"{key} has no simulation scenario"


def test_run_ids_match_the_normaliser_regex_and_templating():
    from siemsoar.schema import RUN_ID_RE
    rid = runner.new_run_id("host-useradd")
    assert RUN_ID_RE.search(f"x run_id={rid} y").group(1) == rid
    assert runner.render("echo {run_id} {short}", "run-1-a-beef") == "echo run-1-a-beef beef"
    assert runner.render("nmap {manager_ip}/32", "run-1-a-beef", {"manager_ip": "10.0.1.5"}) == "nmap 10.0.1.5/32"


def test_match_expectations():
    cases = [{"case_id": "C1", "rule_id": "100100", "source": "wazuh", "run_id": "run-current"}]
    bounds = {"run_id": "run-current", "started_at": "2026-10-06T10:00:00Z",
              "ended_at": "2026-10-06T10:00:10Z", "settle_seconds": 30}
    ok = runner.match_expectations([{"source": "wazuh", "rule_id": "100100", "case": True},
                                    {"source": "wazuh", "rule_id": "100101", "case": False}], cases, bounds)
    assert all(c["ok"] for c in ok)
    bad = runner.match_expectations([{"source": "wazuh", "rule_id": "100100", "case": False},
                                     {"source": "wazuh", "rule_id": "9", "case": True},
                                     {"source": "wazuh", "rule_id": "9", "case": True, "optional": True}],
                                    cases, bounds)
    assert [c["ok"] for c in bad] == [False, False, True]
    stale = [{"case_id": "C0", "rule_id": "100100", "source": "wazuh", "run_id": "run-old"}]
    assert not runner.match_expectations([{"source": "wazuh", "rule_id": "100100", "case": True}],
                                         stale, bounds)[0]["ok"]
    late = [{"case_id": "C2", "rule_id": "100100", "source": "wazuh",
             "created_at": "2026-10-06T10:00:41Z"}]
    assert not runner.match_expectations([{"source": "wazuh", "rule_id": "100100", "case": True}],
                                         late, bounds)[0]["ok"]


def test_a_run_specific_target_has_no_late_arrival_cut_off_and_other_targets_never_match():
    """Stratus: the victim key exists for one run only. GuardDuty's delay is not bounded by any documented figure, so
    a finding naming that key belongs to the run whenever it arrives; the operator's cleanup finding (same rule, other
    key, inside the window) never does - neither for the live verdict nor for the evaluation."""
    run = {"run_id": "run-s", "started_at": "2026-10-19T01:34:20Z", "ended_at": "2026-10-19T01:35:27Z",
           "settle_seconds": 1800, "target": "lab-victim/AKIAVICTIM", "target_unique": True}
    gd = {"rule_id": "Stealth:IAMUser/CloudTrailLoggingDisabled", "source": "guardduty"}
    late = {**gd, "case_id": "C-late", "resource_id": "lab-victim/AKIAVICTIM", "created_at": "2026-10-19T03:00:00Z"}
    operator = {**gd, "case_id": "C-op", "resource_id": "Huy/AKIAOPERATOR", "created_at": "2026-10-19T01:50:00Z"}
    before = {**late, "case_id": "C-old", "created_at": "2026-10-19T01:00:00Z"}
    expect = [{**gd, "case": True}]
    assert [catalog.case_in_run(c, run) for c in (late, operator, before)] == [True, False, False]
    assert runner.match_expectations(expect, [operator], run)[0]["ok"] is False
    assert runner.match_expectations(expect, [operator, late], run)[0]["detail"] == ["C-late"]
    shared = {**run, "target_unique": False}  # a lab host is reused by every run: the window still bounds it
    assert catalog.case_in_run(late, shared) is False


def test_a_run_that_never_executed_does_not_steal_the_next_runs_case():
    gd = {"source": "guardduty", "rule_id": "Stealth:IAMUser/CloudTrailLoggingDisabled", "case": True}
    failed = {"run_id": "run-a", "malicious": True, "kind": "stratus", "techniques": ["T1685.002"], "expect": [gd],
              "started_at": "2026-10-19T01:33:57Z", "ended_at": "2026-10-19T01:33:59Z", "settle_seconds": 1800,
              "result": {"pass": False, "checks": [{"name": "execution", "ok": False, "detail": "WinError 2"}]}}
    done = {**failed, "run_id": "run-b", "started_at": "2026-10-19T01:34:20Z", "ended_at": "2026-10-19T01:35:25Z",
            "target": "lab-victim/AKIAIOSFODNN7EXAMPLE", "target_unique": True, "result": {"pass": True, "checks": []}}
    case = _case(1, rule=gd["rule_id"], source="guardduty", created="2026-10-19T01:49:40Z",
                 resource_id="lab-victim/AKIAIOSFODNN7EXAMPLE")
    q = ev.compute_metrics([case], [failed, done], {})["rule_quality"][gd["rule_id"]]
    assert q["tp"] == 1 and q["fn"] == 0


def test_the_runner_refuses_to_attack_a_host_a_case_still_contains(monkeypatch):
    from siemsoar import response
    r = object.__new__(runner.Runner)
    r.instance = lambda role: "i-06c071a9fc8745d6c"
    tags = {"siemsoar:role": "suricata-sensor", response.CASE_TAG: "C-20261019T043905-0eb8db"}
    monkeypatch.setattr(response, "describe_instance", lambda iid: {"tags": tags})
    with pytest.raises(RuntimeError, match="contained by case C-20261019T043905-0eb8db"):
        r.attack_target("suricata-sensor")
    del tags[response.CASE_TAG]  # a verified restore removes the tag
    assert r.attack_target("suricata-sensor") == "i-06c071a9fc8745d6c"


def test_a_cross_host_run_is_attributed_to_the_host_that_sees_the_detection(monkeypatch):
    """xhost-ssh-credstuffing-target runs on the sensor; the sshd evidence is on lab-target-1, so the run's target
    (attribution, SIEM query) is the target instance, and a contained target refuses the run."""
    from types import SimpleNamespace
    r = object.__new__(runner.Runner)
    r.dry_run, r.wait, r.log = False, False, (lambda m: None)
    r.store = SimpleNamespace(put_run=lambda run: None)
    r.rules_release = lambda: None
    hosts = {"suricata-sensor": "i-0aaaaaaaaaaaaaaa1", "lab-target": "i-0bbbbbbbbbbbbbbb2"}
    contained = set()

    def attack_target(role):
        if hosts[role] in contained:
            raise RuntimeError(f"{hosts[role]} is contained by case C-1")
        return hosts[role]
    r.attack_target = attack_target
    r.exec_atomic = lambda s, run_id: {"instance": attack_target(runner.EXEC_ROLES[s.get("target", "sensor")])}
    run = r.run("xhost-ssh-credstuffing-target")
    assert run["target"] == "i-0bbbbbbbbbbbbbbb2" and run["details"]["executed_on"] == "i-0aaaaaaaaaaaaaaa1"
    contained.add("i-0bbbbbbbbbbbbbbb2")
    refused = r.run("xhost-ssh-credstuffing-target")
    assert "contained by case" in refused["execution_error"]


def test_scenario_hosts_are_validated(tmp_path):
    good = catalog.load_scenarios(catalog.SCENARIO_DIR)["target-useradd"]
    assert good["target"] == "lab-target"
    for bad in ({"target": "everywhere"}, {"observe_on": "manager"}):
        doc = {"id": "x", "title": "t", "kind": "ssm_shell", "malicious": False, "commands": ["true"], **bad}
        (tmp_path / "x.yml").write_text(json.dumps(doc))
        with pytest.raises(ValueError, match="target must be|observe_on must be"):
            catalog.load_scenarios(tmp_path)


def test_observe_alerts_filters_on_the_manager_and_validates_the_agent():
    from datetime import UTC, datetime

    from tools import observe_alerts as oa
    cmd = oa.summary_command("i-0a429ed962b37be8d", datetime(2026, 10, 19, 9, 26, 50, tzinfo=UTC),
                             datetime(2026, 10, 19, 9, 31, 16, tzinfo=UTC))
    assert '.timestamp >= "2026-10-19T09:26:45"' in cmd and '.timestamp <= "2026-10-19T09:31:16"' in cmd
    assert "group_by(.id)" in cmd and ".data.audit.command" in cmd and ".syscheck.path" in cmd
    with pytest.raises(ValueError, match="EC2 instance id"):
        oa.summary_command('i-1" or true', datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 1, 1, tzinfo=UTC))


def test_a_cloud_target_has_no_siem_layer_to_read():
    r = object.__new__(runner.Runner)
    r.ssm_run = lambda *a, **k: pytest.fail("no Wazuh query for an IAM key target")
    run = {"target": "lab-victim/AKIAIOSFODNN7EXAMPLE", "started_at": "2026-10-19T01:34:20Z",
           "ended_at": "2026-10-19T01:35:27Z", "settle_seconds": 1800}
    assert r.siem_alerts(run) == []


def test_the_runner_stops_waiting_once_every_expected_case_exists(monkeypatch):
    from types import SimpleNamespace
    run = {"run_id": "run-w", "started_at": "2026-10-19T01:34:20Z", "ended_at": "2026-10-19T01:35:27Z",
           "settle_seconds": 1800, "target": "lab-victim/AKIAVICTIM", "target_unique": True}
    case = {"case_id": "C1", "rule_id": "R", "source": "guardduty", "resource_id": "lab-victim/AKIAVICTIM",
            "created_at": "2026-10-19T01:50:00Z"}
    polls = iter([[], [], [case]])
    r = object.__new__(runner.Runner)
    r.store = SimpleNamespace(list_cases=lambda: next(polls))
    r.log = lambda msg: None
    slept = []
    monkeypatch.setattr(runner.time, "sleep", slept.append)
    assert r.await_detections([{"source": "guardduty", "rule_id": "R", "case": True}], run) == [case]
    assert slept == [30, 30]
    # a shadow (case: false) expectation is only proven by the full window: no early exit
    now = [0.0]
    monkeypatch.setattr(runner.time, "time", lambda: now[0])
    monkeypatch.setattr(runner.time, "sleep", lambda s: now.__setitem__(0, now[0] + s))
    r.store = SimpleNamespace(list_cases=lambda: [])
    r.await_detections([{"source": "wazuh", "rule_id": "S", "case": False}], {**run, "settle_seconds": 120})
    assert now[0] == 120


# ------------------------------------------------------------------ evaluation metrics
def _meta():
    """Real rule metadata plus one synthetic canary rule, only to unit-test the evaluator's canary handling."""
    return {**rulesctl.load_metadata(), "wazuh-199999": {"rule_id": 199999, "canary": True, "state": "active", "mitre": []}}


def _case(i, rule="100100", source="wazuh", status="RESTORED", created="2026-10-06T10:00:30.000Z",
          event="2026-10-06T10:00:00.000Z", **kw):
    return {"case_id": f"C{i}", "rule_id": rule, "source": source, "status": status, "created_at": created,
            "event_time": event, "alert_count": 1, **kw}


RUNS = [
    {"run_id": "run-a-1", "scenario": "host-useradd", "kind": "atomic", "malicious": True, "techniques": ["T1136.001"],
     "evidence": True,
     "started_at": "2026-10-06T09:59:50.000Z", "ended_at": "2026-10-06T10:00:00.000Z",
     "expect": [{"source": "wazuh", "rule_id": "100100", "case": True}]},
    {"run_id": "run-b-2", "scenario": "canary", "kind": "ssm_shell", "malicious": False, "techniques": [],
     "started_at": "2026-10-06T11:00:00.000Z", "ended_at": "2026-10-06T11:00:05.000Z",
     "observed": {"wazuh:100101": True}, "expect": [{"source": "wazuh", "rule_id": "100101", "case": False}]},
    {"run_id": "run-c-3", "scenario": "net-malicious-ua", "kind": "atomic", "malicious": True, "evidence": True,
     "techniques": ["T1071.001"], "started_at": "2026-10-06T12:00:00.000Z", "ended_at": "2026-10-06T12:00:05.000Z",
     "expect": [{"source": "suricata", "rule_id": "110102", "case": True}]},
    {"run_id": "run-r-4", "scenario": "robust-double-click", "kind": "robustness", "malicious": True,
     "started_at": "2026-10-06T13:00:00.000Z", "expect": [],
     "result": {"pass": True, "checks": [{"name": "one click", "ok": True}]}},
]


def test_metrics_ground_truth_labelling():
    cases = [
        _case(1, run_id="run-a-1", alert_count=3, containment_seconds=12.5, evidence_seconds=4.0, restore_seconds=30.0),
        _case(2, rule="100101", created="2026-10-06T11:00:20.000Z", event="2026-10-06T11:00:10.000Z"),  # shadow violation
        # suricata case matched by time window only (no run_id in EVE), 20 s after replay started
        _case(3, rule="110102", source="suricata", created="2026-10-06T12:00:20.000Z",
              event="2026-10-06T12:00:03.000Z"),
        _case(4, rule="199999", status="DISMISSED", created="2026-10-06T15:00:00.000Z"),  # human FP, no run
        _case(5, rule="100110", status="NOTIFIED", created="2026-10-06T16:00:00.000Z"),  # unlabelled
    ]
    m = ev.compute_metrics(cases, RUNS, _meta())
    q = m["rule_quality"]
    assert q["100100"]["tp"] == 1 and q["100100"]["precision"] == 1.0
    assert q["100101"]["shadow_violation"] == 1 and q["100101"]["precision"] is None or q["100101"]["precision"] == 0.0
    assert q["110102"]["tp"] == 1
    assert "199999" not in q  # canary rule: never counted as detection quality
    assert q["100110"]["unlabelled"] == 1
    assert m["alert_duplication_reduction"] == {"alerts": 7, "cases": 5, "reduction": round(1 - 5 / 7, 3)}
    assert m["time_to_containment_s"]["p50"] == 12.5 and m["time_to_evidence_preservation_s"]["n"] == 1
    assert m["detection_latency_by_source_s"]["alert_to_case"]["wazuh"]["n"] >= 3
    assert m["detection_latency_by_source_s"]["run_start_to_case"]["suricata"]["p50"] == 20.0
    cov = m["attack_coverage"]
    assert set(cov["techniques_detected"]) == {"T1136.001", "T1071.001"} and cov["coverage_of_exercised"] == 1.0
    assert m["robustness"] == {"runs": 1, "passed": 1, "not_executed": 0, "detail": m["robustness"]["detail"]}


def test_robustness_cases_are_attributed_by_their_scripted_decision_and_kept_out_of_rule_quality():
    """Lab session 2: back-to-back robustness runs on one host overlap in time, and their scripted dismissals counted as
    an analyst's FP for rule 100110 (precision 0). The actor `sim:<run_id>` names the run exactly."""
    runs = [{"run_id": f"run-202610180609-robust-{n}", "scenario": f"robust-{n}", "kind": "robustness",
             "malicious": True, "expect": [], "started_at": start, "ended_at": end,
             "result": {"pass": True, "checks": [{"name": "x", "ok": True}]}}
            for n, start, end in (("double-click", "2026-10-18T06:09:18Z", "2026-10-18T06:09:54Z"),
                                  ("slack-down", "2026-10-18T06:09:59Z", "2026-10-18T06:10:28Z"))]
    runs.append({"run_id": "run-202610180610-robust-mid-failure", "scenario": "robust-mid-failure",
                 "kind": "robustness", "malicious": True, "expect": [], "started_at": "2026-10-18T06:10:32Z",
                 "ended_at": "2026-10-18T06:11:15Z",
                 "result": {"pass": False, "checks": [{"name": "execution", "ok": False, "detail": "harness error"}]}})
    cases = [_case(1, rule="100110", status="DISMISSED", created="2026-10-18T06:09:33Z",
                   approver="sim:run-202610180609-robust-double-click"),
             _case(2, rule="100110", status="DISMISSED", created="2026-10-18T06:10:16Z",
                   approver="sim:run-202610180609-robust-slack-down")]
    assert [catalog.case_in_run(cases[1], r) for r in runs] == [False, True, False]  # windows overlap, actor decides
    m = ev.compute_metrics(cases, runs, {})
    assert "100110" not in m["rule_quality"]
    assert {k: m["robustness"][k] for k in ("runs", "passed", "not_executed")} == {"runs": 2, "passed": 2,
                                                                                    "not_executed": 1}
    assert "không thực thi" in ev.render_markdown(m)


def test_metrics_false_negative_and_shadow_ok():
    m = ev.compute_metrics([], RUNS, _meta())
    q = m["rule_quality"]
    assert q["100100"]["fn"] == 1 and q["100100"]["recall"] == 0.0
    assert q["100101"]["shadow_ok"] == 1
    assert m["attack_coverage"]["coverage_of_exercised"] == 0.0


def test_pipeline_only_sample_findings_are_excluded_from_detection_metrics():
    run = {"run_id": "sample-run", "malicious": False, "evaluation_scope": "pipeline_only",
           "techniques": [], "started_at": "2026-10-06T10:00:00Z", "ended_at": "2026-10-06T10:00:01Z",
           "expect": [{"source": "guardduty", "rule_id": "sample-type", "case": True}]}
    case = _case(1, rule="sample-type", source="guardduty", created="2026-10-06T10:00:02Z")
    metrics = ev.compute_metrics([case], [run], {})
    assert metrics["rule_quality"] == {}
    assert metrics["attack_coverage"]["techniques_exercised"] == []
    assert metrics["attack_coverage"]["techniques_detected"] == []
    assert metrics["counts"]["excluded_cases"] == 1
    assert metrics["detection_latency_by_source_s"] == {"alert_to_case": {}, "run_start_to_case": {}}
    assert metrics["alert_duplication_reduction"]["alerts"] == 0


def test_a_measurement_period_excludes_runs_of_an_earlier_system_version():
    old = {**RUNS[0], "run_id": "run-old", "started_at": "2026-10-06T09:00:00.000Z"}
    new = {**RUNS[0], "run_id": "run-new", "rules_release": "facf9b9c"}
    cases, runs = ev.in_scope([_case(1, created="2026-10-06T09:00:30.000Z")], [old, new], "2026-10-06T09:30:00Z")
    assert cases == [] and [r["run_id"] for r in runs] == ["run-new"]
    assert ev.compute_metrics(cases, runs, {})["scope"]["rules_releases"] == ["facf9b9c"]
    with pytest.raises(ValueError, match="ISO"):
        ev.in_scope([], [], "yesterday")


def test_metrics_empty_dataset_does_not_crash():
    m = ev.compute_metrics([], [], {})
    assert m["counts"]["cases"] == 0 and m["alert_duplication_reduction"]["reduction"] is None
    assert "Báo cáo đánh giá" in ev.render_markdown(m)


def test_percentiles_and_summary():
    assert ev.percentile([1, 2, 3, 4, 100], 50) == 3 and ev.percentile([], 50) is None
    assert ev.percentile([10], 95) == 10 and ev.summary([])["n"] == 0
    s = ev.summary([1.0, 2.0, 3.0, 4.0])
    assert s["p50"] == 2.5 and s["max"] == 4.0


def test_baseline_comparison():
    assert ev.baseline_comparison([], {"p50": 10})["available"] is False
    b = ev.baseline_comparison([{"seconds_to_contain": "300", "manual_steps": "9"},
                                {"seconds_to_contain": "500", "manual_steps": "7"}], {"p50": 20.0, "n": 3})
    assert b["baseline_contain_p50_s"] == 400.0 and b["contain_time_delta_s"] == 380.0
    assert b["drills"] == 2 and b["soar_cases"] == 3
    assert b["soar_manual_steps"] is None  # nothing observed: never assume a number
    b = ev.baseline_comparison([{"seconds_to_contain": "300", "manual_steps": "9"}], {"p50": 20.0}, [2, 2, 1])
    assert b["soar_manual_steps"] == 1.7


def test_the_baseline_is_compared_with_the_whole_soar_response_not_the_automated_step():
    """Session 3, real case: notified 01:49:44.8, approved 02:01:14.9 (the operator was busy), contained 02:01:22.0.
    containment_seconds (7.1 s) starts at the approval; a manual response starts at the finding. The comparison uses
    case -> contained (701.3 s), which includes the human reaction like the baseline does."""
    case = _case(1, rule="R", source="guardduty", status="RESTORED", created="2026-10-19T01:49:40.697Z",
                 notified_at="2026-10-19T01:49:44.805Z", approved_at="2026-10-19T02:01:14.881Z",
                 isolated_at="2026-10-19T02:01:21.995Z", containment_seconds=7.11, restoring_at="2026-10-19T02:03:10Z")
    m = ev.compute_metrics([case], [], {}, [{"seconds_to_contain": "900", "manual_steps": "4"}])
    assert m["time_to_containment_s"]["p50"] == 7.11
    assert m["approval_wait_s"]["p50"] == 690.08 and m["case_to_containment_s"]["p50"] == 701.3
    b = m["baseline_comparison"]
    assert b["soar_case_to_contained_p50_s"] == 701.3 and b["contain_time_delta_s"] == 198.7
    assert b["soar_manual_steps"] == 2  # approve + restore, read from the case
    assert "drills" in ev.compute_metrics([], [], {})["baseline_comparison"]


def test_settle_windows_are_checked_against_the_measured_lag():
    base = {"kind": "atomic", "malicious": True, "expect": [], "started_at": "2026-10-19T03:00:00Z",
            "ended_at": "2026-10-19T03:00:10Z", "settle_seconds": 120, "target": "i-0abc1234def567890"}
    fast = {**base, "run_id": "run-1", "scenario": "fast", "siem_alerts": [{"rule_id": "1", "timestamp":
                                                                             "2026-10-19T03:00:14Z"}]}
    slow = {**base, "run_id": "run-2", "scenario": "slow", "started_at": "2026-10-19T04:00:00Z",
            "ended_at": "2026-10-19T04:00:10Z", "siem_alerts": [{"rule_id": "1", "timestamp": "2026-10-19T04:01:20Z"}]}
    cloud = {**base, "run_id": "run-3", "scenario": "cloud", "kind": "stratus", "started_at": "2026-10-19T05:00:00Z",
             "ended_at": "2026-10-19T05:01:00Z", "settle_seconds": 1800, "target": "lab-victim/AKIAIOSFODNN7EXAMPLE",
             "target_unique": True}
    late_case = _case(1, rule="R", source="guardduty", created="2026-10-19T05:40:00Z",
                      resource_id="lab-victim/AKIAIOSFODNN7EXAMPLE")
    w = ev.window_headroom([late_case], [fast, slow, cloud])
    assert w["fast"] == {"runs": 1, "max_lag_s": 4.0, "settle_s": 120, "cut_off": True, "tight": False}
    assert w["slow"]["max_lag_s"] == 70.0 and w["slow"]["tight"] is True        # used more than half the window
    assert w["cloud"]["max_lag_s"] == 2340.0 and w["cloud"]["tight"] is False   # no cut-off: informative only
    assert "SÁT" in ev.render_markdown(ev.compute_metrics([late_case], [fast, slow, cloud], {}))


def test_a_repeat_run_merged_into_the_open_case_is_detected_not_missed():
    """Two host-useradd runs within the dedup window: the second alert is merged into the case of the first (by
    design). The second run is a detection (tp_merged), not a pipeline false negative, and the case still belongs to
    the first run only."""
    exp = [{"source": "wazuh", "rule_id": "100110", "case": True}]
    base = {"scenario": "host-useradd", "kind": "atomic", "malicious": True, "techniques": ["T1136.001"],
            "evidence": True, "expect": exp, "settle_seconds": 120, "target": "i-0abc1234def567890"}
    first = {**base, "run_id": "run-1", "started_at": "2026-10-19T04:00:00Z", "ended_at": "2026-10-19T04:00:10Z"}
    second = {**base, "run_id": "run-2", "started_at": "2026-10-19T04:20:00Z", "ended_at": "2026-10-19T04:20:10Z"}
    case = _case(1, rule="100110", created="2026-10-19T04:00:05Z", resource_id="i-0abc1234def567890",
                 merged_at=["2026-10-19T04:20:06Z"], alert_count=2)
    assert catalog.case_in_run(case, first) and not catalog.case_in_run(case, second)
    assert catalog.merged_in_run(case, second) and not catalog.merged_in_run(case, first)
    q = ev.compute_metrics([case], [first, second], {})["rule_quality"]["100110"]
    assert q["tp"] == 2 and q["tp_merged"] == 1 and q["fn"] == 0 and q["recall"] == 1.0
    check = runner.match_expectations(exp, [case], second)[0]
    assert check["ok"] and check["detail"] == ["C1"]
    elsewhere = {**case, "resource_id": "i-0fff1234def567890"}  # merged on another host: not this run's detection
    assert not catalog.merged_in_run(elsewhere, second)


def test_guardduty_latency_uses_the_latest_activity_of_a_recurring_finding():
    case = _case(1, rule="Policy:IAMUser/RootCredentialUsage", source="guardduty", status="ACKNOWLEDGED",
                 created="2026-10-19T09:30:16.382Z", event="2026-10-19T04:06:41.000Z",
                 extra={"finding_count": 241, "last_seen": "2026-10-19T09:12:29.000Z"})
    lat = ev.compute_metrics([case], [], {})["detection_latency_by_source_s"]["alert_to_case"]["guardduty"]
    assert lat["p50"] == 1067.38  # 17.8 min from the last activity, not 5.4 h from the first occurrence


def test_clopper_pearson_matches_reference_values():
    """Exact binomial intervals; references: (alpha/2)^(1/n) for k = n, and R binom.test(7, 9)$conf.int."""
    assert ev.clopper_pearson(5, 5) == (0.478, 1.0)
    assert ev.clopper_pearson(20, 20) == (0.832, 1.0)
    assert ev.clopper_pearson(0, 10) == (0.0, 0.308)
    assert ev.clopper_pearson(7, 9) == (0.4, 0.972)      # R: 0.3999064 0.9718550
    assert ev.clopper_pearson(0, 0) is None and ev.clopper_pearson(3, 2) is None


def test_rates_are_reported_with_their_interval():
    run = {**RUNS[0], "run_id": "run-x", "siem_alerts": [{"rule_id": "100100", "timestamp": "2026-10-06T09:59:55Z"}]}
    m = ev.compute_metrics([], [run], {})
    b = m["detection_quality"]["rules"]["100100"]
    assert b["recall"] == 1.0 and b["recall_ci95"] == (0.025, 1.0)
    assert "1.0 [0.025–1.0]" in ev.render_markdown(m)


def test_variant_coverage_counts_public_tests_run_and_detected():
    index = {"ref": "388942adbd9641f4dfdcf079d7efe9a75ec0ac43", "tests": {
        "g1": {"technique": "T1053.003", "test_number": 3}, "g2": {"technique": "T1053.003", "test_number": 4},
        "g3": {"technique": "T1053.003", "test_number": 1}, "g4": {"technique": "T1087.001", "test_number": 1}}}
    scenarios = {"cron-a": {"atomic": {"test_guid": "g1"}}, "cron-b": {"atomic": {"test_guid": "g2"}},
                 "enum": {"atomic": {"test_guid": "g4"}}}
    base = {"malicious": True, "started_at": "2026-10-19T10:00:00Z", "ended_at": "2026-10-19T10:00:10Z"}
    runs = [{**base, "run_id": "r1", "scenario": "cron-a", "expect": [{"source": "wazuh", "rule_id": "100150"}],
             "siem_alerts": [{"rule_id": "100150"}]},
            {**base, "run_id": "r2", "scenario": "cron-b", "expect": [{"source": "wazuh", "rule_id": "100150"}],
             "siem_alerts": []},
            {**base, "run_id": "r3", "scenario": "enum", "expect": [], "siem_alerts": []},   # observation only
            {**base, "run_id": "r4", "scenario": "cron-b", "expect": [{"source": "wazuh", "rule_id": "1"}]}]  # unobserved
    v = ev.variant_coverage(runs, [], {}, scenarios, index)
    assert v["techniques"] == {"T1053.003": {"in_index": 3, "run": 2, "detected": 1},
                               "T1087.001": {"in_index": 1, "run": 1, "detected": 0}}
    assert v["index_tests"] == 4 and v["index_techniques"] == 2


def test_precision_needs_benign_runs_during_which_the_rule_was_deployed():
    """Lab 2026-10-20: rules deployed an hour earlier showed precision 1.0 with no benign run behind it."""
    meta = {"wazuh-100140": {"rule_id": 100140, "state": "shadow", "created": "2026-10-20"},
            "wazuh-100100": {"rule_id": 100100, "state": "shadow", "created": "2026-10-06"}}
    releases = {"old": {"wazuh-100100.yml"}, "new": {"wazuh-100100.yml", "wazuh-100140.yml"}}
    attack = {"run_id": "a", "malicious": True, "rules_release": "new", "started_at": "2026-10-19T18:00:00Z",
              "expect": [{"source": "wazuh", "rule_id": "100140"}, {"source": "wazuh", "rule_id": "100100"}],
              "siem_alerts": [{"rule_id": "100140"}, {"rule_id": "100100"}]}
    benign_old = {"run_id": "b", "malicious": False, "rules_release": "old", "started_at": "2026-10-19T03:00:00Z",
                  "expect": [], "siem_alerts": []}
    dq = ev.detection_quality([attack, benign_old], meta, releases=releases.get)["rules"]
    assert dq["100140"]["benign_runs"] == 0 and dq["100140"]["precision"] is None   # not measured, not 1.0
    assert dq["100100"]["benign_runs"] == 1 and dq["100100"]["precision"] == 1.0
    assert dq["100140"]["recall"] == 1.0
    m = ev.compute_metrics([], [attack, benign_old], meta)
    m["detection_quality"] = ev.detection_quality([attack, benign_old], meta, releases=releases.get)
    assert "chưa đo (0 lượt lành tính)" in ev.render_markdown(m)
    # a run recorded before releases were tracked: the rule's creation date decides
    legacy = {**benign_old, "rules_release": None, "started_at": "2026-10-21T08:00:00Z"}
    dq = ev.detection_quality([attack, legacy], meta, releases=releases.get)["rules"]
    assert dq["100140"]["benign_runs"] == 1 and dq["100140"]["precision"] == 1.0


def test_manual_steps_are_read_from_the_case_timeline():
    assert ev.manual_steps({"approved_at": "t1", "restoring_at": "t2"}) == 2
    assert ev.manual_steps({"approved_at": "t1"}) == 1
    assert ev.manual_steps({"dismissed_at": "t1"}) == 1 and ev.manual_steps({}) == 0


def test_failed_execution_and_sample_cases_are_not_detection_evidence():
    failed = {"run_id": "run-f-1", "malicious": True, "techniques": ["T1136.001"],
              "started_at": "2026-10-06T10:00:00.000Z", "ended_at": "2026-10-06T10:00:05.000Z",
              "expect": [{"source": "wazuh", "rule_id": "100110", "case": True}],
              "result": {"pass": False, "checks": [{"name": "execution", "ok": False, "detail": "ssm command Failed"}]}}
    ok = {**failed, "run_id": "run-f-2", "result": {"pass": True, "checks": []}}
    sample = _case(9, rule="Recon:EC2/Portscan", source="guardduty", sample=True)
    m = ev.compute_metrics([sample], [failed], {})
    assert m["rule_quality"] == {}  # no FN: the attack never ran
    assert m["attack_coverage"]["techniques_exercised"] == []
    assert m["counts"]["invalid_runs"] == ["run-f-1"] and m["counts"]["excluded_cases"] == 1
    assert ev.compute_metrics([], [ok], {})["rule_quality"]["100110"]["fn"] == 1  # a run that executed still counts
    assert ev.execution_failed({"run_id": "x", "execution_error": "boom"})


def test_baseline_inputs_must_be_numeric():
    with pytest.raises(ValueError, match="seconds_to_contain"):
        ev.baseline_comparison([{"seconds_to_contain": "NaN"}], {})


def test_the_evaluator_holds_no_price_constants():
    assert not hasattr(ev, "PRICES") and not hasattr(ev, "estimate_cost")  # prices come from the Pricing API



def test_markdown_report_renders_all_sections():
    cases = [_case(1, run_id="run-a-1", containment_seconds=9.0)]
    md = ev.render_markdown(ev.compute_metrics(cases, RUNS, _meta(),
                                               cost={"sessions": [{"hours": 2.0}],
                                                     "actual": {"total_usd": 1.2, "by_service_usd": {"EC2": 1.2},
                                                                "note": "billed"},
                                                     "estimate": {"error": "AccessDenied"}},
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
    import boto3
    boto3.client("ssm", region_name="ap-southeast-1").put_parameter(
        Name="/siemsoar/slack/approver_ids", Value="U0APPROVER", Type="String", Overwrite=True)
    decide = ["decide", cid, "--gate", "approval", "--decision", "dismiss", "--approver", "U0APPROVER"]
    monkeypatch.setattr(soarctl.sys.stdin, "isatty", lambda: False)
    assert soarctl.main(decide) == 1 and store.get_case(cid)["status"] == Status.NOTIFIED  # no terminal: no decision
    monkeypatch.setattr(soarctl.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: cid)
    assert soarctl.main([*decide[:-1], "U0SOMEONE"]) == 1  # not on the approver list
    assert soarctl.main(decide) == 0
    assert store.get_case(cid)["status"] == Status.DISMISSED
    assert sfn.success[0][1]["channel"] == "cli" and sfn.success[0][1]["actor"] == "cli:U0APPROVER"
    audit = [a for a in store.list_audit(cid) if a["action"] == "decision:approval:dismiss"][0]
    assert audit["detail"]["aws_principal"].startswith("arn:aws")  # who ran the CLI is kept next to who approved
    assert soarctl.main(decide) == 1  # rejected: already handled
    stats = soarctl.feedback_stats(store)
    assert stats["UnauthorizedAccess:EC2/SSHBruteForce"] == {"cases": 1, "false_positive": 1}


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
             "expect": [{"source": "wazuh", "rule_id": "199999", "case": True}]}]
    cases = [_case(1, rule="199999", run_id="run-k-1", created="2026-10-06T10:00:20.000Z")]
    m = ev.compute_metrics(cases, runs, _meta())
    assert "199999" not in m["rule_quality"]
    assert m["pipeline_canary"] == {"rules": ["199999"], "expected": 1, "observed": 1, "pipeline_ok": True}
    assert m["attack_coverage"]["techniques_exercised"] == []  # a self-written marker is not an exercised technique
    assert "Canary pipeline" in ev.render_markdown(m)
    missed = ev.compute_metrics([], runs, _meta())
    assert missed["pipeline_canary"]["pipeline_ok"] is False  # no case for the marker: the pipeline is broken


def test_no_shipped_rule_detects_a_marker_that_the_simulation_writes_itself():
    # self-generated markers prove nothing about detection: the repository ships none, pipeline liveness uses AWS samples
    assert not [k for k, m in rulesctl.load_metadata().items() if m.get("canary")]


def _runner_with_fake_ssm(monkeypatch, fail_verify=False):
    calls = []
    r = object.__new__(runner.Runner)
    monkeypatch.setattr(r, "instance", lambda role: "i-sensor", raising=False)
    monkeypatch.setattr(r, "attack_target", lambda role: "i-sensor", raising=False)  # not contained

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
    assert calls[0].startswith("HOME=/root ART_REF=388942adbd9641f4dfdcf079d7efe9a75ec0ac43 python3 ")
    assert calls[1] == "getent passwd siemsoar_sim_beef" and calls[2].endswith("--timeout 120 --cleanup")
    assert calls[3].startswith("userdel -r siemsoar_sim_beef")
    assert out["atomic"]["technique"] == "T1136.001"


def test_atomic_scenario_backs_up_before_and_restores_after(monkeypatch):
    r, calls = _runner_with_fake_ssm(monkeypatch)
    r.exec_atomic(runner.load_scenarios()["host-sudoers"], "run-x-beef")
    assert calls[0].startswith("cp -p /etc/sudoers /var/tmp/") and "run_atomic.py T1548.003" in calls[1]
    assert calls[-2].endswith(" --cleanup") and "run_atomic.py T1548.003" in calls[-2]  # the upstream cleanup
    assert calls[-1].startswith("cp -p /var/tmp/sudoers.siemsoar.bak /etc/sudoers")     # then the scenario's


def test_atomic_failure_is_an_execution_error_not_a_silent_false_negative(monkeypatch):
    r, calls = _runner_with_fake_ssm(monkeypatch, fail_verify=True)
    with pytest.raises(RuntimeError):
        r.exec_atomic(runner.load_scenarios()["host-useradd"], "run-x-beef")
    assert calls[-2].endswith(" --cleanup") and calls[-1].startswith("userdel")  # both cleanups still ran


def test_the_upstream_cleanup_runs_for_scenarios_that_declare_none(monkeypatch):
    """host-cron-crond relies on the test's own cleanup_command; it must run after verify even when nothing else
    is declared (lab 2026-10-19: /etc/cron.d/persistevil and the systemd unit were left behind)."""
    r, calls = _runner_with_fake_ssm(monkeypatch)
    out = r.exec_atomic(runner.load_scenarios()["host-cron-crond"], "run-x-beef")
    assert "run_atomic.py T1053.003 078e69eb" in calls[0] and not calls[0].endswith("--cleanup")
    assert calls[-1].endswith(" --cleanup") and "078e69eb-d9fb-450e-b9d0-2e118217c846" in calls[-1]
    assert "cleanup" in out


def test_atomic_source_requires_a_commit_and_caches_by_commit(tmp_path, monkeypatch):
    from scripts import run_atomic

    sha = "a" * 40
    calls = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"atomic source pinned to commit"

    monkeypatch.setattr(run_atomic, "ART_CACHE", tmp_path)
    monkeypatch.setattr(run_atomic.urllib.request, "urlopen",
                        lambda url, timeout: calls.append((url, timeout)) or FakeResponse())
    path, root = run_atomic.ensure_atomic("T1136.001", sha)
    assert path.read_bytes() == b"atomic source pinned to commit"
    assert root == tmp_path / sha and sha in calls[0][0]
    run_atomic.ensure_atomic("T1136.001", sha)
    assert len(calls) == 1
    with pytest.raises(ValueError, match="commit SHA"):
        run_atomic.ensure_atomic("T1136.001", "master")


def test_stratus_requires_the_expected_aws_account_and_successful_cleanup(monkeypatch):
    from types import SimpleNamespace

    class FakeAWS:
        def client(self, service):
            assert service == "sts"
            return SimpleNamespace(get_caller_identity=lambda: {"Account": "111122223333"})

    r = object.__new__(runner.Runner)
    r.aws = FakeAWS()
    monkeypatch.setenv("SIEMSOAR_LAB_ACCOUNT_ID", "999900001111")
    calls = []
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: calls.append(a) or SimpleNamespace(returncode=0))
    with pytest.raises(RuntimeError, match="refusing Stratus"):
        r.exec_stratus({"stratus_technique": "aws.persistence.iam-create-user-login-profile"}, "run-x")
    assert calls == []

    monkeypatch.setenv("SIEMSOAR_LAB_ACCOUNT_ID", "111122223333")
    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0 if command[1] == "detonate" else 1)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="cleanup failed"):
        r.exec_stratus({"stratus_technique": "aws.persistence.iam-create-user-login-profile"}, "run-y")
    assert [command[1] for command in calls[-2:]] == ["detonate", "cleanup"]

    # detonating as the victim: the run's target is the victim key, i.e. the resource id of the case it should open
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    r.victim_credentials = lambda: {"user": "lab-victim", "AWS_ACCESS_KEY_ID": "AKIAEXAMPLEVICTIM",
                                    "AWS_SECRET_ACCESS_KEY": "x"}
    r.aws.region = lambda: "us-east-1"
    out = r.exec_stratus({"stratus_technique": "aws.defense-evasion.cloudtrail-stop", "detonate_as": "victim"}, "run-z")
    assert out["target"] == "lab-victim/AKIAEXAMPLEVICTIM"
    assert catalog.case_in_run({"resource_id": "Huy/AKIAOPERATOR", "created_at": "2026-10-18T06:34:00Z"},
                               {"target": out["target"], "started_at": "2026-10-18T06:14:14Z",
                                "ended_at": "2026-10-18T06:15:42Z", "settle_seconds": 1800}) is False


def test_the_victim_policy_allows_the_stratus_preflight_and_only_stratus_trails():
    """Stratus' auth check is ec2:DescribeAccountAttributes (CloudTrail of a failed lab run): without it the victim key
    never reaches StopLogging. Anything beyond that read and the Stratus trails would widen the simulation zone."""
    import re
    from pathlib import Path
    tf = (Path(__file__).resolve().parents[2] / "infra/modules/lab-ondemand/iam.tf").read_text()
    doc = re.search(r'data "aws_iam_policy_document" "victim" \{(.*?)\n\}', tf, re.S).group(1)
    statements = dict(re.findall(r'actions\s+= \[([^\]]*)\]\s+resources = \[([^\]]*)\]', doc))
    assert statements == {'"cloudtrail:StopLogging", "cloudtrail:GetTrailStatus"':
                          '"arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/stratus-red-team-*"',
                          '"ec2:DescribeAccountAttributes"': '"*"'}


def test_a_shadow_pass_requires_proof_that_the_rule_fired():
    base = {"run_id": "run-s-1", "malicious": True, "techniques": ["T1110"], "started_at": "2026-10-06T10:00:00.000Z",
            "ended_at": "2026-10-06T10:00:05.000Z", "expect": [{"source": "wazuh", "rule_id": "100121", "case": False}]}
    q = lambda **kw: ev.compute_metrics([], [{**base, **kw}], {})["rule_quality"]["100121"]  # noqa: E731
    assert q(observed={"wazuh:100121": True})["shadow_ok"] == 1
    missed = q(observed={"wazuh:100121": False})
    assert missed["shadow_missed"] == 1 and missed["fn"] == 1 and missed["shadow_ok"] == 0  # rule never alerted
    unchecked = q()
    assert unchecked["shadow_unverified"] == 1 and unchecked["shadow_ok"] == 0


def test_siem_observation_helpers():
    cmd = runner.siem_alerts_command("i-0abc1234def567890")
    assert "alerts.json" in cmd and 'select(.agent.name=="i-0abc1234def567890")' in cmd and 'index("siemsoar")' in cmd
    with pytest.raises(ValueError):
        runner.siem_alerts_command("i-1; rm -rf /")  # the agent name is interpolated into a shell command
    alerts = runner.parse_siem_alerts("\n".join(["100121 2026-10-06T10:00:30.123+0000", "garbage",
                                                   "100100 2026-10-06T09:00:00.000+0000"]))
    assert [a["rule_id"] for a in alerts] == ["100121", "100100"]
    window = runner.in_window(alerts, "2026-10-06T10:00:00Z", "2026-10-06T10:00:10Z", 60)
    assert [a["rule_id"] for a in window] == ["100121"]  # the 09:00 alert is outside the run window
    expect = [{"source": "wazuh", "rule_id": "100121", "case": False}, {"source": "wazuh", "rule_id": "100100", "case": True},
              {"source": "wazuh", "rule_id": "100102", "case": False, "siem_alert": False},
              {"source": "guardduty", "rule_id": "X:Y/Z", "case": True}]
    assert runner.observe_expectations(expect, window) == {"wazuh:100121": True, "wazuh:100100": False}


# ------------------------------------------------------------------ false positives / negatives are measured, not hidden
BENIGN = {"run_id": "run-b-9", "scenario": "host-benign-service-account", "kind": "ssm_shell", "malicious": False,
          "target": "i-0abc1234def567890", "techniques": [], "started_at": "2026-10-06T14:00:00.000Z",
          "ended_at": "2026-10-06T14:00:05.000Z", "settle_seconds": 120, "expect": [],
          "siem_alerts": [{"rule_id": "100110", "timestamp": "2026-10-06T14:00:10.000Z"},
                          {"rule_id": "100100", "timestamp": "2026-10-06T14:00:11.000Z"}]}


def test_a_case_from_a_benign_run_is_a_false_positive_even_though_no_rule_was_expected():
    # used to be "unlabelled": attribution required an expectation on the rule, so a benign run could never yield a FP
    case = _case(1, rule="100110", resource_id="i-0abc1234def567890", created="2026-10-06T14:00:30.000Z",
                 status="DISMISSED", approver="sim:ground-truth:run-b-9")
    m = ev.compute_metrics([case], [BENIGN], {})
    assert m["rule_quality"]["100110"]["fp"] == 1 and m["rule_quality"]["100110"]["human_fp"] == 0
    dq = m["detection_quality"]
    assert dq["rules"]["100110"]["fp"] == 1 and dq["rules"]["100100"]["fp"] == 1 and dq["benign_runs"] == 1


def test_a_case_on_another_instance_or_outside_the_window_is_not_attributed():
    other = _case(1, rule="100110", resource_id="i-0fff0000aaaa11112", created="2026-10-06T14:00:30.000Z")
    late = _case(2, rule="100110", resource_id="i-0abc1234def567890", created="2026-10-06T14:10:00.000Z")
    labels = ev.classify([other, late], [BENIGN])["labels"]
    assert labels == {"C1": "unlabelled", "C2": "unlabelled"}


def test_overlapping_runs_on_the_same_target_make_a_case_ambiguous():
    twin = {**BENIGN, "run_id": "run-b-10"}
    case = _case(1, rule="100110", resource_id="i-0abc1234def567890", created="2026-10-06T14:00:30.000Z")
    assert ev.classify([case], [BENIGN, twin])["labels"]["C1"] == "unlabelled"


def test_ground_truth_dismissals_are_not_human_feedback_but_real_ones_are():
    sim = _case(1, rule="100110", status="DISMISSED", approver="sim:ground-truth:run-x", created="2026-10-07T00:00:00Z")
    human = _case(2, rule="100110", status="DISMISSED", approver="U012ABCDEF", created="2026-10-07T01:00:00Z")
    q = ev.classify([sim, human], [])["rules"]["100110"]
    assert q["human_fp"] == 1 and q["unlabelled"] == 1


def test_unexpected_rule_in_a_malicious_run_is_unplanned_not_tp_or_fp():
    run = {**RUNS[0], "target": "i-0abc1234def567890"}
    case = _case(1, rule="100102", resource_id="i-0abc1234def567890", created="2026-10-06T10:00:20.000Z")
    q = ev.classify([case], [run])["rules"]["100102"]
    assert q["unplanned"] == 1 and q["tp"] == 0 and q["fp"] == 0


def test_false_negatives_are_split_into_detection_and_pipeline_misses():
    base = {**RUNS[0], "expect": [{"source": "wazuh", "rule_id": "100110", "case": True},
                                  {"source": "wazuh", "rule_id": "100100", "case": True}]}
    q = ev.classify([], [{**base, "observed": {"wazuh:100110": True, "wazuh:100100": False}}])["rules"]
    assert q["100110"]["fn_pipeline"] == 1 and q["100100"]["fn_detection"] == 1  # alert without case vs no alert
    assert ev.classify([], [base])["rules"]["100110"]["fn_unverified"] == 1


def test_detection_layer_scores_shadow_rules_without_any_case():
    run = {**RUNS[0], "expect": [{"source": "wazuh", "rule_id": "100102", "case": False},
                                 {"source": "wazuh", "rule_id": "100104", "case": False}],
           "siem_alerts": [{"rule_id": "100102", "timestamp": "2026-10-06T10:00:01.000Z"},
                           {"rule_id": "100103", "timestamp": "2026-10-06T10:00:02.000Z"}]}
    dq = ev.detection_quality([run], rulesctl.load_metadata())
    assert dq["rules"]["100102"]["tp"] == 1 and dq["rules"]["100102"]["state"] == "shadow"
    assert dq["rules"]["100104"]["fn"] == 1 and dq["rules"]["100103"]["unplanned"] == 1
    assert ev.detection_quality([{**run, "siem_alerts": None} if False else {k: v for k, v in run.items()
                                                                              if k != "siem_alerts"}])[
        "unobserved_runs"] == 1


def test_lab_procedure_techniques_are_reported_but_not_counted_as_coverage():
    lab = {"run_id": "run-l-1", "scenario": "host-ssh-burst-existing", "kind": "ssm_shell", "malicious": True,
           "techniques": ["T1110"], "started_at": "2026-10-06T10:00:00Z", "ended_at": "2026-10-06T10:00:05Z",
           "expect": []}
    cov = ev.compute_metrics([], [lab], {})["attack_coverage"]
    assert cov["techniques_exercised"] == [] and cov["techniques_declared_by_lab_procedures"] == ["T1110"]


def test_runner_closes_benign_cases_with_the_ground_truth_actor(monkeypatch):
    from siemsoar import decisions
    calls = []
    monkeypatch.setattr(decisions, "apply_decision", lambda store, cid, gate, decision, actor, channel:
                        calls.append((cid, gate, decision, actor, channel)))
    r = object.__new__(runner.Runner)
    r.store, r.log = None, print
    mine = [_case(1, rule="100110", status="NOTIFIED", resource_id="i-0abc1234def567890",
                  created="2026-10-06T14:00:30.000Z"),
            _case(2, rule="100110", status="NOTIFIED", resource_id="i-0abc1234def567890",
                  created="2026-10-06T18:00:00.000Z")]  # outside the window: left alone
    assert r.close_benign_cases(BENIGN, mine) == ["C1"]
    assert calls == [("C1", "approval", "dismiss", "sim:ground-truth:run-b-9", "cli")]


def test_robustness_scenarios_open_their_case_through_a_real_detection():
    # the trigger is a public attack procedure; it opens a case once its rule is promoted to active (the runner
    # refuses to start otherwise, see Runner._open_case_via)
    for s in runner.load_scenarios().values():
        if s["kind"] == "robustness":
            trigger = runner.load_scenarios()[s["trigger"]]
            assert trigger["kind"] == "atomic" and any(e["source"] == "wazuh" for e in trigger["expect"])
    assert not hasattr(runner.Runner, "_inject_finding")  # no fabricated findings


def test_robustness_without_a_trigger_is_rejected(tmp_path):
    scenario = {"id": "r", "title": "t", "kind": "robustness", "check": "double_click", "malicious": True}
    (tmp_path / "r.yml").write_text(json.dumps(scenario))  # JSON is valid YAML
    with pytest.raises(ValueError, match="trigger"):
        runner.load_scenarios(tmp_path)


# ------------------------------------------------------------------ run_atomic follows Atomic Red Team's own conventions
ART_TEST = {"name": "SSH Credential Stuffing From Linux", "supported_platforms": ["linux"],
            "input_arguments": {"target_host": {"default": "localhost"}},
            "dependencies": [{"description": "Requires SSHPASS", "prereq_command": "command -v sshpass"}],
            "executor": {"name": "bash", "command": 'cp "$PathToAtomicsFolder/T1110.004/src/credstuffuserpass.txt" /tmp/\n'
                                                    "ssh #{target_host}"}}


@pytest.mark.skipif(not hasattr(__import__("os"), "killpg"), reason="process groups: Linux lab hosts / CI only")
def test_run_atomic_kills_a_test_that_outlives_its_timeout():
    from scripts import run_atomic
    out = run_atomic._shell("bash", "echo started; sleep 30 & sleep 30", 1)
    assert out.timed_out and out.returncode is None and "started" in out.stdout


def test_run_atomic_renders_inputs_and_the_atomics_path(tmp_path):
    from scripts import run_atomic
    text = run_atomic.render(ART_TEST["executor"]["command"], ART_TEST, {"target_host": "10.0.1.5"}, tmp_path)
    assert f'cp "{tmp_path}/T1110.004/src/credstuffuserpass.txt" /tmp/' in text and text.endswith("ssh 10.0.1.5")
    with pytest.raises(ValueError, match="not input arguments"):
        run_atomic.render("x", ART_TEST, {"nope": "1"}, tmp_path)
    assert run_atomic.SRC_RE.findall(ART_TEST["executor"]["command"]) == [("T1110.004", "credstuffuserpass.txt")]


def test_run_atomic_fetches_src_files_and_stops_on_a_missing_prerequisite(tmp_path, monkeypatch, capsys):
    import yaml as _yaml

    from scripts import run_atomic
    sha = "b" * 40
    root = tmp_path / sha / "atomics" / "T1110.004"
    root.mkdir(parents=True)
    (root / "T1110.004.yaml").write_text(_yaml.safe_dump({"attack_technique": "T1110.004", "atomic_tests": [
        {**ART_TEST, "auto_generated_guid": "4f08197a-2a8a-472d-9589-cd2895ef22ad"}]}))
    fetched = []
    monkeypatch.setattr(run_atomic, "ART_CACHE", tmp_path)
    monkeypatch.setattr(run_atomic, "_download", lambda ref, rel, dest: fetched.append(rel) or dest.parent.mkdir(
        parents=True, exist_ok=True) or dest.write_text("u:p"))
    monkeypatch.setenv("ART_REF", sha)
    ran = []
    monkeypatch.setattr(run_atomic, "_shell", lambda executor, command, timeout: ran.append(command) or
                        type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})())
    assert run_atomic.main(["T1110.004", "4f08197a-2a8a-472d-9589-cd2895ef22ad"]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["missing_prerequisite"] == "Requires SSHPASS" and ran == ["command -v sshpass"]
    assert fetched == ["T1110.004/src/credstuffuserpass.txt"]
    monkeypatch.setattr(run_atomic, "_shell", lambda executor, command, timeout: ran.append(command) or
                        type("R", (), {"returncode": 0 if "sshpass" in command else 255, "stdout": "", "stderr": ""})())
    assert run_atomic.main(["T1110.004", "4f08197a-2a8a-472d-9589-cd2895ef22ad"]) == 0
    assert json.loads(capsys.readouterr().out)["exit_code"] == 255  # reported, judged by the scenario's verify


def test_known_false_positives_are_declared_only_for_benign_runs_and_still_counted(tmp_path):
    doc = {**ATOMIC, "expect": [{"source": "wazuh", "rule_id": "100110", "case": True, "false_positive": True}]}
    _write(tmp_path, doc)
    with pytest.raises(ValueError, match="false_positive expectations only"):
        runner.load_scenarios(tmp_path)
    run = {**BENIGN, "expect": [{"source": "wazuh", "rule_id": "100110", "case": True, "false_positive": True}]}
    case = _case(1, rule="100110", resource_id="i-0abc1234def567890", created="2026-10-06T14:00:30.000Z")
    m = ev.compute_metrics([case], [run], {})
    assert m["rule_quality"]["100110"]["fp"] == 1 and m["detection_quality"]["rules"]["100110"]["fp"] == 1


def test_the_runner_knows_every_resource_name_the_terraform_module_gives_the_lambdas():
    import re
    from pathlib import Path
    env = runner.resource_env("siemsoar", "314019368810")
    assert env["EVIDENCE_BUCKET"] == "siemsoar-evidence-314019368810"
    s3 = (Path(__file__).resolve().parents[2] / "infra/modules/serverless-core/s3.tf").read_text(encoding="utf-8")
    assert re.search(r'bucket\s*=\s*"\$\{var\.name_prefix\}-evidence-\$\{local\.account_id\}"', s3)

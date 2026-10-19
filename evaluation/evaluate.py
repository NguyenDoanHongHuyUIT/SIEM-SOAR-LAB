"""Turn stored cases + simulation runs into the proposal's evaluation metrics (chapter 6.2).

Ground truth comes from the runs (simulation/runner.py): what was executed, on which target, when, whether it was
malicious, and which rules were expected. Two layers are scored separately, because they fail for different reasons:

  * detection layer (`detection_quality`): the SIEMSOAR alerts Wazuh raised on the target during each run
    (`run.siem_alerts`, every lifecycle state). TP = expected rule alerted in a malicious run, FN = it did not,
    FP = any alert in a benign run that the run did not list as a lifecycle check. This is what decides whether a shadow
    rule may be promoted.
  * case layer (`rule_quality`): the cases the SOAR opened. A case is joined to a run by run_id, or by target + time
    window (catalog.case_in_run). FN is split into `fn_detection` (the rule never alerted) and `fn_pipeline` (it
    alerted but no case was opened), so a broken integration is not blamed on the rule.

Cases closed by the simulation's own ground truth (`sim:ground-truth`) are never counted as human feedback.

  python -m evaluation.evaluate [--prefix siemsoar] [--out reports] [--days 30] [--since ISO]
                                [--offline cases.json runs.json]

The baseline (manual response) is measured from CloudTrail only (evaluation/sources.py); there is no input for
self-reported stopwatch times.

compute_metrics() is pure (lists in, dict out) so it is unit tested without AWS.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src" / "lambdas"))

from siemsoar.util import parse_iso  # noqa: E402

from simulation.catalog import case_in_run, merged_in_run  # noqa: E402

GROUND_TRUTH_ACTOR = "sim:ground-truth"


def manual_steps(case: dict) -> int:
    """Human decisions this case actually needed, read from its own timestamps (approval gate, restore gate)."""
    return sum(1 for key in ("approved_at", "restoring_at", "dismissed_at", "acknowledged_at") if case.get(key))


def percentile(values: list[float], p: int) -> float | None:
    """p-th percentile with linear interpolation (statistics.quantiles, 'inclusive' = the usual definition)."""
    if not values:
        return None
    if len(values) == 1:
        return round(values[0], 2)
    return round(statistics.quantiles(values, n=100, method="inclusive")[p - 1], 2)


def summary(values: list[float]) -> dict:
    vals = [v for v in values if v is not None]
    return {"n": len(vals), "mean": round(statistics.fmean(vals), 2) if vals else None,
            "p50": percentile(vals, 50), "p95": percentile(vals, 95), "max": round(max(vals), 2) if vals else None}


def attribute(case: dict, runs: list[dict]) -> tuple[dict | None, dict | None]:
    """(run, matched expectation) for a case: the single run it belongs to (catalog.case_in_run) and the expectation
    on its rule, if the run listed one. Overlapping runs on the same target make the case ambiguous: (None, None).
    A run whose execution failed is a candidate only when no executed run claims the case: it carried out nothing
    (lab session 3: a Stratus run that never started had no target, so its window also covered the next run's case)."""
    owners = [r for r in runs if case_in_run(case, r)]
    if len(owners) > 1:
        owners = [r for r in owners if not execution_failed(r)] or owners
    if len(owners) != 1:
        return None, None
    run = owners[0]
    exp = next((e for e in run.get("expect", []) if str(e["rule_id"]) == str(case["rule_id"])
                and e["source"] == case["source"]), None)
    return run, exp


def _human_fp(case: dict) -> bool:
    by_sim = str(case.get("approver", "")).startswith("sim:")  # ground truth or a robustness script, not an analyst
    return not by_sim and (case["status"] == "DISMISSED" or case.get("verdict") == "false_positive")


def execution_failed(run: dict) -> bool:
    """True when the scenario itself could not be carried out (SSM/atomic/Stratus error, failed `verify:` command).

    Such a run says nothing about detection: counting its expectations as false negatives would blame the rule for an
    attack that never happened.
    """
    if run.get("execution_error"):
        return True
    return any(c.get("name") == "execution" and not c.get("ok") for c in (run.get("result") or {}).get("checks", []))


def classify(cases: list[dict], runs: list[dict], canary_rules: frozenset[str] = frozenset()) -> dict:
    """Case-layer labelling against the runs' ground truth. Returns per-rule counters and per-case labels.

    Not evidence: GuardDuty sample findings (`sample: true`), cases of runs whose execution failed, runs scoped
    `pipeline_only`, and robustness runs (they test the workflow with scripted decisions and injected faults).
    `canary_rules` (metadata `canary: true`) detect a marker the simulation writes itself: reported separately, never
    counted as TP/FP/FN.
    """
    rules: dict[str, dict] = {}
    labels: dict[str, str] = {}
    canary = {"rules": sorted(canary_rules), "expected": 0, "observed": 0}

    def bucket(rule_id: str) -> dict:
        return rules.setdefault(rule_id, {"tp": 0, "fp": 0, "fn": 0, "fn_detection": 0, "fn_pipeline": 0,
                                          "fn_unverified": 0, "shadow_violation": 0, "shadow_ok": 0,
                                          "shadow_missed": 0, "shadow_unverified": 0, "human_fp": 0,
                                          "unplanned": 0, "unlabelled": 0, "tp_merged": 0})

    invalid = {r["run_id"] for r in runs if execution_failed(r)}
    matched: set[tuple[str, str]] = set()
    for c in cases:
        if c.get("sample"):
            labels[c["case_id"]] = "sample"
            continue
        run, exp = attribute(c, runs)
        if str(c["rule_id"]) in canary_rules:
            labels[c["case_id"]] = "canary"
            if run and exp and (run["run_id"], str(exp["rule_id"])) not in matched:
                matched.add((run["run_id"], str(exp["rule_id"])))
                canary["observed"] += 1
            continue
        if run and run.get("evaluation_scope") == "pipeline_only":
            labels[c["case_id"]] = "pipeline_only"
            continue
        if run and run.get("kind") == "robustness":
            labels[c["case_id"]] = "robustness"
            continue
        if run and run["run_id"] in invalid:
            labels[c["case_id"]] = "invalid_run"
            continue
        b = bucket(str(c["rule_id"]))
        if run is None:
            label = "fp_human" if _human_fp(c) else "unlabelled"
            b["human_fp" if label == "fp_human" else "unlabelled"] += 1
        elif exp is not None:
            matched.add((run["run_id"], str(exp["rule_id"])))
            if exp.get("case", True) is False:  # shadow rule opened a case: a lifecycle bug, whatever the ground truth
                label = "shadow_violation"
            else:
                label = "tp" if run.get("malicious") else "fp"
            b[label] += 1
        elif run.get("malicious"):
            label = "unplanned"  # fired during an attack but the scenario did not predict it: review the expectation
            b["unplanned"] += 1
        else:
            label = "fp"         # anything a benign run produces that it did not list is a false positive
            b["fp"] += 1
        labels[c["case_id"]] = label
    for run in runs:
        if run.get("evaluation_scope") == "pipeline_only" or run["run_id"] in invalid:
            continue
        for e in run.get("expect", []):
            if str(e["rule_id"]) in canary_rules:
                canary["expected"] += e.get("case", True) is True
                continue
            if (run["run_id"], str(e["rule_id"])) in matched or e.get("optional"):
                continue
            b = bucket(str(e["rule_id"]))
            if e.get("case", True) and run.get("malicious", True) and any(
                    str(c["rule_id"]) == str(e["rule_id"]) and c["source"] == e["source"] and merged_in_run(c, run)
                    for c in cases):
                b["tp"] += 1          # detected; dedup merged it into the case already open on this target
                b["tp_merged"] += 1
                continue
            observed = (run.get("observed") or {}).get(f"{e['source']}:{e['rule_id']}")
            if e.get("case", True):
                if run.get("malicious", True):
                    b["fn"] += 1
                    # guardduty expectations have no SIEM layer: their miss is a detection miss by definition
                    key = {True: "fn_pipeline", False: "fn_detection"}.get(
                        observed, "fn_detection" if e["source"] == "guardduty" else "fn_unverified")
                    b[key] += 1
            else:  # shadow rule: no case is expected, but only a rule that really fired proves the lifecycle works
                if observed is True:
                    b["shadow_ok"] += 1
                elif observed is False:
                    b["shadow_missed"] += 1  # the rule never alerted, not even in shadow
                    if run.get("malicious", True):
                        b["fn"] += 1
                        b["fn_detection"] += 1
                else:
                    b["shadow_unverified"] += 1  # nobody checked the SIEM: cannot call this a pass
    for b in rules.values():
        fp = b["fp"] + b["human_fp"] + b["shadow_violation"]
        b["precision"] = round(b["tp"] / (b["tp"] + fp), 3) if b["tp"] + fp else None
        b["recall"] = round(b["tp"] / (b["tp"] + b["fn"]), 3) if b["tp"] + b["fn"] else None
    canary["pipeline_ok"] = (canary["observed"] >= canary["expected"]) if canary["expected"] else None
    return {"rules": rules, "labels": labels, "canary": canary, "invalid_runs": sorted(invalid)}


def detection_quality(runs: list[dict], rules_meta: dict | None = None) -> dict:
    """SIEM-layer TP/FP/FN per rule from `run.siem_alerts`, independent of lifecycle state and of the case pipeline.

    Runs that were not observed (no `siem_alerts`), failed, or are pipeline-only are not scored but counted.
    """
    states = {str(m.get("wazuh_rule_id") or m.get("rule_id")): m.get("state") for m in (rules_meta or {}).values()}
    rules: dict[str, dict] = {}
    unobserved = 0

    def bucket(rule_id: str) -> dict:
        return rules.setdefault(rule_id, {"state": states.get(rule_id), "tp": 0, "fp": 0, "fn": 0, "unplanned": 0,
                                          "benign_runs_seen": 0})

    benign_runs = 0
    for run in runs:
        if run.get("kind") == "robustness" or run.get("evaluation_scope") == "pipeline_only" or execution_failed(run):
            continue
        if "siem_alerts" not in run:
            unobserved += 1
            continue
        alerted = {str(a["rule_id"]) for a in run["siem_alerts"]}
        listed = {str(e["rule_id"]) for e in run.get("expect", [])
                  if e["source"] in ("wazuh", "suricata") and not e.get("false_positive")}
        required = {str(e["rule_id"]) for e in run.get("expect", [])
                    if e["source"] in ("wazuh", "suricata") and not e.get("optional")}
        if run.get("malicious"):
            for r in required:
                bucket(r)["tp" if r in alerted else "fn"] += 1
            for r in alerted - listed:
                bucket(r)["unplanned"] += 1
        else:
            benign_runs += 1
            for r in alerted - listed:
                bucket(r)["fp"] += 1
    for b in rules.values():
        b["precision"] = round(b["tp"] / (b["tp"] + b["fp"]), 3) if b["tp"] + b["fp"] else None
        b["recall"] = round(b["tp"] / (b["tp"] + b["fn"]), 3) if b["tp"] + b["fn"] else None
    return {"rules": rules, "benign_runs": benign_runs, "unobserved_runs": unobserved}


def attack_coverage(rules_meta: dict, runs: list[dict], labels: dict, cases: list[dict]) -> dict:
    """Techniques exercised by valid malicious runs and whether the system detected them (a TP case, or the expected
    rule alerting in the SIEM). Techniques of lab procedures (`ssm_shell`) are reported apart: their technique was
    declared by us, not taken from a public source."""
    live = {t for m in rules_meta.values() if m.get("state") in ("active", "enforce") for t in m.get("mitre", [])}
    valid = [r for r in runs if r.get("malicious") and not r.get("canary") and not execution_failed(r)
             and r.get("evaluation_scope") != "pipeline_only" and r.get("kind") != "robustness"]
    exercised = {t for r in valid if r.get("evidence", r.get("kind") != "ssm_shell") for t in r.get("techniques", [])}
    declared = {t for r in valid if not r.get("evidence", r.get("kind") != "ssm_shell")
                for t in r.get("techniques", [])} - exercised
    detected = set()
    for c in cases:
        if labels.get(c["case_id"]) == "tp":
            run, _ = attribute(c, runs)
            detected |= set((run or {}).get("techniques", []))
    for r in valid:
        required = {str(e["rule_id"]) for e in r.get("expect", []) if not e.get("optional")}
        if required & {str(a["rule_id"]) for a in r.get("siem_alerts", [])}:
            detected |= set(r.get("techniques", []))
    return {"techniques_in_active_rules": sorted(live), "techniques_exercised": sorted(exercised),
            "techniques_declared_by_lab_procedures": sorted(declared),
            "techniques_detected": sorted(detected & exercised),
            "coverage_of_exercised": round(len(detected & exercised) / len(exercised), 3) if exercised else None}


def baseline_comparison(baseline: list[dict], soar_case_to_contained: dict,
                        soar_steps: list[int] | None = None) -> dict:
    """Manual response vs SOAR, on the same interval: from the moment the detection is available (baseline: the
    GuardDuty finding is created; SOAR: the case is created from it) to containment. Both include the human reaction
    time (noticing + deciding); the SOAR number is NOT the approval-to-containment time, which would compare an
    automated step with a whole manual response."""
    secs = [_nonnegative_float(r["seconds_to_contain"], "seconds_to_contain") for r in baseline
            if r.get("seconds_to_contain") not in (None, "")]
    steps = [_nonnegative_float(r["manual_steps"], "manual_steps") for r in baseline
             if r.get("manual_steps") not in (None, "")]
    if not secs:
        return {"available": False, "drills": 0,
                "note": "no manual containment measured yet: needs console drills (docs/evaluation.md, Baseline)"}
    base_p50 = percentile(secs, 50)
    soar_p50 = soar_case_to_contained.get("p50")
    return {"available": True, "drills": len(secs), "baseline_contain_p50_s": base_p50,
            "soar_case_to_contained_p50_s": soar_p50, "soar_cases": soar_case_to_contained.get("n", 0),
            "baseline_manual_steps_mean": round(statistics.fmean(steps), 1) if steps else None,
            "soar_manual_steps": round(statistics.fmean(soar_steps), 1) if soar_steps else None,
            "contain_time_delta_s": round(base_p50 - soar_p50, 2) if soar_p50 is not None else None,
            "note": "both from detection available to containment, human reaction included"}


def window_headroom(cases: list[dict], runs: list[dict]) -> dict:
    """Per scenario: the latest detection after a run ended (SIEM alert or attributed case) vs its settle window.

    The settle windows are an operator choice; this checks them against what was measured. A window is `tight` when
    the slowest observed detection used more than half of it: a slower one next time could fall outside and become a
    false negative. Runs with a run-specific target have no cut-off (catalog.case_in_run), their lag is informative.
    """
    out: dict[str, dict] = {}
    for r in runs:
        end = parse_iso(r.get("ended_at"))
        if end is None or execution_failed(r) or r.get("kind") == "robustness":
            continue
        times = [parse_iso(a.get("timestamp")) for a in r.get("siem_alerts") or []]
        times += [parse_iso(c.get("created_at")) for c in cases if case_in_run(c, r)]
        lags = [(t - end).total_seconds() for t in times if t is not None]
        row = out.setdefault(r.get("scenario", "?"), {"runs": 0, "max_lag_s": None,
                                                      "settle_s": int(r.get("settle_seconds", 120)),
                                                      "cut_off": not r.get("target_unique")})
        row["runs"] += 1
        if lags:
            row["max_lag_s"] = round(max([max(lags)] + ([row["max_lag_s"]] if row["max_lag_s"] is not None else [])), 1)
    for row in out.values():
        row["tight"] = bool(row["cut_off"] and row["max_lag_s"] is not None and row["max_lag_s"] > row["settle_s"] / 2)
    return out


def in_scope(cases: list[dict], runs: list[dict], since: str | None) -> tuple[list[dict], list[dict]]:
    """Cases created and runs started at or after `since` (ISO time). A system change (e.g. a detection fix) starts a
    new measurement period: mixing runs of two versions would blame the fixed system for the old one's misses."""
    if not since:
        return cases, runs
    start = parse_iso(since)
    if start is None:
        raise ValueError(f"--since must be an ISO timestamp, got {since!r}")
    keep_c = [c for c in cases if (t := parse_iso(c.get("created_at"))) and t >= start]
    keep_r = [r for r in runs if (t := parse_iso(r.get("started_at"))) and t >= start]
    return keep_c, keep_r


def compute_metrics(cases: list[dict], runs: list[dict], rules_meta: dict | None = None,
                    baseline: list[dict] | None = None, deployments: list[dict] | None = None,
                    cost: dict | None = None) -> dict:
    rules_meta = rules_meta or {}
    cls = classify(cases, runs, frozenset(str(m["rule_id"]) for m in rules_meta.values() if m.get("canary")))
    excluded = {"pipeline_only", "sample", "invalid_run"}
    measured_cases = [c for c in cases if cls["labels"].get(c["case_id"]) not in excluded]
    pipeline: dict[str, list[float]] = {}
    e2e: dict[str, list[float]] = {}
    for c in measured_cases:
        # GuardDuty: the activity that triggered this delivery (eventLastSeen, kept in `extra.last_seen`); cases stored
        # before the schema used it carry the first occurrence as event_time, hours early for a recurring finding
        last = parse_iso((c.get("extra") or {}).get("last_seen")) if c["source"] == "guardduty" else None
        ev, cr = last or parse_iso(c.get("event_time")), parse_iso(c.get("created_at"))
        if ev and cr:
            pipeline.setdefault(c["source"], []).append(max(0.0, (cr - ev).total_seconds()))
        run, exp = attribute(c, runs)
        if run and exp and cr:
            e2e.setdefault(c["source"], []).append(max(0.0, (cr - parse_iso(run["started_at"])).total_seconds()))
    total_alerts = sum(int(c.get("alert_count", 1)) for c in measured_cases)
    containment = summary([c["containment_seconds"] for c in cases if c.get("containment_seconds") is not None])
    contained = [c for c in cases if c.get("isolated_at") and not c.get("decided_by_assistant")]
    case_to_contained = summary([round((parse_iso(c["isolated_at"]) - parse_iso(c["created_at"])).total_seconds(), 2)
                                 for c in contained if parse_iso(c.get("created_at"))])
    approval_wait = summary([round((parse_iso(c["approved_at"]) - parse_iso(c["notified_at"])).total_seconds(), 2)
                             for c in contained if parse_iso(c.get("approved_at")) and parse_iso(c.get("notified_at"))])
    robustness = [r for r in runs if r.get("kind") == "robustness"]
    lead = []
    for d in deployments or []:
        a, b = parse_iso(d.get("commit_time")), parse_iso(d.get("deployed_at"))
        if a and b:
            lead.append((b - a).total_seconds())
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {"rules_releases": sorted({r["rules_release"] for r in runs if r.get("rules_release")}),
                  "first_run": min((r["started_at"] for r in runs if r.get("started_at")), default=None)},
        "counts": {"cases": len(cases), "excluded_cases": len(cases) - len(measured_cases), "invalid_runs": cls["invalid_runs"],
               "alerts": total_alerts, "runs": len(runs),
                   "by_status": {s: sum(1 for c in cases if c["status"] == s) for s in sorted({c["status"] for c in cases})}},
        "detection_latency_by_source_s": {"alert_to_case": {k: summary(v) for k, v in pipeline.items()},
                                          "run_start_to_case": {k: summary(v) for k, v in e2e.items()}},
        "time_to_containment_s": containment,
        "approval_wait_s": approval_wait,
        "case_to_containment_s": case_to_contained,
        "time_to_evidence_preservation_s": summary([c["evidence_seconds"] for c in cases
                                                    if c.get("evidence_seconds") is not None]),
        "time_to_restore_s": summary([c["restore_seconds"] for c in cases if c.get("restore_seconds") is not None]),
        "rule_quality": cls["rules"],
        "detection_quality": detection_quality(runs, rules_meta),
        "pipeline_canary": cls["canary"],
        "attack_coverage": attack_coverage(rules_meta, runs, cls["labels"], cases),
        # same population on both sides: excluded cases (samples, failed runs) have their alerts excluded too
        "alert_duplication_reduction": {
            "alerts": total_alerts, "cases": len(measured_cases),
            "reduction": round(1 - len(measured_cases) / total_alerts, 3) if total_alerts else None},
        "rule_deployment_lead_time_s": summary(lead),
        # a run the harness could not carry out (e.g. its own setup error) tested nothing: listed, not scored
        "window_headroom": window_headroom(cases, runs),
        "robustness": {"runs": sum(1 for r in robustness if not execution_failed(r)),
                       "passed": sum(1 for r in robustness if r.get("result", {}).get("pass")),
                       "not_executed": sum(1 for r in robustness if execution_failed(r)),
                       "detail": [{"run": r["run_id"], "scenario": r["scenario"], "pass": r.get("result", {}).get("pass"),
                                   "executed": not execution_failed(r),
                                   "checks": r.get("result", {}).get("checks", [])} for r in robustness]},
        "operating_cost": cost or {"available": False, "note": "no cost data: run without --offline so that "
                                   "CloudTrail, the Pricing API and Cost Explorer can be queried"},
        "baseline_comparison": baseline_comparison(
            baseline or [], case_to_contained, [manual_steps(c) for c in contained]),
    }


def _fmt(s: dict) -> str:
    if not s or not s.get("n"):
        return "n/a"
    return f"n={s['n']} · p50 {s['p50']}s · p95 {s['p95']}s · max {s['max']}s"


def _render_cost(oc: dict) -> list[str]:
    if oc.get("available") is False:
        return [f"- n/a: {oc['note']}"]
    lines = []
    sessions = oc.get("sessions")
    if sessions is not None:
        lines.append(f"- Phiên lab (CloudTrail): {len(sessions)}; tổng {round(sum(x['hours'] for x in sessions), 2)} giờ")
    for name, label in (("actual", "Thực tế (Cost Explorer)"), ("estimate", "Ước tính (giá niêm yết AWS Pricing API)")):
        part = oc.get(name) or {}
        if part.get("error"):
            lines.append(f"- {label}: không lấy được ({part['error']})")
        elif "total_usd" in part:
            lines.append(f"- {label}: **${part['total_usd']}** theo dịch vụ {json.dumps(part['by_service_usd'])}. "
                         f"_{part['note']}_")
        elif "total_usd_compute_estimate" in part:
            lines.append(f"- {label}: **${part['total_usd_compute_estimate']}** "
                         f"(TB ${part['avg_usd_per_session']}/phiên). _{part['note']}_")
    return lines or ["- n/a"]


def render_markdown(m: dict) -> str:
    scope = m.get("scope") or {}
    L = ["# Báo cáo đánh giá SIEM/SOAR lab", f"_Sinh lúc {m['generated_at']}_", "",
         f"- Phạm vi: các lượt chạy từ {scope.get('since') or scope.get('first_run') or '-'}; bản phát hành rule: "
         f"{', '.join(s[:8] for s in scope.get('rules_releases', [])) or 'không ghi nhận'}",
         f"- Cases: **{m['counts']['cases']}**, alerts gộp vào: **{m['counts']['alerts']}**, "
         f"lượt mô phỏng: **{m['counts']['runs']}**",
         f"- Trạng thái: {json.dumps(m['counts']['by_status'])}", "", "## Độ trễ phát hiện (Detection latency per source)", "",
         "| Nguồn | alert → case | bắt đầu mô phỏng → case |", "|---|---|---|"]
    lat = m["detection_latency_by_source_s"]
    for s in sorted(set(lat["alert_to_case"]) | set(lat["run_start_to_case"])):
        L.append(f"| {s} | {_fmt(lat['alert_to_case'].get(s))} | {_fmt(lat['run_start_to_case'].get(s))} |")
    L += ["", "## Thời gian phản ứng", "",
          f"- Time to containment (từ lúc duyệt đến khi xác minh): {_fmt(m['time_to_containment_s'])}",
          f"- Thời gian chờ người duyệt (thông báo → duyệt): {_fmt(m.get('approval_wait_s'))}",
          f"- Từ khi có case đến khi ngăn chặn xong (gồm chờ duyệt): {_fmt(m.get('case_to_containment_s'))}",
          f"- Time to evidence preservation: {_fmt(m['time_to_evidence_preservation_s'])}",
          f"- Time to restore: {_fmt(m['time_to_restore_s'])}", "", "## Chất lượng rule (ground truth)", "",
          "Tầng case (SOAR):", "",
          "| Rule | TP | FP | FP (người dismiss) | Vi phạm shadow | FN (phát hiện / pipeline / chưa kiểm) "
          "| Ngoài dự kiến | Precision | Recall |",
          "|---|---|---|---|---|---|---|---|---|"]
    for rid, b in sorted(m["rule_quality"].items()):
        prec = "n/a" if b["precision"] is None else b["precision"]
        rec = "n/a" if b["recall"] is None else b["recall"]
        tp = f"{b['tp']} ({b['tp_merged']} gộp vào case đang mở)" if b.get("tp_merged") else b["tp"]
        L.append(f"| {rid} | {tp} | {b['fp']} | {b['human_fp']} | {b['shadow_violation']} | {b['fn']} "
                 f"({b['fn_detection']} / {b['fn_pipeline']} / {b['fn_unverified']}) | {b['unplanned']} "
                 f"| {prec} | {rec} |")
    dq = m["detection_quality"]
    L += ["", f"Tầng phát hiện (alert SIEM, mọi trạng thái vòng đời; {dq['benign_runs']} lượt lành tính, "
              f"{dq['unobserved_runs']} lượt chưa quan sát):", "",
          "| Rule | Trạng thái | TP | FP | FN | Ngoài dự kiến | Precision | Recall |", "|---|---|---|---|---|---|---|---|"]
    for rid, b in sorted(dq["rules"].items()):
        prec = "n/a" if b["precision"] is None else b["precision"]
        rec = "n/a" if b["recall"] is None else b["recall"]
        L.append(f"| {rid} | {b['state'] or '?'} | {b['tp']} | {b['fp']} | {b['fn']} | {b['unplanned']} "
                 f"| {prec} | {rec} |")
    k = m["pipeline_canary"]
    L += ["", "## Canary pipeline (không tính vào chất lượng rule)", "",
          f"- Rule canary: {', '.join(k['rules']) or '-'}; kỳ vọng {k['expected']}, quan sát {k['observed']} "
          f"→ pipeline {'OK' if k['pipeline_ok'] else 'n/a' if k['pipeline_ok'] is None else 'LỖI'}"]
    c = m["attack_coverage"]
    cov = "n/a" if c["coverage_of_exercised"] is None else c["coverage_of_exercised"]
    L += ["", "## Độ phủ ATT&CK", "",
          f"- Kỹ thuật trong rule active/enforce: {', '.join(c['techniques_in_active_rules']) or '-'}",
          f"- Kỹ thuật đã mô phỏng (Atomic/Stratus/pcap): {', '.join(c['techniques_exercised']) or '-'}",
          f"- Kỹ thuật do thủ tục lab tự khai (không tính coverage): "
          f"{', '.join(c['techniques_declared_by_lab_procedures']) or '-'}",
          f"- Kỹ thuật phát hiện đúng: {', '.join(c['techniques_detected']) or '-'} (coverage {cov})", "",
          "## Giảm trùng lặp cảnh báo", "",
          f"- {m['alert_duplication_reduction']['alerts']} alert → {m['alert_duplication_reduction']['cases']} case "
          f"(giảm {m['alert_duplication_reduction']['reduction']})", "",
          "## Rule deployment lead time", "", f"- {_fmt(m['rule_deployment_lead_time_s'])}", "",
          "## Cửa sổ chờ của kịch bản (kiểm chứng bằng số đo)", "",
          "| Kịch bản | Lượt | Phát hiện muộn nhất sau khi chạy xong | Cửa sổ | Đánh giá |", "|---|---|---|---|---|"]
    for sid, w in sorted((m.get("window_headroom") or {}).items()):
        verdict = ("không cắt (target riêng của lượt)" if not w["cut_off"] else
                   "SÁT: nới cửa sổ" if w["tight"] else "đủ dư" if w["max_lag_s"] is not None else "chưa có phát hiện")
        L.append(f"| {sid} | {w['runs']} | {w['max_lag_s'] if w['max_lag_s'] is not None else '-'} s | "
                 f"{w['settle_s']} s | {verdict} |")
    L += ["",
          "## Robustness", "", f"- Đạt {m['robustness']['passed']}/{m['robustness']['runs']} lượt chạy"
          + (f" ({m['robustness'].get('not_executed')} lượt không thực thi được do lỗi công cụ, không tính)"
             if m["robustness"].get("not_executed") else "")]
    for r in m["robustness"]["detail"]:
        verdict = ("PASS" if r["pass"] else "FAIL") if r.get("executed", True) else "không thực thi (lỗi công cụ)"
        L.append(f"  - {r['scenario']} ({r['run']}): {verdict}")
    L += ["", "## Chi phí vận hành mỗi phiên", ""] + _render_cost(m["operating_cost"]) + [
        "", "## So sánh baseline (GuardDuty email + cách ly thủ công)", ""]
    b = m["baseline_comparison"]
    L.append("- " + (b["note"] if not b["available"] else
                     f"{b['drills']} lượt cách ly thủ công đo từ CloudTrail: p50 {b['baseline_contain_p50_s']}s; SOAR "
                     f"(case → ngăn chặn, {b['soar_cases']} case) p50 {b['soar_case_to_contained_p50_s']}s; số thao "
                     f"tác thủ công {b['baseline_manual_steps_mean']} vs {b['soar_manual_steps']}. {b['note']}"))
    L += ["", "## Giới hạn", "", "Xem docs/limitations.md. Số liệu chỉ phản ánh lab một tài khoản với lưu lượng mô phỏng."]
    return "\n".join(L) + "\n"


def _nonnegative_float(value, field: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as err:
        raise ValueError(f"{field} must be numeric") from err
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{field} must be finite and non-negative")
    return number



def _guarded(fn, *args) -> dict:
    """Each AWS-backed source may be unavailable (no credentials, tag not activated yet): say so, never fill it in."""
    try:
        return fn(*args)
    except Exception as err:  # noqa: BLE001
        return {"error": f"{type(err).__name__}: {err}"}


def collect_cost(days: int) -> dict:
    """Lab sessions from CloudTrail, billed cost from Cost Explorer, list-price estimate from the Pricing API."""
    import boto3
    from siemsoar import aws

    from evaluation import sources
    end = datetime.now(UTC)
    start = end - timedelta(days=days)
    sessions = sources.sessions_from_cloudtrail(aws.client("cloudtrail"), start, end)
    types = sorted({t for s in sessions for t in s["types"]})

    def estimate() -> dict:
        pricing = boto3.client("pricing", region_name="us-east-1")  # the Pricing API only exists there
        prices = {t: sources.ec2_hourly_price(pricing, t, aws.region()) for t in types}
        return sources.estimate_session_cost(sessions, prices)

    ce = boto3.client("ce", region_name="us-east-1")
    return {"sessions": [{**s, "start": s["start"].isoformat(), "end": s["end"].isoformat()} for s in sessions],
            "actual": _guarded(sources.actual_cost, ce, start, end), "estimate": _guarded(estimate)}


def load_deployments(prefix: str) -> list[dict]:
    """releases/<sha>/deployment.json written by the rules workflow (commit_time, deployed_at)."""
    from siemsoar import aws
    account = aws.client("sts").get_caller_identity()["Account"]
    bucket, out = f"{prefix}-rules-{account}", []
    pages = aws.client("s3").get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="releases/")
    for page in pages:
        for o in page.get("Contents", []):
            if o["Key"].endswith("/deployment.json"):
                out.append(json.loads(aws.client("s3").get_object(Bucket=bucket, Key=o["Key"])["Body"].read()))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", default="siemsoar")
    ap.add_argument("--out", default="reports")
    ap.add_argument("--days", type=int, default=30, help="how far back CloudTrail/Cost Explorer are queried (max 90)")
    ap.add_argument("--offline", nargs=2, metavar=("CASES_JSON", "RUNS_JSON"))
    ap.add_argument("--since", help="only cases/runs from this ISO time on (start of a measurement period)")
    args = ap.parse_args(argv)

    from tools import rulesctl
    deployments: list[dict] = []
    cost: dict | None = None
    baseline: list[dict] = []
    if args.offline:
        cases, runs = (json.loads(Path(p).read_text(encoding="utf-8")) for p in args.offline)
    else:
        import os
        os.environ.setdefault("NAME_PREFIX", args.prefix)
        os.environ.setdefault("CASES_TABLE", f"{args.prefix}-cases")
        from siemsoar import aws
        from siemsoar.store import CaseStore

        from evaluation import sources
        store = CaseStore()
        cases, runs = store.list_cases(), store.list_runs()
        try:
            deployments = load_deployments(args.prefix)
        except Exception as err:  # noqa: BLE001
            print(f"warning: could not read deployments: {err}", file=sys.stderr)
        try:
            cost = collect_cost(args.days)
        except Exception as err:  # noqa: BLE001
            cost = {"available": False, "note": f"AWS cost sources unavailable: {type(err).__name__}: {err}"}
        end = datetime.now(UTC)  # the baseline is measured from CloudTrail, never typed in
        measured = _guarded(lambda: {"rows": sources.baseline_from_cloudtrail(
            aws.client("cloudtrail"), aws.client("guardduty"), end - timedelta(days=args.days), end)})
        if "error" in measured:
            print(f"warning: baseline from CloudTrail unavailable: {measured['error']}", file=sys.stderr)
        baseline = measured.get("rows", [])
    cases, runs = in_scope(cases, runs, args.since)
    m = compute_metrics(cases, runs, rulesctl.load_metadata(), baseline, deployments, cost)
    m["scope"]["since"] = args.since
    out = Path(args.out) / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(m, indent=2, default=str), encoding="utf-8")
    (out / "metrics.md").write_text(render_markdown(m), encoding="utf-8")
    print(f"wrote {out}/metrics.json and metrics.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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
UNKNOWN_PLAN = "unknown"


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
                # Not a case-layer TP or FN either way: no case was due. Counting shadow_missed as FN while shadow_ok is
                # never a TP showed recall 0.0 for rules that fired in most runs (report 2026-10-30, 100100/100102).
                # The miss is a detection-layer FN, scored in detection_quality.
                if observed is True:
                    b["shadow_ok"] += 1
                elif observed is False:
                    b["shadow_missed"] += 1  # the rule never alerted, not even in shadow
                else:
                    b["shadow_unverified"] += 1  # nobody checked the SIEM: cannot call this a pass
    for b in rules.values():
        fp = b["fp"] + b["human_fp"] + b["shadow_violation"]
        b["precision"] = round(b["tp"] / (b["tp"] + fp), 3) if b["tp"] + fp else None
        b["recall"] = round(b["tp"] / (b["tp"] + b["fn"]), 3) if b["tp"] + b["fn"] else None
        _with_intervals(b, ("fp", "human_fp", "shadow_violation"))
    canary["pipeline_ok"] = (canary["observed"] >= canary["expected"]) if canary["expected"] else None
    return {"rules": rules, "labels": labels, "canary": canary, "invalid_runs": sorted(invalid)}


def _binom_cdf(k: int, n: int, p: float) -> float:
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1))


def clopper_pearson(k: int, n: int, confidence: float = 0.95) -> tuple[float, float] | None:
    """Exact (Clopper-Pearson) confidence interval of a proportion k/n: the bounds solve
    P(X >= k | p_lo) = alpha/2 and P(X <= k | p_hi) = alpha/2 (Clopper & Pearson, Biometrika 26, 1934). Solved by
    bisection on the binomial CDF, so no statistics package is needed. With k = n the lower bound is (alpha/2)^(1/n):
    5/5 detections only show a rate >= 0.478 at 95 %."""
    if n <= 0 or not 0 <= k <= n:
        return None
    alpha = 1 - confidence

    def solve(f, lo=0.0, hi=1.0):
        for _ in range(80):
            mid = (lo + hi) / 2
            lo, hi = (mid, hi) if f(mid) else (lo, mid)
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else solve(lambda p: 1 - _binom_cdf(k - 1, n, p) < alpha / 2)
    upper = 1.0 if k == n else solve(lambda p: _binom_cdf(k, n, p) > alpha / 2)
    return round(lower, 3), round(upper, 3)


def _with_intervals(b: dict, fp_key: str = "fp") -> dict:
    fp = b[fp_key] if isinstance(fp_key, str) else sum(b[k] for k in fp_key)
    b["recall_ci95"] = clopper_pearson(b["tp"], b["tp"] + b["fn"])
    b["precision_ci95"] = clopper_pearson(b["tp"], b["tp"] + fp)
    return b


_RELEASE_FILES: dict[str, set[str] | None] = {}


def release_metadata(sha: str) -> set[str] | None:
    """Metadata file names (`wazuh-100140.yml`) present in the rule release `sha`, read from the git history; None when
    the commit is not available (shallow clone, other repository)."""
    if sha not in _RELEASE_FILES:
        import subprocess
        try:
            out = subprocess.run(["git", "ls-tree", "--name-only", sha, "rules/metadata/"], cwd=ROOT,
                                 capture_output=True, text=True, check=True, timeout=30).stdout
            _RELEASE_FILES[sha] = {Path(line).name for line in out.splitlines() if line.strip()}
        except (OSError, subprocess.SubprocessError):
            _RELEASE_FILES[sha] = None
    return _RELEASE_FILES[sha]


def rule_was_deployed(meta_key: str, meta: dict, run: dict, releases=release_metadata) -> bool:
    """Could this rule have fired during `run`? Yes if its metadata is in the rule release the run recorded. Runs
    recorded before releases were tracked fall back to the rule's `created` date: a rule created after the run did
    not exist on the lab. A benign run is a false-positive opportunity only for the rules deployed at the time."""
    files = releases(run["rules_release"]) if run.get("rules_release") else None
    if files is not None:
        return f"{meta_key}.yml" in files
    created, started = str(meta.get("created") or ""), str(run.get("started_at") or "")[:10]
    return bool(created) and bool(started) and created <= started


def detection_quality(runs: list[dict], rules_meta: dict | None = None, releases=release_metadata) -> dict:
    """SIEM-layer TP/FP/FN per rule from `run.siem_alerts`, independent of lifecycle state and of the case pipeline.

    Runs that were not observed (no `siem_alerts`), failed, or are pipeline-only are not scored but counted.
    Precision needs false-positive opportunities: `benign_runs` per rule counts the observed benign runs during which
    the rule was deployed. With none, precision is not measured (None), not 1.0 (lab 2026-10-20: rules deployed an
    hour earlier showed precision 1.0 with no benign run behind it).
    """
    rules_meta = rules_meta or {}
    states = {str(m.get("wazuh_rule_id") or m.get("rule_id")): m.get("state") for m in rules_meta.values()}
    keys = {str(m.get("wazuh_rule_id") or m.get("rule_id")): (k, m) for k, m in rules_meta.items()}
    rules: dict[str, dict] = {}
    unobserved = 0

    def bucket(rule_id: str) -> dict:
        return rules.setdefault(rule_id, {"state": states.get(rule_id), "tp": 0, "fp": 0, "fn": 0, "unplanned": 0,
                                          "benign_runs": 0})

    benign_runs = 0
    # alerts a benign run declares as its correct outcome (not false_positive): an exception rule taking the benign
    # activity (100112 service account, 100146 package manager). Neither TP nor FP, but the evidence that it works.
    benign_expected: dict[str, int] = {}
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
            for r in alerted & listed:
                benign_expected[r] = benign_expected.get(r, 0) + 1
            for rid, (key, meta) in keys.items():
                if rid in alerted or rule_was_deployed(key, meta, run, releases):
                    bucket(rid)["benign_runs"] += 1
    for b in rules.values():
        measured = b["benign_runs"] > 0 and b["tp"] + b["fp"] > 0
        b["precision"] = round(b["tp"] / (b["tp"] + b["fp"]), 3) if measured else None
        b["recall"] = round(b["tp"] / (b["tp"] + b["fn"]), 3) if b["tp"] + b["fn"] else None
        _with_intervals(b)
        if not measured:
            b["precision_ci95"] = None
    return {"rules": {r: b for r, b in rules.items() if b["tp"] + b["fp"] + b["fn"] + b["unplanned"]},
            "benign_runs": benign_runs, "unobserved_runs": unobserved,
            "benign_expected": dict(sorted(benign_expected.items()))}


def credits_technique(case: dict, runs: list[dict], labels: dict) -> bool:
    """A TP case counts as detecting its run's technique only when the run expected that rule as its detection, not as
    an `optional` side effect (host-reactivate-account: the account its set-up creates also fires 100110)."""
    if labels.get(case["case_id"]) != "tp":
        return False
    _, exp = attribute(case, runs)
    return exp is not None and not exp.get("optional")


def variant_coverage(runs: list[dict], cases: list[dict], labels: dict, scenarios: dict, art_index: dict) -> dict:
    """Per technique: the public Atomic Red Team tests the pinned Linux index lists, how many distinct tests the lab
    ran (valid malicious runs), and how many of those were detected (an expected rule alerted, or a TP case). It shows
    how much of the public procedure space behind each claim was tried; a test run in observation (no rule expected
    yet) counts as run, not detected. The index includes tests whose name says FreeBSD; they are counted, not hidden."""
    guid_of = {sid: (s.get("atomic") or {}).get("test_guid") for sid, s in scenarios.items()}
    tests = (art_index or {}).get("tests", {})
    per: dict[str, dict] = {}
    detected_cases = {c["case_id"] for c in cases if credits_technique(c, runs, labels)}
    for r in runs:
        guid = guid_of.get(r.get("scenario"))
        if not guid or guid not in tests or not r.get("malicious") or execution_failed(r):
            continue
        tp_case = any(case_in_run(c, r) for c in cases if c["case_id"] in detected_cases)
        if "siem_alerts" not in r and not tp_case:
            continue  # never observed (e.g. the runner stopped during the wait): neither detected nor missed
        tech = tests[guid]["technique"]
        row = per.setdefault(tech, {"in_index": sum(1 for t in tests.values() if t["technique"] == tech),
                                    "run": set(), "detected": set()})
        row["run"].add(guid)
        required = {str(e["rule_id"]) for e in r.get("expect", []) if not e.get("optional")}
        alerted = {str(a["rule_id"]) for a in r.get("siem_alerts", [])}
        if (required & alerted) or tp_case:
            row["detected"].add(guid)
    out = {t: {"in_index": v["in_index"], "run": len(v["run"]), "detected": len(v["detected"])}
           for t, v in sorted(per.items())}
    techniques_in_index = len({t["technique"] for t in tests.values()})
    return {"techniques": out, "index_tests": len(tests), "index_techniques": techniques_in_index,
            "index_ref": (art_index or {}).get("ref")}


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
        if credits_technique(c, runs, labels):
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


def baseline_comparison(baseline: list[dict], soar_activity_to_contained: dict[str, dict],
                        soar_steps: dict[str, list[int]] | None = None) -> dict:
    """Manual response vs SOAR, on the same interval: from the activity the detector saw (baseline: the occurrence of
    the GuardDuty finding; SOAR: the case's activity_time, the same clock as schema.normalize_guardduty) to containment.
    Both include the detector's own delay and the human reaction time (noticing + deciding); the SOAR number is NOT the
    approval-to-containment time, which would compare an automated step with a whole manual response, nor the
    case-to-containment time, whose clock starts after the detector's delay.

    Like with like: both sides are grouped by response plan (`plan` of a drill row, `response_plan.type` of a case).
    Disabling a key in the IAM console and isolating an instance are different responses, so a plan is compared only
    when both sides measured it; a side without data is reported as such, never filled in."""
    base: dict[str, dict[str, list[float]]] = {}
    for r in baseline:
        if r.get("seconds_to_contain") in (None, ""):
            continue
        row = base.setdefault(r.get("plan") or UNKNOWN_PLAN, {"secs": [], "steps": []})
        row["secs"].append(_nonnegative_float(r["seconds_to_contain"], "seconds_to_contain"))
        if r.get("manual_steps") not in (None, ""):
            row["steps"].append(_nonnegative_float(r["manual_steps"], "manual_steps"))
    if not base:
        return {"available": False, "drills": 0,
                "note": "no manual containment measured yet: needs console drills (docs/evaluation.md, Baseline)"}
    by_plan = {}
    for plan in sorted(set(base) | {p for p, s in soar_activity_to_contained.items() if s.get("n")}):
        b = base.get(plan, {"secs": [], "steps": []})
        soar, steps = soar_activity_to_contained.get(plan) or {}, (soar_steps or {}).get(plan) or []
        base_p50, soar_p50 = percentile(b["secs"], 50), soar.get("p50")
        # `unknown` on both sides would pair two unrelated populations
        comparable = plan != UNKNOWN_PLAN and base_p50 is not None and soar_p50 is not None
        by_plan[plan] = {"drills": len(b["secs"]), "baseline_contain_p50_s": base_p50,
                         "soar_cases": soar.get("n", 0), "soar_activity_to_contained_p50_s": soar_p50,
                         "baseline_manual_steps_mean": round(statistics.fmean(b["steps"]), 1) if b["steps"] else None,
                         "soar_manual_steps": round(statistics.fmean(steps), 1) if steps else None,
                         "comparable": comparable,
                         "contain_time_delta_s": round(base_p50 - soar_p50, 2) if comparable else None}
    return {"available": True, "drills": sum(len(b["secs"]) for b in base.values()), "by_plan": by_plan,
            "note": "both from the activity the detector saw to containment, detector delay and human reaction "
                    "included; compared per response plan"}


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


def deployments_in_scope(deployments: list[dict], since: str | None) -> list[dict]:
    """Rule releases deployed at or after `since`, the same measurement period as the cases and runs."""
    if not since:
        return deployments
    start = parse_iso(since)
    if start is None:
        raise ValueError(f"--since must be an ISO timestamp, got {since!r}")
    return [d for d in deployments if (t := parse_iso(d.get("deployed_at"))) and t >= start]


def deployment_outcome(d: dict) -> str:
    """tools/release.py writes deployment.json for every publish: also when the lab was off (every target
    `skipped_lab_off`, or no target with --no-deploy) and when a host rejected the release (`failed`). Only `deployed`
    (at least one target really took it) measures commit -> active on the lab; one with another target failed is
    counted there too and reported apart (rule_releases.partial_failure)."""
    statuses = {t.get("status") for t in d.get("targets") or []}
    if "deployed" in statuses:
        return "deployed"
    return "failed" if "failed" in statuses else "lab_off"


def activity_time(case: dict) -> datetime | None:
    """When the activity behind this case happened. GuardDuty: the one that triggered this delivery (eventLastSeen,
    kept in `extra.last_seen`); cases stored before the schema used it carry the first occurrence as event_time, hours
    early for a recurring finding."""
    last = parse_iso((case.get("extra") or {}).get("last_seen")) if case["source"] == "guardduty" else None
    return last or parse_iso(case.get("event_time"))


def plan_of(case: dict) -> str:
    return (case.get("response_plan") or {}).get("type") or UNKNOWN_PLAN


def dry_run(case: dict) -> bool:
    """True when the case's response ran in dry-run: nothing changed in AWS, yet verify reports the containment as
    done (contain._verify accepts dry). Read from `dry_run` on the case when it has one; otherwise from its audit
    details (preflight_ok, status:ISOLATED, status:RESTORED), in `case["audit"]` as tools/export_evidence writes it and
    main() loads it."""
    if case.get("dry_run") is not None:
        return bool(case["dry_run"])
    return any((a.get("detail") or {}).get("dry_run") is True for a in case.get("audit") or [])


RESPONSE_TIMES = ("containment_seconds", "evidence_seconds", "restore_seconds", "isolated_at")


def harness_outcome(run: dict, cases: list[dict]) -> dict | None:
    """For a robustness run whose harness raised: the case the run decided (actor `sim:<run_id>`), if any. With one,
    the system did execute (e.g. robust-mid-failure 2026-10-18, run 851a: the case reached FAILED with the host left
    contained, then the harness's own recovery step failed), which is not the same as a run that never started."""
    case = next((c for c in cases if str(c.get("approver") or "") == f"sim:{run['run_id']}"), None)
    if case is None:
        return None
    return {"case_id": case["case_id"], "status": case.get("status"), "safe_state": case.get("safe_state")}


def failed_cases(cases: list[dict], runs: list[dict]) -> list[dict]:
    """Every case that ended FAILED, with its cause, so a count in the report is never read without one: a fault the
    robustness harness injected on purpose (approver sim:<robustness run>, InjectedFault) is not an operational
    failure. The resource is not listed (an IAM resource id holds the access key id)."""
    kinds = {r["run_id"]: r.get("kind") for r in runs}
    out = []
    for c in sorted((c for c in cases if c.get("status") == "FAILED"), key=lambda c: c["case_id"]):
        actor = str(c.get("approver") or "")
        run_id = actor[4:] if actor.startswith("sim:") else None
        injected = c.get("failure_error") == "InjectedFault"
        origin = ("robustness" if kinds.get(run_id) == "robustness" or injected else
                  "simulation" if run_id else "operational")
        out.append({"case_id": c["case_id"], "source": c.get("source"), "rule_id": c.get("rule_id"),
                    "error": c.get("failure_error"), "origin": origin, "run": run_id,
                    "safe_state": c.get("safe_state"), "manual_recovery_at": c.get("manual_recovery_at")})
    return out


def compute_metrics(cases: list[dict], runs: list[dict], rules_meta: dict | None = None,
                    baseline: list[dict] | None = None, deployments: list[dict] | None = None,
                    cost: dict | None = None, scenarios: dict | None = None, art_index: dict | None = None) -> dict:
    rules_meta = rules_meta or {}
    cls = classify(cases, runs, frozenset(str(m["rule_id"]) for m in rules_meta.values() if m.get("canary")))
    excluded = {"pipeline_only", "sample", "invalid_run"}
    measured_cases = [c for c in cases if cls["labels"].get(c["case_id"]) not in excluded]
    pipeline: dict[str, list[float]] = {}
    e2e: dict[str, list[float]] = {}
    for c in measured_cases:
        ev, cr = activity_time(c), parse_iso(c.get("created_at"))
        if ev and cr:
            pipeline.setdefault(c["source"], []).append(max(0.0, (cr - ev).total_seconds()))
        run, exp = attribute(c, runs)
        if run and exp and cr:
            e2e.setdefault(c["source"], []).append(max(0.0, (cr - parse_iso(run["started_at"])).total_seconds()))
    total_alerts = sum(int(c.get("alert_count", 1)) for c in measured_cases)
    # response times are measured on real responses only: a dry run changes nothing in AWS but verify passes it
    dry = [c for c in cases if dry_run(c) and any(c.get(k) is not None for k in RESPONSE_TIMES)]
    live = [c for c in cases if not dry_run(c)]
    plans = sorted({plan_of(c) for c in live if c.get("containment_seconds") is not None or c.get("isolated_at")})
    containment = summary([c["containment_seconds"] for c in live if c.get("containment_seconds") is not None])
    # `decided_by_assistant`: set by hand in DynamoDB on the case an AI assistant approved through the CLI before the
    # CLI required a human approver (commit 25af333). Its approval wait is not a human's, so it is left out (and named
    # in the report) wherever the approval is part of the interval.
    by_assistant = [c for c in live if c.get("isolated_at") and c.get("decided_by_assistant")]
    contained = [c for c in live if c.get("isolated_at") and not c.get("decided_by_assistant")]

    def to_contained(group: list[dict], start=lambda c: parse_iso(c.get("created_at"))) -> dict:
        return summary([round((parse_iso(c["isolated_at"]) - start(c)).total_seconds(), 2) for c in group if start(c)])
    case_to_contained = to_contained(contained)
    case_to_contained_by_plan = {p: to_contained([c for c in contained if plan_of(c) == p]) for p in plans}
    approval_wait = summary([round((parse_iso(c["approved_at"]) - parse_iso(c["notified_at"])).total_seconds(), 2)
                             for c in contained if parse_iso(c.get("approved_at")) and parse_iso(c.get("notified_at"))])
    robustness = [r for r in runs if r.get("kind") == "robustness"]
    outcomes = {r["run_id"]: harness_outcome(r, cases) for r in robustness if execution_failed(r)}
    deployments = deployments or []
    released = {k: sum(1 for d in deployments if deployment_outcome(d) == k) for k in ("deployed", "lab_off", "failed")}
    released["partial_failure"] = sum(1 for d in deployments if deployment_outcome(d) == "deployed"
                                      and any(t.get("status") == "failed" for t in d.get("targets") or []))
    lead = []
    for d in deployments:
        a, b = parse_iso(d.get("commit_time")), parse_iso(d.get("deployed_at"))
        if a and b and deployment_outcome(d) == "deployed":
            lead.append((b - a).total_seconds())
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {"rules_releases": sorted({r["rules_release"] for r in runs if r.get("rules_release")}),
                  "first_run": min((r["started_at"] for r in runs if r.get("started_at")), default=None)},
        "counts": {"cases": len(cases), "measured_cases": len(measured_cases),
                   "excluded_cases": len(cases) - len(measured_cases),
                   "excluded_by_reason": {k: sum(1 for c in cases if cls["labels"].get(c["case_id"]) == k)
                                          for k in sorted(excluded)
                                          if any(cls["labels"].get(c["case_id"]) == k for c in cases)},
                   "invalid_runs": cls["invalid_runs"], "alerts": total_alerts, "runs": len(runs),
                   "by_status": {s: sum(1 for c in cases if c["status"] == s) for s in sorted({c["status"] for c in cases})}},
        "detection_latency_by_source_s": {"alert_to_case": {k: summary(v) for k, v in pipeline.items()},
                                          "run_start_to_case": {k: summary(v) for k, v in e2e.items()}},
        "response_exclusions": {"dry_run": sorted(c["case_id"] for c in dry),
                                "decided_by_assistant": sorted(c["case_id"] for c in by_assistant)},
        "time_to_containment_s": containment,
        "time_to_containment_by_plan_s": {p: summary([c["containment_seconds"] for c in live if plan_of(c) == p
                                                      and c.get("containment_seconds") is not None]) for p in plans},
        "approval_wait_s": approval_wait,
        "case_to_containment_s": case_to_contained,
        "case_to_containment_by_plan_s": case_to_contained_by_plan,
        "time_to_evidence_preservation_s": summary([c["evidence_seconds"] for c in live
                                                    if c.get("evidence_seconds") is not None]),
        "time_to_restore_s": summary([c["restore_seconds"] for c in live if c.get("restore_seconds") is not None]),
        "rule_quality": cls["rules"],
        "detection_quality": detection_quality(runs, rules_meta),
        "pipeline_canary": cls["canary"],
        "attack_coverage": attack_coverage(rules_meta, runs, cls["labels"], cases),
        "variant_coverage": variant_coverage(runs, cases, cls["labels"], scenarios or {}, art_index or {}),
        # same population on both sides: excluded cases (samples, failed runs) have their alerts excluded too
        "alert_duplication_reduction": {
            "alerts": total_alerts, "cases": len(measured_cases),
            "reduction": round(1 - len(measured_cases) / total_alerts, 3) if total_alerts else None},
        "rule_deployment_lead_time_s": summary(lead),
        "rule_releases": released,
        "window_headroom": window_headroom(cases, runs),
        "failed_cases": failed_cases(cases, runs),
        # a run whose harness raised is not scored. It either tested nothing (its own setup error), or the system did
        # run and only the harness failed afterwards: `system_outcome` (the case it decided) tells the two apart.
        "robustness": {"runs": sum(1 for r in robustness if not execution_failed(r)),
                       "passed": sum(1 for r in robustness if r.get("result", {}).get("pass")),
                       "not_executed": sum(1 for o in outcomes.values() if o is None),
                       "harness_failed": sum(1 for o in outcomes.values() if o is not None),
                       "detail": [{"run": r["run_id"], "scenario": r["scenario"], "pass": r.get("result", {}).get("pass"),
                                   "executed": not execution_failed(r), "system_outcome": outcomes.get(r["run_id"]),
                                   "checks": r.get("result", {}).get("checks", [])} for r in robustness]},
        "operating_cost": cost or {"available": False, "note": "no cost data: run without --offline so that "
                                   "CloudTrail, the Pricing API and Cost Explorer can be queried"},
        "baseline_comparison": baseline_comparison(
            baseline or [], {p: to_contained([c for c in contained if plan_of(c) == p], activity_time) for p in plans},
            {p: [manual_steps(c) for c in contained if plan_of(c) == p] for p in plans}),
    }


def _rate(value: float | None, ci: tuple | list | None) -> str:
    """0.8 [0.284–0.995]: the observed rate with its exact 95 % interval, so a 1/1 is not read as a certainty."""
    if value is None:
        return "n/a"
    return f"{value} [{ci[0]}–{ci[1]}]" if ci else str(value)


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
        still_open = [x for x in sessions if x.get("open")]
        # an open session is cut at the report time: the lab may still be up, or its stop (manual or the auto-stop
        # schedule) is not in CloudTrail yet, so its hours are a lower bound
        lines.append(f"- Phiên lab (CloudTrail): {len(sessions)}; tổng {round(sum(x['hours'] for x in sessions), 2)} giờ"
                     + (f" (tối thiểu: {len(still_open)} phiên còn mở, chỉ tính đến lúc sinh báo cáo "
                        f"{', '.join(str(x.get('end', '?'))[:19] for x in still_open)})" if still_open else ""))
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


EXCLUDED_LABELS = {"sample": "mẫu GuardDuty", "invalid_run": "thuộc lượt mô phỏng lỗi",
                   "pipeline_only": "lượt chỉ kiểm pipeline"}
PLANS_SHOWN = ("ec2_isolate", "iam_key_disable")  # always listed, so a plan without data shows as n/a, not missing


def _by_plan(per_plan: dict | None) -> str:
    per_plan = per_plan or {}
    return "; ".join(f"{p}: {_fmt(per_plan.get(p))}" for p in sorted(set(PLANS_SHOWN) | set(per_plan)))


def _robustness_verdict(r: dict) -> str:
    if r.get("executed", True):
        harness = [c for c in r.get("checks", []) if c.get("harness") and not c.get("ok")]
        return ("PASS" if r["pass"] else "FAIL") + (
            f" (bước khôi phục của công cụ kiểm thử lỗi: {harness[0].get('detail')})" if harness else "")
    o = r.get("system_outcome")
    if o:
        safe = " và dừng ở trạng thái an toàn" if o["status"] == "FAILED" and o.get("safe_state") else ""
        return (f"hệ thống đã thực thi{safe} (case {o['case_id']} → {o['status']}, {o.get('safe_state') or '-'}); công "
                f"cụ kiểm thử lỗi sau đó nên không chấm PASS/FAIL")
    return "không thực thi (lỗi công cụ)"


def render_markdown(m: dict) -> str:
    scope = m.get("scope") or {}
    n = m["counts"]
    measured = n.get("measured_cases", n["cases"] - n.get("excluded_cases", 0))
    why = ", ".join(f"{k} {EXCLUDED_LABELS.get(r, r)}" for r, k in (n.get("excluded_by_reason") or {}).items())
    L = ["# Báo cáo đánh giá SIEM/SOAR lab", f"_Sinh lúc {m['generated_at']}_", "",
         f"- Phạm vi: các lượt chạy từ {scope.get('since') or scope.get('first_run') or '-'}; bản phát hành rule: "
         f"{', '.join(s[:8] for s in scope.get('rules_releases', [])) or 'không ghi nhận'}",
         f"- Cases: **{n['cases']}** (đo: **{measured}**; loại trừ {n['cases'] - measured}"
         + (f": {why}" if why else "") + f"); alert gộp vào {measured} case đo: **{n['alerts']}**; "
         f"lượt mô phỏng: **{n['runs']}**",
         f"- Trạng thái (mọi case): {json.dumps(n['by_status'])}", "",
         "## Độ trễ phát hiện (Detection latency per source)", "",
         "| Nguồn | alert → case | bắt đầu mô phỏng → case |", "|---|---|---|"]
    lat = m["detection_latency_by_source_s"]
    for s in sorted(set(lat["alert_to_case"]) | set(lat["run_start_to_case"])):
        L.append(f"| {s} | {_fmt(lat['alert_to_case'].get(s))} | {_fmt(lat['run_start_to_case'].get(s))} |")
    ex = m.get("response_exclusions") or {}
    L += ["", "## Thời gian phản ứng", "",
          f"- Time to containment (từ lúc duyệt đến khi xác minh): {_fmt(m['time_to_containment_s'])}",
          f"  - theo kế hoạch phản ứng: {_by_plan(m.get('time_to_containment_by_plan_s'))}",
          f"- Thời gian chờ người duyệt (thông báo → duyệt): {_fmt(m.get('approval_wait_s'))}",
          f"- Từ khi có case đến khi ngăn chặn xong (gồm chờ duyệt): {_fmt(m.get('case_to_containment_s'))}",
          f"  - theo kế hoạch phản ứng: {_by_plan(m.get('case_to_containment_by_plan_s'))}",
          f"- Time to evidence preservation: {_fmt(m['time_to_evidence_preservation_s'])}",
          f"- Time to restore: {_fmt(m['time_to_restore_s'])}",
          f"- Loại khỏi mọi số đo trên: {len(ex.get('dry_run', []))} case dry-run (không thay đổi gì trên AWS nhưng "
          f"bước verify vẫn ghi là đã ngăn chặn): {', '.join(ex.get('dry_run', [])) or '-'}",
          f"- Loại khỏi thời gian chờ duyệt, case → ngăn chặn và số thao tác thủ công của baseline: "
          f"{len(ex.get('decided_by_assistant', []))} case có trường `decided_by_assistant` (gắn tay trong DynamoDB, "
          f"commit 25af333: trợ lý AI duyệt qua CLI, không phải quyết định của người duyệt): "
          f"{', '.join(ex.get('decided_by_assistant', [])) or '-'}",
          "", "## Chất lượng rule (ground truth)", "",
          "Tầng case (SOAR). Rule shadow không được kỳ vọng mở case: recall tầng case là n/a, kết quả của nó nằm ở "
          "cột Shadow và ở tầng phát hiện bên dưới.", "",
          "| Rule | TP | FP | FP (người dismiss) | Vi phạm shadow | FN (phát hiện / pipeline / chưa kiểm) "
          "| Ngoài dự kiến | Shadow (đã alert / không alert / chưa kiểm) | Chưa gán nhãn | Precision | Recall |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for rid, b in sorted(m["rule_quality"].items()):
        prec, rec = _rate(b["precision"], b.get("precision_ci95")), _rate(b["recall"], b.get("recall_ci95"))
        shadow = (b.get("shadow_ok", 0), b.get("shadow_missed", 0), b.get("shadow_unverified", 0))
        if b["recall"] is None and any(shadow):
            rec = "n/a (shadow)"
        tp = f"{b['tp']} ({b['tp_merged']} gộp vào case đang mở)" if b.get("tp_merged") else b["tp"]
        L.append(f"| {rid} | {tp} | {b['fp']} | {b['human_fp']} | {b['shadow_violation']} | {b['fn']} "
                 f"({b['fn_detection']} / {b['fn_pipeline']} / {b['fn_unverified']}) | {b['unplanned']} "
                 f"| {' / '.join(map(str, shadow))} | {b.get('unlabelled', 0)} | {prec} | {rec} |")
    dq = m["detection_quality"]
    L += ["", f"Tầng phát hiện (alert SIEM, mọi trạng thái vòng đời; {dq['benign_runs']} lượt lành tính, "
              f"{dq['unobserved_runs']} lượt chưa quan sát):", "",
          "| Rule | Trạng thái | TP | FP | FN | Ngoài dự kiến | Lượt lành tính (rule đã deploy) | Precision | Recall |",
          "|---|---|---|---|---|---|---|---|---|"]
    for rid, b in sorted(dq["rules"].items()):
        prec, rec = _rate(b["precision"], b.get("precision_ci95")), _rate(b["recall"], b.get("recall_ci95"))
        prec = prec if b["precision"] is not None or not (b["tp"] + b["fp"]) else "chưa đo (0 lượt lành tính)"
        L.append(f"| {rid} | {b['state'] or '?'} | {b['tp']} | {b['fp']} | {b['fn']} | {b['unplanned']} "
                 f"| {b.get('benign_runs', 0)} | {prec} | {rec} |")
    if dq.get("benign_expected"):
        L += ["", "Hoạt động lành tính được rule nhận đúng như kịch bản khai báo (rule ngoại lệ hoặc rule sức khỏe; "
              "không tính TP/FP): "
              + ", ".join(f"{rid} ({n} lượt)" for rid, n in dq["benign_expected"].items())]
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
          f"- Kỹ thuật phát hiện đúng: {', '.join(c['techniques_detected']) or '-'} (coverage {cov})", ""]
    v = m.get("variant_coverage") or {}
    if v.get("techniques"):
        L += ["## Độ phủ thủ tục công khai (Atomic Red Team, chỉ mục Linux đã ghim)", "",
              f"Chỉ mục `{str(v.get('index_ref'))[:8]}`: {v['index_tests']} test, {v['index_techniques']} kỹ thuật. "
              "Bảng chỉ liệt kê kỹ thuật lab đã chạy; test chạy ở chế độ quan sát (chưa có rule) tính là đã chạy, "
              "chưa phát hiện.", "", "| Kỹ thuật | Test trong chỉ mục | Test đã chạy | Test được phát hiện |",
              "|---|---|---|---|"]
        L += [f"| {t} | {r['in_index']} | {r['run']} | {r['detected']} |" for t, r in v["techniques"].items()]
        L += [""]
    L += [
          "Khoảng tin cậy 95% trong ngoặc vuông là khoảng chính xác Clopper–Pearson của tỉ lệ; khoảng rộng nghĩa là "
          "còn ít lượt chạy.", "",
          "## Giảm trùng lặp cảnh báo", "",
          f"- {m['alert_duplication_reduction']['alerts']} alert → {m['alert_duplication_reduction']['cases']} case "
          f"(giảm {m['alert_duplication_reduction']['reduction']}; chỉ các case đo, như dòng Cases ở đầu báo cáo)", "",
          "## Rule deployment lead time", "", f"- {_fmt(m['rule_deployment_lead_time_s'])}"
          + (" (commit → deploy xong; chỉ release đã lên ít nhất một host; không tính "
             f"{m['rule_releases']['lab_off']} release phát hành khi lab tắt, {m['rule_releases']['failed']} release "
             "deploy lỗi trên mọi host"
             + (f"; đã tính {m['rule_releases']['partial_failure']} release lỗi trên một host"
                if m["rule_releases"].get("partial_failure") else "")
             + ")" if m.get("rule_releases") else ""), "",
          "## Cửa sổ chờ của kịch bản (kiểm chứng bằng số đo)", "",
          "| Kịch bản | Lượt | Phát hiện muộn nhất sau khi chạy xong | Cửa sổ | Đánh giá |", "|---|---|---|---|---|"]
    for sid, w in sorted((m.get("window_headroom") or {}).items()):
        verdict = ("không cắt (target riêng của lượt)" if not w["cut_off"] else
                   "SÁT: nới cửa sổ" if w["tight"] else "đủ dư" if w["max_lag_s"] is not None else "chưa có phát hiện")
        L.append(f"| {sid} | {w['runs']} | {w['max_lag_s'] if w['max_lag_s'] is not None else '-'} s | "
                 f"{w['settle_s']} s | {verdict} |")
    rb = m["robustness"]
    L += ["",
          "## Robustness", "", f"- Đạt {rb['passed']}/{rb['runs']} lượt chạy"
          + (f" ({rb.get('not_executed')} lượt không thực thi được do lỗi công cụ, không tính)"
             if rb.get("not_executed") else "")
          + (f" ({rb.get('harness_failed')} lượt hệ thống đã thực thi nhưng công cụ kiểm thử lỗi sau đó, không chấm)"
             if rb.get("harness_failed") else "")]
    for r in rb["detail"]:
        L.append(f"  - {r['scenario']} ({r['run']}): {_robustness_verdict(r)}")
    failed = m.get("failed_cases") or []
    if failed:
        origin = {"robustness": "lỗi do kiểm thử robustness cố ý tiêm", "simulation": "trong lượt mô phỏng",
                  "operational": "lỗi vận hành thật"}
        L += ["", "## Case FAILED (dừng ở trạng thái an toàn)", ""]
        for f in failed:
            L.append(f"- {f['case_id']} · {f['source']} {f['rule_id']} · {f['error']} · {origin[f['origin']]}"
                     + (f" ({f['run']})" if f["run"] else "") + f" · trạng thái giữ lại: {f['safe_state']}"
                     + f" · khôi phục tay: {f['manual_recovery_at'] or 'không ghi nhận'}")
    L += ["", "## Chi phí vận hành mỗi phiên", ""] + _render_cost(m["operating_cost"]) + [
        "", "## So sánh baseline (GuardDuty email + cách ly thủ công)", ""]
    b = m["baseline_comparison"]
    if not b["available"]:
        L.append(f"- {b['note']}")
    else:
        L.append(f"- {b['drills']} lượt ngăn chặn thủ công đo từ CloudTrail, so với SOAR (hoạt động → ngăn chặn) theo "
                 f"từng kế hoạch phản ứng. {b['note']}")
        for plan, p in b["by_plan"].items():
            manual = (f"{p['drills']} lượt, p50 {p['baseline_contain_p50_s']}s, {p['baseline_manual_steps_mean']} thao "
                      "tác" if p["drills"] else "chưa có dữ liệu")
            soar = (f"{p['soar_cases']} case, p50 {p['soar_activity_to_contained_p50_s']}s, {p['soar_manual_steps']} "
                    "thao tác" if p["soar_cases"] else "chưa có dữ liệu")
            verdict = (f"chênh p50 {p['contain_time_delta_s']}s" if p["comparable"] else
                       "không so sánh được (không rõ kế hoạch phản ứng)" if plan == UNKNOWN_PLAN else
                       "không so sánh được (một phía chưa có dữ liệu)")
            L.append(f"  - {plan}: thủ công {manual}; SOAR {soar}; {verdict}")
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
        for c in cases:  # dry_run() falls back to the audit when the case carries no dry_run of its own
            if c.get("dry_run") is None and any(c.get(k) is not None for k in RESPONSE_TIMES):
                c["audit"] = store.list_audit(c["case_id"])
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
    deployments = deployments_in_scope(deployments, args.since)
    from simulation import catalog
    from tools import refdata
    m = compute_metrics(cases, runs, rulesctl.load_metadata(), baseline, deployments, cost,
                        catalog.load_scenarios(catalog.SCENARIO_DIR), refdata.load_atomic())
    m["scope"]["since"] = args.since
    out = Path(args.out) / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(m, indent=2, default=str), encoding="utf-8")
    (out / "metrics.md").write_text(render_markdown(m), encoding="utf-8")
    print(f"wrote {out}/metrics.json and metrics.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())

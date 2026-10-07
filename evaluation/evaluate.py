"""Turn stored cases + simulation runs into the proposal's evaluation metrics (chapter 6.2).

  python -m evaluation.evaluate [--prefix siemsoar] [--out reports] [--baseline evaluation/baseline.csv]
                                [--sessions evaluation/sessions.csv] [--offline cases.json runs.json]

compute_metrics() is pure (lists in, dict out) so it is unit tested without AWS.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src" / "lambdas"))

DEFAULT_SETTLE = 300
# Approximate on-demand list prices, ap-southeast-1 (USD). Verify in Cost Explorer; override with --prices file.
PRICES = {"t3.large": 0.1056, "t3.small": 0.0264, "t3.medium": 0.0528, "public_ipv4_per_hour": 0.005,
          "gp3_gb_month": 0.0912, "manager_gb": 50, "sensor_gb": 20}
SOAR_MANUAL_STEPS = 2  # approve containment + restore decision


def _t(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    xs = sorted(values)
    k = (len(xs) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo), 2)


def summary(values: list[float]) -> dict:
    vals = [v for v in values if v is not None]
    return {"n": len(vals), "mean": round(statistics.fmean(vals), 2) if vals else None,
            "p50": percentile(vals, 50), "p95": percentile(vals, 95), "max": round(max(vals), 2) if vals else None}


def attribute(case: dict, runs: list[dict]) -> tuple[dict | None, dict | None]:
    """Return (run, matched expectation). Host runs match by run_id; others by time window + expected rule."""
    by_id = {r["run_id"]: r for r in runs}
    if case.get("run_id") in by_id:
        run = by_id[case["run_id"]]
        exp = next((e for e in run.get("expect", []) if str(e["rule_id"]) == str(case["rule_id"])), None)
        return run, exp
    created = _t(case.get("created_at"))
    for run in sorted(runs, key=lambda r: r["started_at"]):
        start, end = _t(run["started_at"]), _t(run.get("ended_at")) or _t(run["started_at"])
        settle = timedelta(seconds=int(run.get("settle_seconds", DEFAULT_SETTLE)))
        if created and start - timedelta(seconds=5) <= created <= end + settle:
            exp = next((e for e in run.get("expect", [])
                        if str(e["rule_id"]) == str(case["rule_id"]) and e["source"] == case["source"]), None)
            if exp:
                return run, exp
    return None, None


def classify(cases: list[dict], runs: list[dict], canary_rules: frozenset[str] = frozenset()) -> dict:
    """Ground-truth labelling. Returns per-rule counters and per-case labels.

    `canary_rules` (metadata `canary: true`) detect a marker written by the simulation itself, so a hit proves the
    pipeline works but says nothing about detection quality: they are reported separately and never counted as TP/FP/FN.
    """
    rules: dict[str, dict] = {}
    labels: dict[str, str] = {}
    canary = {"rules": sorted(canary_rules), "expected": 0, "observed": 0}

    def bucket(rule_id: str) -> dict:
        return rules.setdefault(rule_id, {"tp": 0, "fp": 0, "fn": 0, "shadow_violation": 0, "shadow_ok": 0,
                                          "human_fp": 0, "unlabelled": 0})

    matched: set[tuple[str, str]] = set()
    for c in cases:
        if str(c["rule_id"]) in canary_rules:
            labels[c["case_id"]] = "canary"
            run, exp = attribute(c, runs)
            if run and exp and (run["run_id"], str(exp["rule_id"])) not in matched:
                matched.add((run["run_id"], str(exp["rule_id"])))
                canary["observed"] += 1
            continue
        b = bucket(str(c["rule_id"]))
        run, exp = attribute(c, runs)
        if run and exp:
            matched.add((run["run_id"], str(exp["rule_id"])))
            if exp.get("case", True) is False:
                b["shadow_violation"] += 1
                labels[c["case_id"]] = "shadow_violation"
            elif run.get("malicious"):
                b["tp"] += 1
                labels[c["case_id"]] = "tp"
            else:
                b["fp"] += 1
                labels[c["case_id"]] = "fp"
        elif c["status"] == "DISMISSED" or c.get("verdict") == "false_positive":
            b["human_fp"] += 1
            labels[c["case_id"]] = "fp_human"
        else:
            b["unlabelled"] += 1
            labels[c["case_id"]] = "unlabelled"
    for run in runs:
        for e in run.get("expect", []):
            if str(e["rule_id"]) in canary_rules:
                canary["expected"] += e.get("case", True) is True
                continue
            if (run["run_id"], str(e["rule_id"])) in matched or e.get("optional"):
                continue
            b = bucket(str(e["rule_id"]))
            if e.get("case", True):
                if run.get("malicious", True):
                    b["fn"] += 1
            else:
                b["shadow_ok"] += 1
    for b in rules.values():
        fp = b["fp"] + b["human_fp"] + b["shadow_violation"]
        b["precision"] = round(b["tp"] / (b["tp"] + fp), 3) if b["tp"] + fp else None
        b["recall"] = round(b["tp"] / (b["tp"] + b["fn"]), 3) if b["tp"] + b["fn"] else None
    canary["pipeline_ok"] = (canary["observed"] >= canary["expected"]) if canary["expected"] else None
    return {"rules": rules, "labels": labels, "canary": canary}


def attack_coverage(rules_meta: dict, runs: list[dict], labels: dict, cases: list[dict]) -> dict:
    live = {t for m in rules_meta.values() if m.get("state") in ("active", "enforce") for t in m.get("mitre", [])}
    exercised = {t for r in runs if r.get("malicious") and not r.get("canary") for t in r.get("techniques", [])}
    detected = set()
    for c in cases:
        if labels.get(c["case_id"]) == "tp":
            run, _ = attribute(c, runs)
            detected |= set((run or {}).get("techniques", [])) & exercised
    return {"techniques_in_active_rules": sorted(live), "techniques_exercised": sorted(exercised),
            "techniques_detected": sorted(detected),
            "coverage_of_exercised": round(len(detected) / len(exercised), 3) if exercised else None}


def estimate_cost(sessions: list[dict], prices: dict | None = None) -> dict:
    p = {**PRICES, **(prices or {})}
    rows, total = [], 0.0
    for s in sessions:
        h = float(s["hours"])
        compute = h * (p.get(s["manager_type"], 0) + p.get(s["sensor_type"], 0))
        network = h * 2 * p["public_ipv4_per_hour"]
        storage = (p["manager_gb"] + p["sensor_gb"]) * p["gp3_gb_month"] * h / 730
        usd = round(compute + network + storage, 3)
        rows.append({"start": s.get("start"), "hours": h, "usd_estimate": usd})
        total += usd
    return {"sessions": rows, "total_usd_estimate": round(total, 2),
            "avg_usd_per_session": round(total / len(rows), 2) if rows else None,
            "note": "estimate from list prices; compare with Cost Explorer (tag Project=siem-soar-lab)"}


def baseline_comparison(baseline: list[dict], containment: dict) -> dict:
    secs = [float(r["seconds_to_contain"]) for r in baseline if r.get("seconds_to_contain")]
    steps = [float(r["manual_steps"]) for r in baseline if r.get("manual_steps")]
    if not secs:
        return {"available": False, "note": "no baseline measurements yet (evaluation/baseline.csv)"}
    base_p50 = percentile(secs, 50)
    soar_p50 = containment.get("p50")
    return {"available": True, "baseline_contain_p50_s": base_p50, "soar_contain_p50_s": soar_p50,
            "baseline_manual_steps_mean": round(statistics.fmean(steps), 1) if steps else None,
            "soar_manual_steps": SOAR_MANUAL_STEPS,
            "contain_time_delta_s": round(base_p50 - soar_p50, 2) if soar_p50 is not None else None,
            "note": "SOAR containment time starts at the human approval; baseline starts at the email. "
                    "Compare it with `seconds_to_notice` + approval latency, not as a pure speed-up."}


def compute_metrics(cases: list[dict], runs: list[dict], rules_meta: dict | None = None,
                    baseline: list[dict] | None = None, deployments: list[dict] | None = None,
                    sessions: list[dict] | None = None) -> dict:
    rules_meta = rules_meta or {}
    cls = classify(cases, runs, frozenset(str(m["rule_id"]) for m in rules_meta.values() if m.get("canary")))
    pipeline: dict[str, list[float]] = {}
    e2e: dict[str, list[float]] = {}
    for c in cases:
        ev, cr = _t(c.get("event_time")), _t(c.get("created_at"))
        if ev and cr:
            pipeline.setdefault(c["source"], []).append(max(0.0, (cr - ev).total_seconds()))
        run, exp = attribute(c, runs)
        if run and exp and cr:
            e2e.setdefault(c["source"], []).append(max(0.0, (cr - _t(run["started_at"])).total_seconds()))
    total_alerts = sum(int(c.get("alert_count", 1)) for c in cases)
    containment = summary([c["containment_seconds"] for c in cases if c.get("containment_seconds") is not None])
    robustness = [r for r in runs if r.get("kind") == "robustness"]
    lead = []
    for d in deployments or []:
        a, b = _t(d.get("commit_time")), _t(d.get("deployed_at"))
        if a and b:
            lead.append((b - a).total_seconds())
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {"cases": len(cases), "alerts": total_alerts, "runs": len(runs),
                   "by_status": {s: sum(1 for c in cases if c["status"] == s) for s in sorted({c["status"] for c in cases})}},
        "detection_latency_by_source_s": {"alert_to_case": {k: summary(v) for k, v in pipeline.items()},
                                          "run_start_to_case": {k: summary(v) for k, v in e2e.items()}},
        "time_to_containment_s": containment,
        "time_to_evidence_preservation_s": summary([c["evidence_seconds"] for c in cases
                                                    if c.get("evidence_seconds") is not None]),
        "time_to_restore_s": summary([c["restore_seconds"] for c in cases if c.get("restore_seconds") is not None]),
        "rule_quality": cls["rules"],
        "pipeline_canary": cls["canary"],
        "attack_coverage": attack_coverage(rules_meta, runs, cls["labels"], cases),
        "alert_duplication_reduction": {
            "alerts": total_alerts, "cases": len(cases),
            "reduction": round(1 - len(cases) / total_alerts, 3) if total_alerts else None},
        "rule_deployment_lead_time_s": summary(lead),
        "robustness": {"runs": len(robustness), "passed": sum(1 for r in robustness if r.get("result", {}).get("pass")),
                       "detail": [{"run": r["run_id"], "scenario": r["scenario"], "pass": r.get("result", {}).get("pass"),
                                   "checks": r.get("result", {}).get("checks", [])} for r in robustness]},
        "operating_cost": estimate_cost(sessions or []),
        "baseline_comparison": baseline_comparison(baseline or [], containment),
    }


def _fmt(s: dict) -> str:
    if not s or not s.get("n"):
        return "n/a"
    return f"n={s['n']} · p50 {s['p50']}s · p95 {s['p95']}s · max {s['max']}s"


def render_markdown(m: dict) -> str:
    L = ["# Báo cáo đánh giá SIEM/SOAR lab", f"_Sinh lúc {m['generated_at']}_", "",
         f"- Cases: **{m['counts']['cases']}**, alerts gộp vào: **{m['counts']['alerts']}**, "
         f"lượt mô phỏng: **{m['counts']['runs']}**",
         f"- Trạng thái: {json.dumps(m['counts']['by_status'])}", "", "## Độ trễ phát hiện (Detection latency per source)", "",
         "| Nguồn | alert → case | bắt đầu mô phỏng → case |", "|---|---|---|"]
    lat = m["detection_latency_by_source_s"]
    for s in sorted(set(lat["alert_to_case"]) | set(lat["run_start_to_case"])):
        L.append(f"| {s} | {_fmt(lat['alert_to_case'].get(s))} | {_fmt(lat['run_start_to_case'].get(s))} |")
    L += ["", "## Thời gian phản ứng", "",
          f"- Time to containment (từ lúc duyệt đến khi xác minh): {_fmt(m['time_to_containment_s'])}",
          f"- Time to evidence preservation: {_fmt(m['time_to_evidence_preservation_s'])}",
          f"- Time to restore: {_fmt(m['time_to_restore_s'])}", "", "## Chất lượng rule (ground truth)", "",
          "| Rule | TP | FP | FP (người dismiss) | Vi phạm shadow | FN | Precision | Recall |",
          "|---|---|---|---|---|---|---|---|"]
    for rid, b in sorted(m["rule_quality"].items()):
        prec = "n/a" if b["precision"] is None else b["precision"]
        rec = "n/a" if b["recall"] is None else b["recall"]
        L.append(f"| {rid} | {b['tp']} | {b['fp']} | {b['human_fp']} | {b['shadow_violation']} | {b['fn']} | {prec} | {rec} |")
    k = m["pipeline_canary"]
    L += ["", "## Canary pipeline (không tính vào chất lượng rule)", "",
          f"- Rule canary: {', '.join(k['rules']) or '-'}; kỳ vọng {k['expected']}, quan sát {k['observed']} "
          f"→ pipeline {'OK' if k['pipeline_ok'] else 'n/a' if k['pipeline_ok'] is None else 'LỖI'}"]
    c = m["attack_coverage"]
    cov = "n/a" if c["coverage_of_exercised"] is None else c["coverage_of_exercised"]
    L += ["", "## Độ phủ ATT&CK", "",
          f"- Kỹ thuật trong rule active/enforce: {', '.join(c['techniques_in_active_rules']) or '-'}",
          f"- Kỹ thuật đã mô phỏng: {', '.join(c['techniques_exercised']) or '-'}",
          f"- Kỹ thuật phát hiện đúng: {', '.join(c['techniques_detected']) or '-'} (coverage {cov})", "",
          "## Giảm trùng lặp cảnh báo", "",
          f"- {m['alert_duplication_reduction']['alerts']} alert → {m['alert_duplication_reduction']['cases']} case "
          f"(giảm {m['alert_duplication_reduction']['reduction']})", "",
          "## Rule deployment lead time", "", f"- {_fmt(m['rule_deployment_lead_time_s'])}", "",
          "## Robustness", "", f"- Đạt {m['robustness']['passed']}/{m['robustness']['runs']} kịch bản"]
    for r in m["robustness"]["detail"]:
        L.append(f"  - {r['scenario']}: {'PASS' if r['pass'] else 'FAIL'}")
    oc = m["operating_cost"]
    L += ["", "## Chi phí vận hành mỗi phiên", "",
          f"- Tổng ước tính: **${oc['total_usd_estimate']}**, trung bình ${oc['avg_usd_per_session']}/phiên. "
          f"_{oc['note']}_", "",
          "## So sánh baseline (GuardDuty email + cách ly thủ công)", ""]
    b = m["baseline_comparison"]
    L.append("- " + (b["note"] if not b["available"] else
                     f"baseline p50 {b['baseline_contain_p50_s']}s vs SOAR p50 {b['soar_contain_p50_s']}s; "
                     f"số thao tác thủ công {b['baseline_manual_steps_mean']} vs {b['soar_manual_steps']}. {b['note']}"))
    L += ["", "## Giới hạn", "", "Xem docs/limitations.md. Số liệu chỉ phản ánh lab một tài khoản với lưu lượng mô phỏng."]
    return "\n".join(L) + "\n"


def _read_csv(path: str | None) -> list[dict]:
    if not path or not Path(path).exists():
        return []
    with open(path, newline="") as fh:
        return list(csv.DictReader(line for line in fh if not line.lstrip().startswith("#")))


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
    ap.add_argument("--baseline", default=str(ROOT / "evaluation" / "baseline.csv"))
    ap.add_argument("--sessions", default=str(ROOT / "evaluation" / "sessions.csv"))
    ap.add_argument("--offline", nargs=2, metavar=("CASES_JSON", "RUNS_JSON"))
    args = ap.parse_args(argv)

    from tools import rulesctl
    deployments: list[dict] = []
    if args.offline:
        cases, runs = (json.loads(Path(p).read_text()) for p in args.offline)
    else:
        import os
        os.environ.setdefault("NAME_PREFIX", args.prefix)
        os.environ.setdefault("CASES_TABLE", f"{args.prefix}-cases")
        from siemsoar.store import CaseStore
        store = CaseStore()
        cases, runs = store.list_cases(), store.list_runs()
        try:
            deployments = load_deployments(args.prefix)
        except Exception as err:  # noqa: BLE001
            print(f"warning: could not read deployments: {err}", file=sys.stderr)
    m = compute_metrics(cases, runs, rulesctl.load_metadata(), _read_csv(args.baseline), deployments,
                        _read_csv(args.sessions))
    out = Path(args.out) / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(m, indent=2, default=str))
    (out / "metrics.md").write_text(render_markdown(m))
    print(f"wrote {out}/metrics.json and metrics.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())

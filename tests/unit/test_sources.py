"""Evaluation inputs read from AWS. The AWS clients are replaced by stubs that return CloudTrail / Pricing / Cost
Explorer / GuardDuty documents shaped as AWS documents them (the stubs are test doubles, not measurements)."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from evaluation import sources as src


def t(hour, minute=0):
    return datetime(2026, 10, 6, hour, minute, tzinfo=UTC)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def run_event(when, iids_types, lab=True):
    tags = [{"key": "siemsoar:plane", "value": "ondemand"}] if lab else [{"key": "Name", "value": "other"}]
    return {"eventTime": iso(when), "eventName": "RunInstances",
            "requestParameters": {"instanceType": iids_types[0][1],
                                  "tagSpecificationSet": {"items": [{"resourceType": "instance", "tags": tags}]}},
            "responseElements": {"instancesSet": {"items": [{"instanceId": i} for i, _ in iids_types]}}}


def power_event(when, name, *iids):
    return {"eventTime": iso(when), "eventName": name,
            "requestParameters": {"instancesSet": {"items": [{"instanceId": i} for i in iids]}}}


# ------------------------------------------------------------------ sessions
def test_a_session_still_running_is_reported_up_to_now():
    run = [{"eventTime": "2026-10-17T16:30:00Z", "responseElements": {"instancesSet": {"items": [
        {"instanceId": "i-1"}]}}, "requestParameters": {"instanceType": "t3.small", "tagSpecificationSet": {"items": [
            {"resourceType": "instance", "tags": [{"key": "siemsoar:plane", "value": "ondemand"}]}]}}}]
    s = src.build_sessions(run, [], [], now=datetime(2026, 10, 17, 18, 30, tzinfo=UTC))
    assert len(s) == 1 and s[0]["open"] and s[0]["hours"] == 2.0
    assert src.build_sessions(run, [], []) == []  # without `now` an open session has no end


def test_sessions_are_wall_clock_from_first_start_to_last_stop_of_the_lab_instances():
    runs = [run_event(t(9), [("i-mgr", "t3.large")]), run_event(t(9), [("i-sen", "t3.small")]),
            run_event(t(9), [("i-other", "m5.large")], lab=False)]
    starts = [power_event(t(14), "StartInstances", "i-mgr", "i-sen")]
    stops = [power_event(t(11), "StopInstances", "i-mgr", "i-sen", "i-other"), power_event(t(18), "StopInstances", "i-sen"),
             power_event(t(18, 30), "StopInstances", "i-mgr")]
    sessions = src.build_sessions(runs, starts, stops)
    assert [(s["start"], s["end"], s["hours"]) for s in sessions] == [(t(9), t(11), 2.0), (t(14), t(18, 30), 4.5)]
    assert sessions[0]["types"] == ["t3.large", "t3.small"]  # the untagged m5.large is not part of the lab


def test_a_resized_instance_is_priced_with_the_type_it_had_in_each_session():
    """Terraform resizes a stopped instance in place (ModifyInstanceAttribute, no new RunInstances): sessions after the
    resize use the new type; two instances of one type count twice."""
    runs = [run_event(t(9), [("i-mgr", "t3.large")]), run_event(t(9), [("i-sen", "t3.large")])]
    resize = {"eventTime": iso(t(12)), "eventName": "ModifyInstanceAttribute",
              "requestParameters": {"instanceId": "i-mgr", "instanceType": {"value": "t3a.xlarge"}}}
    starts = [power_event(t(14), "StartInstances", "i-mgr", "i-sen")]
    stops = [power_event(t(11), "StopInstances", "i-mgr", "i-sen"), power_event(t(16), "StopInstances", "i-mgr", "i-sen")]
    before, after = src.build_sessions(runs, starts, stops, modify_events=[resize])
    assert before["types"] == ["t3.large", "t3.large"] and after["types"] == ["t3.large", "t3a.xlarge"]
    est = src.estimate_session_cost([before, after], {"t3.large": 0.0832, "t3a.xlarge": 0.1504})
    assert est["sessions"][0]["usd_compute_estimate"] == round(2 * 2 * 0.0832, 3)
    assert est["sessions"][1]["usd_compute_estimate"] == round(2 * (0.0832 + 0.1504), 3)


def test_a_session_still_running_is_not_reported_as_finished():
    assert src.build_sessions([run_event(t(9), [("i-a", "t3.large")])], [], []) == []


class FakeCloudTrail:
    def __init__(self, by_name):
        self.by_name, self.calls = by_name, []

    def get_paginator(self, name):
        assert name == "lookup_events"
        outer = self

        class P:
            def paginate(self, LookupAttributes, StartTime, EndTime):  # noqa: N803 (boto3 spelling)
                value = LookupAttributes[0]["AttributeValue"]
                outer.calls.append(value)
                # CloudTrail returns the record as a JSON string
                yield {"Events": [{"CloudTrailEvent": json.dumps(e)} for e in outer.by_name.get(value, [])]}
        return P()


def test_sessions_from_cloudtrail_unwraps_the_json_records():
    ct = FakeCloudTrail({"RunInstances": [run_event(t(9), [("i-a", "t3.large")])],
                         "StopInstances": [power_event(t(10), "StopInstances", "i-a")]})
    sessions = src.sessions_from_cloudtrail(ct, t(0), t(23))
    assert sessions[0]["hours"] == 1.0
    assert set(ct.calls) == {"RunInstances", "StartInstances", "StopInstances", "ModifyInstanceAttribute"}


# ------------------------------------------------------------------ cost
PRICE_ITEM = {"terms": {"OnDemand": {"X": {"priceDimensions": {"Y": {"unit": "Hrs", "pricePerUnit": {"USD": "0.1056"}}}}}}}


def test_price_parsing_refuses_ambiguity():
    assert src.parse_ec2_price([json.dumps(PRICE_ITEM)]) == 0.1056
    other = {"terms": {"OnDemand": {"X": {"priceDimensions": {"Y": {"unit": "Hrs", "pricePerUnit": {"USD": "0.2"}}}}}}}
    with pytest.raises(ValueError, match="one on-demand hourly price"):
        src.parse_ec2_price([json.dumps(PRICE_ITEM), json.dumps(other)])
    with pytest.raises(ValueError):
        src.parse_ec2_price([])


def test_price_lookup_asks_for_linux_shared_tenancy_in_the_right_location():
    class Pricing:
        def get_products(self, **kw):
            self.kw = kw
            return {"PriceList": [json.dumps(PRICE_ITEM)]}
    pricing = Pricing()
    assert src.ec2_hourly_price(pricing, "t3.large", "ap-southeast-1") == 0.1056
    flt = {f["Field"]: f["Value"] for f in pricing.kw["Filters"]}
    assert flt["location"] == "Asia Pacific (Singapore)" and flt["instanceType"] == "t3.large"
    assert flt["operatingSystem"] == "Linux" and flt["tenancy"] == "Shared"
    with pytest.raises(ValueError):
        src.region_location("mars-1")


def test_cost_estimate_needs_a_price_for_every_type_and_never_invents_one():
    sessions = [{"start": t(9), "end": t(11), "hours": 2.0, "types": ["t3.large", "t3.small"]}]
    est = src.estimate_session_cost(sessions, {"t3.large": 0.1, "t3.small": 0.02})
    assert est["total_usd_compute_estimate"] == 0.24 and est["avg_usd_per_session"] == 0.24
    with pytest.raises(ValueError, match="no price"):
        src.estimate_session_cost(sessions, {"t3.large": 0.1})
    assert "still open" not in est["note"] and est["sessions"][0]["open"] is False
    open_est = src.estimate_session_cost([{**sessions[0], "open": True}], {"t3.large": 0.1, "t3.small": 0.02})
    assert "1 session(s) still open, counted only up to the report time" in open_est["note"]


def test_actual_cost_sums_billed_amounts_by_service_for_the_tag():
    class CE:
        status = "Active"

        activated = "2026-09-01T00:00:00Z"
        empty = False

        def list_cost_allocation_tags(self, TagKeys):
            return {"CostAllocationTags": [{"TagKey": "Project", "Type": "UserDefined", "Status": self.status,
                                            "LastUpdatedDate": self.activated}]}

        def get_cost_and_usage(self, **kw):
            self.kw = kw
            day = lambda ec2, s3: {"Groups": [  # noqa: E731
                {"Keys": ["Amazon Elastic Compute Cloud - Compute"], "Metrics": {"UnblendedCost": {"Amount": ec2}}},
                {"Keys": ["Amazon Simple Storage Service"], "Metrics": {"UnblendedCost": {"Amount": s3}}}]}
            if self.empty:
                return {"ResultsByTime": [{"Groups": []}, {"Groups": []}]}
            return {"ResultsByTime": [day("1.5", "0.01"), day("0.5", "0.02")]}
    ce = CE()
    out = src.actual_cost(ce, t(0), t(0) + timedelta(days=2))
    assert out["total_usd"] == 2.03 and out["by_service_usd"]["Amazon Elastic Compute Cloud - Compute"] == 2.0
    assert ce.kw["Filter"] == {"Tags": {"Key": "Project", "Values": ["siem-soar-lab"]}} and ce.kw["Granularity"] == "DAILY"
    assert "covers_from" in out and "earlier sessions" not in out["note"]
    ce.activated = iso(t(0) + timedelta(hours=12))  # activated inside the period: earlier days are not covered
    assert "earlier sessions are not included" in src.actual_cost(ce, t(0), t(0) + timedelta(days=2))["note"]
    ce.empty = True  # the lab account right after activation (2026-10-19): nothing attributed yet, which is not "$0"
    with pytest.raises(RuntimeError, match="unknown, not \$0"):
        src.actual_cost(ce, t(0), t(0) + timedelta(days=2))
    ce.empty, ce.status = False, "Inactive"  # before activation
    with pytest.raises(RuntimeError, match="unknown, not \$0"):
        src.actual_cost(ce, t(0), t(0) + timedelta(days=2))


# ------------------------------------------------------------------ baseline
def human(when, name, who="arn:aws:iam::1:user/analyst", ro=False, console=True, **params):
    record = {"eventTime": iso(when), "eventName": name, "readOnly": ro, "userIdentity": {"arn": who},
              "requestParameters": params}
    if console:
        record["sessionCredentialFromConsole"] = "true"
    return record


def test_baseline_measures_the_first_human_containment_call_and_counts_the_clicks():
    finding = {"id": "f1", "type": "UnauthorizedAccess:EC2/SSHBruteForce", "first_seen": iso(t(10)),
               "resources": {"i-0abc"}}
    soar = "arn:aws:sts::1:assumed-role/siemsoar-fn-contain/siemsoar-contain"
    events = [
        human(t(10, 2), "DescribeInstances", ro=True, instanceId="i-0abc"),                 # read-only: not a step
        human(t(10, 3), "CreateSecurityGroup", groupName="isolate"),                         # a step
        human(t(10, 6), "ModifyInstanceAttribute", instanceId="i-0abc"),                     # the containment
        human(t(10, 1), "ModifyInstanceAttribute", who=soar, console=False, instanceId="i-0abc"),  # SOAR: never
        human(t(10, 4), "CreateSecurityGroup", console=False, groupName="x"),                # same user, a script
        human(t(10, 7), "ModifyInstanceAttribute", who="arn:aws:iam::1:user/other", instanceId="i-zzz"),
    ]
    [row] = src.baseline_rows([finding], events)
    assert row["seconds_to_contain"] == 360.0 and row["manual_steps"] == 2 and row["scenario"] == finding["type"]
    assert "ModifyInstanceAttribute by arn:aws:iam::1:user/analyst" in row["notes"]


def test_baseline_ignores_findings_nobody_contained_and_actions_outside_the_window():
    finding = {"id": "f", "type": "X", "first_seen": iso(t(10)), "resources": {"i-1"}}
    late = human(t(10) + src.BASELINE_WINDOW + timedelta(minutes=1), "StopInstances", instanceId="i-1")
    early = human(t(9), "StopInstances", instanceId="i-1")
    assert src.baseline_rows([finding], [late, early]) == []
    # the simulation runner deletes the previous victim key with the operator's credentials: an SDK call, not a person
    runner_cleanup = human(t(10, 5), "DeleteAccessKey", console=False, userName="lab-victim", accessKeyId="AKIAX")
    key_finding = {"id": "k", "type": "Stealth:IAMUser/CloudTrailLoggingDisabled", "first_seen": iso(t(10)),
                   "resources": {"lab-victim", "AKIAX"}}
    assert src.baseline_rows([key_finding], [runner_cleanup]) == []
    assert src.from_console({"sessionCredentialFromConsole": "true"}) and not src.from_console({})
    assert src.is_soar_principal({"userIdentity": {"arn": "arn:aws:sts::1:assumed-role/siemsoar-sfn-role/x"}})
    assert not src.is_soar_principal({"userIdentity": {"arn": "arn:aws:iam::1:user/analyst"}})


def test_repeated_drills_aggregated_into_one_recurring_finding_are_timed_from_the_matching_occurrence():
    """GuardDuty folds repeated drills on one key into one finding (Service.Count > 1) and keeps its first
    (eventFirstSeen) and latest (eventLastSeen) activity. Timed from the first only, a drill 8 h later fell outside the
    window and the rest were measured from an older occurrence."""
    finding = {"id": "f", "type": "Stealth:IAMUser/CloudTrailLoggingDisabled", "plan": "iam_key_disable",
               "first_seen": iso(t(8)), "last_seen": iso(t(16)), "resources": {"lab-victim", "key-1"}}
    calls = [human(t(8, 5), "UpdateAccessKey", userName="lab-victim", accessKeyId="key-1"),    # drill 1
             human(t(8, 6), "DeleteAccessKey", userName="lab-victim", accessKeyId="key-1"),    # same drill, 2nd click
             human(t(12, 5), "UpdateAccessKey", userName="lab-victim", accessKeyId="key-1"),   # drill 2: time not kept
             human(t(16, 4), "UpdateAccessKey", userName="lab-victim", accessKeyId="key-1")]   # drill 3 (latest)
    rows = src.baseline_rows([finding], calls)
    assert [(r["seconds_to_contain"], r["plan"]) for r in rows] == [(300.0, "iam_key_disable"),
                                                                    (240.0, "iam_key_disable")]
    assert rows[1]["manual_steps"] == 1  # only the clicks after the latest occurrence
    single = {**finding, "last_seen": iso(t(8))}
    assert [r["seconds_to_contain"] for r in src.baseline_rows([single], calls)] == [300.0]


def test_guardduty_findings_use_the_latest_activity_like_the_schema_and_keep_the_plan():
    class GD:
        def list_detectors(self):
            return {"DetectorIds": ["d"]}

        def get_paginator(self, name):
            class P:
                def paginate(self, **kw):
                    yield {"FindingIds": ["key", "host"]}
            return P()

        def get_findings(self, DetectorId, FindingIds):  # noqa: N803
            return {"Findings": [
                {"Id": "key", "Type": "Stealth:IAMUser/CloudTrailLoggingDisabled", "CreatedAt": iso(t(8, 10)),
                 "UpdatedAt": iso(t(20)), "Service": {"Count": 3, "EventFirstSeen": iso(t(8)),
                                                      "EventLastSeen": iso(t(16))},
                 "Resource": {"ResourceType": "AccessKey",
                              "AccessKeyDetails": {"UserName": "lab-victim", "AccessKeyId": "key-1"}}},
                {"Id": "host", "Type": "Recon:EC2/Portscan", "CreatedAt": iso(t(9)), "UpdatedAt": iso(t(11)),
                 "Service": {"Count": 1},
                 "Resource": {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": "i-1"}}}]}
    key, host = src.guardduty_findings(GD(), t(0))
    # UpdatedAt (t 20: e.g. an archive) is not an occurrence; without EventFirstSeen the schema falls back to CreatedAt
    assert (key["plan"], key["first_seen"], key["last_seen"]) == ("iam_key_disable", iso(t(8)), iso(t(16)))
    assert (host["plan"], host["first_seen"], host["last_seen"]) == ("ec2_isolate", iso(t(9)), iso(t(9)))
    calls = [human(t(16, 4), "UpdateAccessKey", userName="lab-victim", accessKeyId="key-1")]
    assert [r["seconds_to_contain"] for r in src.baseline_rows([key], calls)] == [240.0]


def test_baseline_plans_are_the_soar_plan_names():
    from siemsoar import schema
    assert set(src.PLAN_OF_RESOURCE.values()) == {schema.PLAN_EC2, schema.PLAN_IAM}


def test_guardduty_samples_are_never_a_baseline():
    class GD:
        def list_detectors(self):
            return {"DetectorIds": ["d"]}

        def get_paginator(self, name):
            class P:
                def paginate(self, **kw):
                    yield {"FindingIds": ["real", "sample"]}
            return P()

        def get_findings(self, DetectorId, FindingIds):  # noqa: N803
            def f(i, sample):
                return {"Id": i, "Type": "Recon:EC2/Portscan", "CreatedAt": iso(t(10)),
                        "Service": {"AdditionalInfo": {"Value": '{"sample": true}'}} if sample else {},
                        "Resource": {"InstanceDetails": {"InstanceId": "i-" + i}}}
            return {"Findings": [f("real", False), f("sample", True)]}
    out = src.guardduty_findings(GD(), t(0))
    assert [f["id"] for f in out] == ["real"] and out[0]["resources"] == {"i-real"}

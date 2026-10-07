## What changes
<!-- infra / lambda / workflow / rule -->

## Detection rule checklist (delete if no rule changes)
- [ ] New rules start in `state: shadow` (the lifecycle gate fails otherwise)
- [ ] `expected_fp` explains what legitimate activity could trigger it
- [ ] Positive **and** negative tests added; `python -m tools.rulesctl test` is green
- [ ] MITRE ATT&CK ids match between metadata and the rule XML
- [ ] Suricata rules: `python -m tools.suricata_pcap_test` is green (pcap expectation added)
- [ ] Promotion (shadow → active) is in its **own** PR with the FP evidence from the shadow period

## Infra / workflow checklist (delete if not relevant)
- [ ] `terraform plan` reviewed; no unexpected destroys (especially the evidence bucket / DynamoDB table)
- [ ] IAM changes keep least privilege; SOAR roles still limited to `siemsoar:zone=workload` and `lab-*` IAM users
- [ ] `python -m tools.gen_asl` re-run if the workflow changed

"""GitHub silently refuses to run a workflow whose YAML does not parse ("Invalid workflow file"), so a typo here
means CI never runs at all. Parse every workflow in the test suite."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
FILES = sorted((ROOT / ".github").rglob("*.yml"))


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_github_yaml_parses(path):
    doc = yaml.safe_load(path.read_text())
    assert isinstance(doc, dict)
    if path.parent.name == "workflows":
        assert "jobs" in doc and doc["jobs"], path.name
        for name, job in doc["jobs"].items():
            assert "steps" in job or "uses" in job, f"{path.name}:{name}"


def test_every_bootstrap_directory_triggers_the_terraform_workflow():
    """Terraform uploads these directories to the bootstrap bucket; a change there needs an apply. agent/ was missing
    from the triggers (2026-10-20): a who-data change merged and nothing deployed it."""
    import re
    tf = (ROOT / "infra/modules/lab-ondemand/bootstrap.tf").read_text()
    block = re.search(r"bootstrap_dirs = \{(.*?)\n  \}", tf, re.S).group(1)  # the map's own closing brace
    dirs = re.findall(r'"\$\{path\.module\}/\.\./\.\./\.\./([\w-]+)"', block)
    assert dirs, "no bootstrap directory found"
    wf = yaml.safe_load((ROOT / ".github/workflows/terraform.yml").read_text())
    triggers = wf.get("on") or wf.get(True)
    for event in ("pull_request", "push"):
        paths = triggers[event]["paths"]
        for d in dirs:
            assert f"{d}/**" in paths, f"{d}/ is uploaded by Terraform but does not trigger the {event} workflow"


def _workflow(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def _tf_vars(wf):
    return {k: v for k, v in wf["env"].items() if k.startswith("TF_VAR_")}


def test_lab_session_applies_with_the_same_terraform_variables_as_the_terraform_workflow():
    """Both workflows apply the same state: a TF_VAR_* missing in one silently resets that setting to its default on
    every apply of the other (lab-session lacked TF_VAR_enable_fault_injection, so `up` turned fault injection off)."""
    assert _tf_vars(_workflow("lab-session.yml")) == _tf_vars(_workflow("terraform.yml"))


def test_lab_on_off_is_read_from_the_state_and_fails_closed():
    """`terraform output lab || echo null` read any error (a transient state read failure) as "lab off": the
    auto-approved apply would then destroy the on-demand plane. The decision must come from a state read that fails
    the step on error (bash -eo pipefail through the pipe)."""
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        text = path.read_text()
        assert "output -json lab" not in text and "|| echo null" not in text, path.name
    wf = _workflow("terraform.yml")
    assert wf["defaults"]["run"]["shell"] == "bash"
    plan = next(s["run"] for s in wf["jobs"]["plan"]["steps"] if s.get("id") == "plan")
    apply = next(s["run"] for s in wf["jobs"]["apply"]["steps"] if s.get("name") == "Apply")
    for run in (plan, apply):
        assert "$(terraform -chdir=$TF_DIR state pull | jq " in run
        assert 'startswith("module.lab[")' in run


def test_workflows_run_a_terraform_version_the_configuration_accepts():
    """infra/envs/lab uses write-only arguments (Terraform >= 1.11): every pinned CLI must satisfy required_version."""
    import re
    need = re.search(r'required_version = ">= ([\d.]+)"', (ROOT / "infra/envs/lab/backend.tf").read_text()).group(1)
    pins = [s["with"]["terraform_version"] for p in (ROOT / ".github/workflows").glob("*.yml")
            for job in yaml.safe_load(p.read_text())["jobs"].values() for s in job.get("steps", [])
            if str(s.get("uses", "")).startswith("hashicorp/setup-terraform")]
    assert pins

    def version(v):
        return tuple(int(x) for x in v.split("."))

    assert all(version(pin)[:len(version(need))] >= version(need) for pin in pins), (need, pins)


def test_terraform_never_stores_a_secure_string_value_in_state():
    """`value` + ignore_changes still refreshed the decrypted Slack token into the state (seen in the live state).
    Every SecureString Terraform creates takes its placeholder through the write-only `value_wo`; a fixed
    `value_wo_version` and no ignore_changes on it, so the placeholder is written on create only."""
    import re
    blocks = []
    for tf in (ROOT / "infra").rglob("*.tf"):
        if ".terraform" in tf.parts:
            continue
        blocks += re.findall(r'resource "aws_ssm_parameter" "\w+" \{\n(.*?)\n\}', tf.read_text(encoding="utf-8"), re.S)
    secure = [b for b in blocks if '"SecureString"' in b]
    assert secure
    for b in secure:
        assert re.search(r"^\s+value_wo\s+=", b, re.M) and re.search(r"^\s+value_wo_version\s+= 1$", b, re.M), b
        assert not re.search(r"^\s+value\s+=", b, re.M) and "ignore_changes" not in b, b


def test_plan_role_writes_only_the_state_lock_file():
    """gha-plan is assumable by any same-repo pull request: it reads the state and may write only the lock file."""
    import re
    oidc = (ROOT / "infra/bootstrap/oidc.tf").read_text(encoding="utf-8")
    block = re.search(r'data "aws_iam_policy_document" "plan_state" \{\n(.*?)\n\}', oidc, re.S).group(1)
    key = re.search(r'key\s+= "([^"]+)"', (ROOT / "infra/envs/lab/backend.tf").read_text()).group(1)
    for stmt in re.findall(r"statement \{(.*?)\n  \}", block, re.S):
        if "PutObject" in stmt or "DeleteObject" in stmt:
            assert re.findall(r'resources = \[(.*?)\]', stmt) == [f'"${{aws_s3_bucket.tfstate.arn}}/{key}.tflock"'], stmt
            assert "GetObject" not in stmt


def test_ci_scans_the_tree_for_secrets_and_fails_on_findings():
    job = _workflow("ci.yml")["jobs"]["secret-scan"]
    run = " ".join(s.get("run", "") for s in job["steps"])
    assert "zricethezav/gitleaks@sha256:" in run  # pinned by digest
    assert "--exit-code 1" in run and "--redact" in run


def test_terraform_workflow_asks_only_for_the_permissions_it_uses():
    assert _workflow("terraform.yml")["permissions"] == {"id-token": "write", "contents": "read"}

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

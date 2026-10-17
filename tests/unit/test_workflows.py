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

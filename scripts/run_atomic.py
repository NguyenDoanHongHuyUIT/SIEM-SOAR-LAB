#!/usr/bin/env python3
"""Run ONE Atomic Red Team test on this host, exactly as its upstream YAML describes it.

  run_atomic.py T1136.001 40d8eabd-e394-46f6-8785-b9bfa1d011d2 [--arg username=siemsoar_sim_ab12] [--cleanup]

* The technique YAML (and any `src/` file a command reads through PathToAtomicsFolder) is fetched from the official
  repository at the full commit SHA in $ART_REF and cached per SHA. Branch names and tags are rejected so later upstream
  changes cannot alter a run.
* Execution follows Atomic Red Team's own conventions (the ones Invoke-AtomicTest implements): `#{name}` is replaced by
  the input argument (explicit --arg, else the test's default), `PathToAtomicsFolder` is the path of the `atomics`
  directory, the command runs with the executor named in the YAML (sh/bash; we are root, so elevation holds), and
  `--cleanup` runs the test's cleanup_command instead.
* Dependencies: every `prereq_command` must succeed first. A missing prerequisite exits 3 so the simulation runner
  records an execution error, never a false negative. The bootstrap installs the tools the lab's atomics need.
* The exit code of the test command is reported, not judged: Atomic tests often end with a command that returns
  non-zero on purpose (nc to a closed port). Whether the behaviour happened is checked by the scenario's `verify`.
* A test that is still running at --timeout is killed with its whole process group and reported `timed_out`, as
  Invoke-AtomicTest does (T1046 test 2 ends with `nc` to a port that never closes the connection).

Used by simulation/runner.py (scenario kind `atomic`) through SSM. Needs python3 + PyYAML (python3-yaml).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ART_CACHE = Path(os.environ.get("ART_DIR", "/opt/atomic-red-team/atomics")).parent
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
RAW = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{ref}/atomics/{path}"
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
SRC_RE = re.compile(r"PathToAtomicsFolder[/\\]+(T\d{4}(?:\.\d{3})?)[/\\]+src[/\\]+([A-Za-z0-9_.\-]+)")
EXECUTORS = {"sh": ["sh", "-c"], "bash": ["bash", "-c"]}


def _download(ref: str, rel: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(RAW.format(ref=ref, path=rel), timeout=30) as resp:  # noqa: S310 (fixed https host)
        dest.write_bytes(resp.read())


def ensure_atomic(technique: str, ref: str) -> tuple[Path, Path]:
    if not TECHNIQUE_RE.fullmatch(technique):
        raise ValueError("technique must be an ATT&CK technique ID")
    if not COMMIT_RE.fullmatch(ref):
        raise ValueError("ART_REF must be a full 40-character commit SHA")
    root = ART_CACHE / ref
    path = root / "atomics" / technique / f"{technique}.yaml"
    if not path.exists():
        _download(ref, f"{technique}/{technique}.yaml", path)
    return path, root


def find_test(doc: dict, guid: str) -> dict:
    for test in doc.get("atomic_tests", []):
        if test.get("auto_generated_guid") == guid:
            return test
    raise ValueError(f"no test {guid} in {doc.get('attack_technique')}")


def render(text: str, test: dict, args: dict[str, str], atomics: Path) -> str:
    values = {k: str(v.get("default", "")) for k, v in (test.get("input_arguments") or {}).items()}
    unknown = set(args) - set(values)
    if unknown:
        raise ValueError(f"not input arguments of {test['name']!r}: {sorted(unknown)}")
    values.update(args)
    text = re.sub(r"#\{(\w+)\}", lambda m: values.get(m.group(1), m.group(0)), text)
    return text.replace("$PathToAtomicsFolder", str(atomics)).replace("PathToAtomicsFolder", str(atomics))


def ensure_sources(text: str, ref: str, root: Path) -> list[str]:
    """Fetch every atomics/<T>/src/<file> the (unrendered) commands refer to, from the same commit."""
    fetched = []
    for technique, name in sorted(set(SRC_RE.findall(text))):
        dest = root / "atomics" / technique / "src" / name
        if not dest.exists():
            _download(ref, f"{technique}/src/{name}", dest)
        fetched.append(f"{technique}/src/{name}")
    return fetched


@dataclass
class Outcome:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


def _shell(executor: str, command: str, timeout: int) -> Outcome:
    if executor not in EXECUTORS:
        raise ValueError(f"executor {executor!r} is not supported on Linux lab hosts")
    proc = subprocess.Popen([*EXECUTORS[executor], command], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, text=True, start_new_session=True)
    try:
        out, err = proc.communicate(timeout=timeout)
        return Outcome(proc.returncode, out, err)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)  # the shell and everything it started (nc, telnet, ...)
        out, err = proc.communicate()
        return Outcome(None, out, err, timed_out=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("technique")
    ap.add_argument("test_guid")
    ap.add_argument("--arg", action="append", default=[], metavar="NAME=VALUE", help="atomic input argument")
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args(argv)

    ref = os.environ.get("ART_REF", "")
    if not UUID_RE.fullmatch(args.test_guid):
        ap.error("test_guid must be a UUID")
    for value in args.arg:
        key, separator, _ = value.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            ap.error("--arg must use NAME=VALUE with a valid argument name")
    import yaml  # python3-yaml on the lab hosts

    path, root = ensure_atomic(args.technique, ref)
    test = find_test(yaml.safe_load(path.read_text(encoding="utf-8")), args.test_guid)
    if "linux" not in test.get("supported_platforms", []):
        ap.error(f"{test['name']!r} does not support linux")
    inputs = dict(a.split("=", 1) for a in args.arg)
    executor = test["executor"]
    atomics = root / "atomics"
    raw_text = "\n".join(str(x) for x in (executor.get("command"), executor.get("cleanup_command"),
                                          *[d.get("prereq_command") for d in test.get("dependencies") or []]) if x)
    sources = ensure_sources(raw_text, ref, root)
    report = {"technique": args.technique, "test_guid": args.test_guid, "test_name": test["name"], "art_ref": ref,
              "phase": "cleanup" if args.cleanup else "execute", "inputs": inputs, "sources": sources}

    if not args.cleanup:
        dep_exec = test.get("dependency_executor_name", executor["name"])
        for dep in test.get("dependencies") or []:
            check = _shell(dep_exec, render(dep["prereq_command"], test, inputs, atomics), 60)
            if check.returncode != 0:
                report["missing_prerequisite"] = dep.get("description", "").strip()
                print(json.dumps(report))
                return 3
        command = executor["command"]
    else:
        command = executor.get("cleanup_command") or ""
        if not command.strip():
            report["exit_code"] = None
            print(json.dumps(report))
            return 0
    result = _shell(executor["name"], render(command, test, inputs, atomics), args.timeout)
    report.update(exit_code=result.returncode, timed_out=getattr(result, "timed_out", False),
                  stdout_tail=result.stdout[-400:], stderr_tail=result.stderr[-400:])
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())

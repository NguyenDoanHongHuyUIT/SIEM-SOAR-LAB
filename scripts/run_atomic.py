#!/usr/bin/env python3
"""Run ONE Atomic Red Team test on this host with atomic-operator (the Python runner for Atomic Red Team).

  run_atomic.py T1136.001 40d8eabd-e394-46f6-8785-b9bfa1d011d2 [--arg username=siemsoar_sim_ab12] [--cleanup]

* Atomics are the unmodified YAML files of github.com/redcanaryco/atomic-red-team (downloaded per technique at the
  ref in $ART_REF, default `master`; set a commit SHA for reproducible evaluation runs). The commit actually used is
  printed, so it can be stored with the simulation run.
* Without --cleanup the atomic's test commands run; with --cleanup the atomic's own cleanup commands run.
* Used by simulation/runner.py (scenario kind `atomic`) through SSM; needs the venv built by
  suricata/bootstrap_sensor.sh (atomic-operator + attrs).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

ATOMICS = Path(os.environ.get("ART_DIR", "/opt/atomic-red-team/atomics"))
RAW = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{ref}/atomics/{t}/{t}.yaml"


def ensure_atomic(technique: str, ref: str) -> Path:
    path = ATOMICS / technique / f"{technique}.yaml"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(RAW.format(ref=ref, t=technique), timeout=30) as resp:  # noqa: S310 (fixed https host)
            path.write_bytes(resp.read())
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("technique")
    ap.add_argument("test_guid")
    ap.add_argument("--arg", action="append", default=[], metavar="NAME=VALUE", help="atomic input argument")
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--timeout", type=int, default=90)
    args = ap.parse_args(argv)

    ref = os.environ.get("ART_REF", "master")
    ensure_atomic(args.technique, ref)
    from atomic_operator import AtomicOperator  # imported late: only present in the venv on lab hosts

    inputs = dict(a.split("=", 1) for a in args.arg)
    AtomicOperator().run(techniques=[args.technique], test_guids=[args.test_guid], atomics_path=str(ATOMICS.parent),
                         input_arguments=inputs, cleanup=args.cleanup, command_timeout=args.timeout,
                         prompt_for_input_args=False, check_prereqs=False, get_prereqs=False)
    print(json.dumps({"technique": args.technique, "test_guid": args.test_guid, "art_ref": ref,
                      "phase": "cleanup" if args.cleanup else "execute", "inputs": inputs}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

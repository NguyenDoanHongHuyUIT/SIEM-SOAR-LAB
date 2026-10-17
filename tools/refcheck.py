"""refcheck: every reference cited by a rule or by policy.toml must resolve (HTTP 2xx/3xx).

  python -m tools.refcheck            # network required; exits 1 when a link is dead

`rulesctl lint` checks that references are well formed HTTPS URLs and that ATT&CK ids are live in the pinned snapshot;
this checks that what is cited still exists. It is separate (and runs as a scheduled/non-blocking CI job) because a
third-party outage must not fail a pull request.
"""

from __future__ import annotations

import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
URL_RE = re.compile(r"https://[^\s\"'<>)\]]+")
SOURCES = [ROOT / "rules" / "metadata", ROOT / "src" / "lambdas" / "siemsoar" / "policy.toml", ROOT / "rules" / "wazuh",
           ROOT / "rules" / "suricata"]
USER_AGENT = "siem-soar-lab-refcheck/1.0 (+https://github.com)"


def collect(paths: list[Path] | None = None) -> dict[str, list[str]]:
    """{url: [files citing it]}"""
    found: dict[str, list[str]] = {}
    for base in paths or SOURCES:
        files = [base] if base.is_file() else sorted(p for p in base.rglob("*") if p.is_file())
        for f in files:
            for url in URL_RE.findall(f.read_text(encoding="utf-8")):
                found.setdefault(url.rstrip(".,;"), []).append(f.relative_to(ROOT).as_posix())
    return found


def probe(url: str, timeout: int = 30) -> tuple[bool, str]:
    for method in ("HEAD", "GET"):  # some sites reject HEAD
        req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only, from repo files)
                return True, str(resp.status)
        except urllib.error.HTTPError as err:
            if method == "GET" or err.code not in (403, 405, 501):
                return False, f"HTTP {err.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            return False, type(err).__name__
    return False, "unreachable"


def main() -> int:
    refs = collect()
    with ThreadPoolExecutor(8) as pool:
        results = dict(zip(refs, pool.map(probe, refs), strict=True))
    dead = {u: r for u, (ok, r) in results.items() if not ok}
    for url, (ok, status) in sorted(results.items()):
        print(f"{'ok  ' if ok else 'DEAD'} {status:<14} {url}" + ("" if ok else f"   <- {', '.join(sorted(set(refs[url])))}"))
    print(f"{len(refs) - len(dead)}/{len(refs)} references resolve")
    return 1 if dead else 0


if __name__ == "__main__":
    sys.exit(main())

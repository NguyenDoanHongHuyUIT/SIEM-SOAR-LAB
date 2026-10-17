"""Every text file the tools read or write names its encoding.

Without it Python uses the platform default (cp1252 on Windows): `evaluation.evaluate` crashed writing the Vietnamese
report on the operator's machine after the first lab session (UnicodeEncodeError on 'đ').
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = [p for d in ("evaluation", "tools", "simulation", "scripts", "src/lambdas") for p in (ROOT / d).rglob("*.py")]


def _text_mode_open(call: ast.Call) -> bool:
    mode = call.args[1] if len(call.args) > 1 else next((k.value for k in call.keywords if k.arg == "mode"), None)
    return not (isinstance(mode, ast.Constant) and "b" in str(mode.value))


def test_text_io_always_names_its_encoding():
    missing = []
    for path in SOURCES:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call) or any(k.arg == "encoding" for k in node.keywords):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            builtin_open = isinstance(node.func, ast.Name) and name == "open"  # not tarfile.open etc.
            if name in ("read_text", "write_text") or (builtin_open and _text_mode_open(node)):
                missing.append(f"{path.relative_to(ROOT)}:{node.lineno} {name}()")
    assert not missing, "text I/O without encoding=: " + ", ".join(missing)

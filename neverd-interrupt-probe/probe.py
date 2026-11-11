import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).parent
p = json.loads((root / "Probe.def").read_text())
fixture = (root / p["fixture"]).read_text()
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    for key, name in p["sources"].items():
        match = re.search(p["source_pattern"].format(key=key), fixture, re.S)
        (tmp / name).write_text(match.group(2))
    commands = [p["original"], p["driver"], p["execute"]]
    report = {"fixture_sha256": hashlib.sha256(fixture.encode()).hexdigest()}
    try:
        for cmd in commands:
            subprocess.run(cmd, cwd=tmp, check=True, timeout=p["timeout"])
        rows = [[int(value) for value in line.split()] for line in
                (tmp / p["samples"]).read_text().splitlines()]
        if len(rows) != len(p["expected"]) or any(
                off < 0 or off % p["alignment"] or row != expect
                for (off, *row), expect in zip(rows, p["expected"])):
            raise ValueError(p["invalid"])
        report["samples"] = rows
        report["passed"] = True
    finally:
        Path(p["report"]).write_text(json.dumps(report, indent=2))

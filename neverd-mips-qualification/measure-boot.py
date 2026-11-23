"""Replay the original publications without retaining them in the artifacts."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

MANUALS = {
    "r4300ps.pdf": (
        "95c7ae1667dbd3722d0320df394293047fb3f2130ed3c47d50a7d8ce75fcfd97",
        [
            "https://archive.org/download/manualzilla-id-5722005/5722005.pdf",
            "https://web.archive.org/web/20060510080138id_/http://www.c-h-s.com/r4300ps.pdf",
        ],
    ),
    "r4xxxps.pdf": (
        "85c1024fa15c3c4b994c4558c235303cff6df640ed1e60c8864e7004b4a234c7",
        ["https://web.archive.org/web/20030728054757id_/http://www.c-h-s.com/r4xxxps.pdf"],
    ),
}


def download(directory, name, expected, urls):
    for attempt in range(4):
        for url in urls:
            try:
                with urlopen(url, timeout=30) as response:
                    data = response.read()
                if hashlib.sha256(data).hexdigest() != expected:
                    raise ValueError("unexpected document")
                path = directory / name
                path.write_bytes(data)
                return path
            except (OSError, ValueError) as err:
                print(f"{name}: {err}", flush=True)
        if attempt < 3:
            time.sleep(2 ** attempt)
    raise RuntimeError(f"could not obtain original {name}")


with tempfile.TemporaryDirectory() as directory:
    inputs = [download(Path(directory), name, sha, urls)
              for name, (sha, urls) in MANUALS.items()]
    output = subprocess.check_output(
        [sys.executable, "unittests/lift/mips/historical-reset-capture.py", *inputs]
    )
    got = json.loads(output)
    for board, bounds in [("R4300", [196, 204]), ("R4600", [62, 66])]:
        assert got[board]["raster_bounds_ns"] == bounds
    Path("evidence/reset-waveforms.json").write_bytes(output)

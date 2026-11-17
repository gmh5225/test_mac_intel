from pathlib import Path
import json
import os
import subprocess
import tempfile

policy = json.loads(Path(__file__).with_name("WindowsProbe.def").read_text())
clang = os.environ["NEVERD_SOURCE_CLANG"]
reports = []
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    for opt in policy["optimizations"]:
        for case in policy["fixtures"]:
            source = root / case["file"]
            source.write_text(case["source"])
            args = [clang, "-target", policy["target"], "-ffreestanding", "-nostdlibinc", opt]
            assembly = subprocess.check_output([*args, "-S", str(source), "-o", "-"], text=True)
            subprocess.run([*args, "-c", str(source), "-o", str(root / "probe.o")], check=True)
            absent = [marker for marker in case["markers"] if marker not in assembly]
            if absent:
                raise RuntimeError((source.name, opt, absent))
            reports.append({"source": source.name, "optimization": opt, "verified": case["markers"]})
print(subprocess.check_output([clang, "--version"], text=True))
print(json.dumps(reports, indent=2))

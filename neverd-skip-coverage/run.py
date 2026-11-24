import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root = Path.cwd()
inputs = root / "inputs"
reports = root / "reports"
control = json.loads((root / "neverd-skip-coverage/controls.def").read_text())
for name, expected in control["files"].items():
    assert hashlib.sha256((inputs / name).read_bytes()).hexdigest() == expected
sys.path.insert(0, str(root / "model/neverd-cpta"))
from run import model_session
with tempfile.TemporaryDirectory() as temp, model_session(Path(temp), reports) as model:
    for profile in control["profiles"]:
        target = reports / profile
        subprocess.run([sys.executable, str(inputs / "verify_arm64e_return_model.py"),
                        "run", "--guests", str(inputs / profile), "--model", str(model),
                        "--output", str(target)], check=True)
        shutil.copyfile(inputs / profile / "guests.json", target / "guests.json")
(reports / "inputs.json").write_text(json.dumps(control, indent=2) + "\n")

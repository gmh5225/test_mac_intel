from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile

root = Path.cwd()
inputs = Path(__file__).resolve().parent
reports = root / "reports"
reports.mkdir()
control = json.loads((inputs / "inputs.def").read_text())
for name, expected in control["files"].items():
    if hashlib.sha256((inputs / name).read_bytes()).hexdigest() != expected:
        raise ValueError(name)
sys.path.insert(0, str(root / "model/neverd-cpta"))
from run import model_session

with tempfile.TemporaryDirectory() as parent, model_session(Path(parent), reports) as model:
    for source, destination in (("joins", "joined-execution"), ("scratch-free", "scratch-free-execution"), ("previous", "previous-execution"), ("guests", "execution"), ("legacy", "legacy-execution")):
        subprocess.run([sys.executable, str(inputs / "verify_arm64e_return_model.py"), "run",
                        "--model", str(model), "--guests", str(inputs / source),
                        "--output", str(reports / destination)], check=True)
shutil.copyfile(inputs / "joins/guests.json", reports / "joined-guests.json")
shutil.copyfile(inputs / "guests/guests.json", reports / "guests.json")
shutil.copyfile(inputs / "legacy/guests.json", reports / "legacy-guests.json")
shutil.copyfile(inputs / "inputs.def", reports / "inputs.json")

shutil.copyfile(inputs / "previous/guests.json", reports / "previous-guests.json")

shutil.copyfile(inputs / "scratch-free/guests.json", reports / "scratch-free-guests.json")

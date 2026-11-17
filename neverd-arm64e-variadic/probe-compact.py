import json
import subprocess
from pathlib import Path

config = json.loads(Path(__file__).with_name("CompactProbe.def").read_text())
out = Path(config["output"]).resolve()
out.mkdir(parents=True, exist_ok=True)
source = out / config["source"]
body = Path(config["fixture"]).read_text().split(config["begin"], 1)[1].split(config["end"], 1)[0]
source.write_text(body)
values = {"source": str(source), "out": str(out)}
for name, args in config["commands"].items():
    command = [arg.format_map(values) for arg in args]
    result = subprocess.run(command, text=True, capture_output=True)
    (out / (name + ".json")).write_text(json.dumps({"command": command, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}, indent=2))
    result.check_returncode()

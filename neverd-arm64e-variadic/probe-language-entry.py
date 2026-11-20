from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import tempfile


policy = json.loads(Path(__file__).with_name("EntryLanguageProbe.def").read_text())
repo = Path(sys.argv[1]).resolve()
definition = (repo / policy["fixture"]).read_text()
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    args = {key: str(root / filename) for key, filename in policy["outputs"].items()}
    args.update(include=str(repo / "include"), target=policy["target"],
                mode=policy["mode"], value=policy["old_value"])
    Path(args["companion"]).write_text(policy["companion"])
    for key, (filename, tag) in policy["sources"].items():
        pattern = rf'ASYNC_FRAME_TEXT\({key}, R"{tag}\((.*?)\){tag}"\)'
        path = root / filename
        path.write_text(re.search(pattern, definition, re.S).group(1))
        args[key] = str(path)
    results = {}
    for name, command in policy["commands"].items():
        actual = [word.format(**args) for word in command]
        probe = subprocess.run(actual, capture_output=True, text=True)
        results[name] = {"exit": probe.returncode, "stdout": probe.stdout, "stderr": probe.stderr}
        if name != "execute":
            probe.check_returncode()
    results["image_sha256"] = hashlib.sha256(Path(args["image"]).read_bytes()).hexdigest()
    if Path(args["samples"]).exists():
        results["sample"] = Path(args["samples"]).read_text().strip()
    evidence = Path(policy["output"])
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(results, indent=2) + "\n")
    print(evidence.read_text())
    if "expected" in policy:
        expected = policy["expected"]
        assert expected["encoding"] in results["unwind"]["stdout"]
        assert results["execute"]["exit"] == expected["exit"]
        assert len(results["sample"].split()) == expected["sample_fields"]
        assert int(results["sample"].split()[expected["exact_field"]]) == expected["exact"]

import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

policy = json.loads(Path(__file__).with_name("Inputs.def").read_text())
out = Path(policy["out"]).resolve()
out.mkdir()

def data_in_code(path):
    data = path.read_bytes()
    layout = policy["layout"]
    pos = layout["mach_header_64"]
    for _ in range(struct.unpack_from(layout["count"], data, layout["ncmds"])[0]):
        cmd, size = struct.unpack_from(layout["command"], data, pos)
        if cmd == layout["data_in_code"]:
            offset, length = struct.unpack_from(layout["command"], data, pos + layout["linkedit_data_fields"])
            return [[width, kind] for _, width, kind in
                    struct.iter_unpack(layout["entry"], data[offset:offset + length])]
        pos += size
    return []

with tempfile.TemporaryDirectory() as scratch:
    root = Path(scratch)
    assembly, oracle = (root / name for name in policy["sources"])
    assembly.write_text(policy["assembly"])
    oracle.write_text(policy["oracle"])
    runner = root / policy["driver"]
    subprocess.run([*policy["caller"], oracle, policy["output_option"], runner], check=True)
    reports = {}
    for name, flags in policy["variants"].items():
        image = out / (name + policy["image_suffix"])
        subprocess.run([*policy["compile"], *flags, assembly, policy["output_option"], image], check=True)
        subprocess.run([*policy["signature"], image], check=True)
        subprocess.run([*policy["verify"], image], check=True)
        records = data_in_code(image)
        assert records == policy["expected"][name], (name, records)
        subprocess.run([runner, image], check=True)
        reports[name] = {"sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
                         "records": records, "comparisons": policy["compare_count"]}
    (out / policy["report"]).write_text(json.dumps(reports, indent=2) + "\n")

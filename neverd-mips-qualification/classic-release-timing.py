"""Time the NeverD decoder and its underlying Capstone iterator on matching words."""

import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import tempfile


def profile_inputs(syscall):
    if syscall:
        yield 32, 0, "mips1", (0x0000000C, 0x3C1AA000) * 64
        return
    common = (
        0x24840007, 0x00851021, 0x00851026, 0x8CA20000,
        0xACA20004, 0x10850001, 0x00000000, 0x03E00008,
    )
    for width in (32, 64):
        words = (common + ((0x0085102D, 0x64840007) if width == 64 else ())) * 16
        for rev in (1, 2, 3, 5):
            name = ("mips" if width == 32 else "mips64") if rev == 2 else f"mips{width}r{rev}"
            yield width, rev, name, words


def measure(binary, output, syscall=False):
    stages = ("decode", "capstone")
    profiles = {}
    rng = random.Random(20261124)
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        for width, revision, name, words in profile_inputs(syscall):
            for order in ("big", "little"):
                profile = name + ("el" if order == "little" else "")
                raw = b"".join(word.to_bytes(4, order) for word in words)
                (root / profile).write_bytes(raw)
                profiles[profile] = {
                    "width": width, "revision": revision, "endian": order,
                    "sha256": hashlib.sha256(raw).hexdigest(), "count": len(words), "pairs": [],
                }
                if syscall:
                    profiles[profile]["historical_isa"] = 1

        def run(name, stage, reps):
            row = json.loads(subprocess.check_output(
                [str(binary), name, stage, str(root / name), str(reps)], text=True
            ))
            assert row["repeats"] == reps and row["instructions_per_repeat"] == profiles[name]["count"]
            assert row["cpu_seconds"] > 0 and row["wall_seconds"] > 0
            return row

        for name, profile in profiles.items():
            count = profile["count"]
            pilot_reps = math.ceil(8_000_000 / count)
            pilot = {stage: run(name, stage, pilot_reps) for stage in stages}
            assert pilot["decode"]["digest"] == pilot["capstone"]["digest"]
            profile["digest"] = pilot["decode"]["digest"]
            profile["pilot"] = pilot
            fastest = min(row["cpu_seconds"] for row in pilot.values())
            profile["reps"] = max(math.ceil(48_000_000 / count), math.ceil(1.2 * pilot_reps / fastest))

        for block in range(8):
            names = list(profiles)
            rng.shuffle(names)
            for name in names:
                profile = profiles[name]
                order = stages if (block + list(profiles).index(name)) % 2 == 0 else stages[::-1]
                legs = {stage: run(name, stage, profile["reps"]) for stage in order}
                assert all(row["digest"] == profile["digest"] for row in legs.values())
                profile["pairs"].append({"order": order, "legs": legs})
            print("finished paired block", block + 1, flush=True)

    for profile in profiles.values():
        pairs = profile["pairs"]
        assert sum(pair["order"][0] == "decode" for pair in pairs) == len(pairs) // 2
        profile["minimum_cpu_seconds"] = min(r["cpu_seconds"] for pair in pairs for r in pair["legs"].values())
        profile["median_decode_over_capstone"] = {
            clock: statistics.median(p["legs"]["decode"][clock] / p["legs"]["capstone"][clock] for p in pairs)
            for clock in ("cpu_seconds", "wall_seconds")
        }
    report = {
        "source": os.environ["REVISION"], "host": platform.platform(), "runner_os": os.environ["RUNNER_OS"],
        "executable_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "profiles": profiles,
    }
    output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    measure(Path(sys.argv[1]).resolve(), Path(sys.argv[2]), sys.argv[3:] == ["--r3000-syscall"])

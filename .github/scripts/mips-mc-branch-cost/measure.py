"""Measure identical classic MIPS object emission, by CPU time and native instruction count."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import resource
import shutil
import statistics
import struct
import subprocess
import tempfile
import time


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def cpu():
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return child.ru_utime + child.ru_stime


def text_digest(path):
    data = path.read_bytes()
    assert data[:6] == b"\x7fELF\x01\x01"
    off, = struct.unpack_from("<I", data, 32)
    stride, count, strings = struct.unpack_from("<3H", data, 46)
    headers = [struct.unpack_from("<10I", data, off + i * stride) for i in range(count)]
    names = data[headers[strings][4]:][:headers[strings][5]]
    section, = [h for h in headers if names[h[0]:].split(b"\0", 1)[0] == b".text"]
    return hashlib.sha256(data[section[4]:][:section[5]]).hexdigest()


def measure(args):
    start, c0 = time.perf_counter(), cpu()
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)
    return {"wall": time.perf_counter() - start, "cpu": cpu() - c0}


def summary(rows, metric):
    groups = [[100 * (row["r14"][metric] / row["r13"][metric] - 1) for row in rows if row["layout"] == phase]
              for phase in (0, 1)]
    assert len(groups[0]) == len(groups[1]) == 32
    rng, median = random.Random(583317), statistics.median
    boot = sorted(median(rng.choices(groups[0], k=32) + rng.choices(groups[1], k=32)) for _ in range(10000))
    return {"median_pct": median(groups[0] + groups[1]), "ci95_pct": [boot[249], boot[9749]],
            "assignment_medians": [median(group) for group in groups]}


def main():
    project = Path.cwd()
    outputs = project / "evidence"
    outputs.mkdir(exist_ok=True)
    variants = ("r13", "r14")
    drivers = {name: project / ("build-" + name) / "llvm-mc" for name in variants}
    rng = random.Random(8159031)
    available = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {available[0]})
    with tempfile.TemporaryDirectory() as scratch:
        tmp = Path(scratch)
        cases = {}
        header = ".set noreorder\n.text\n"
        for name, count, branches in (("empty", 0, False), ("small", 1024, True),
                                      ("branches", 32768, True), ("arithmetic", 32768, False)):
            path = tmp / (name + ".s")
            body = ("".join(f".Lhead{i}:\n addiu $3, $3, 17\n bne $3, $4, .Lhead{i}\n nop\n" for i in range(count)) if branches
                    else "".join(f".Lhead{i}:\n addiu $3, $3, 17\n addu $3, $3, $4\n nop\n" for i in range(count)))
            path.write_text(header + body)
            cases[name] = path
        output = tmp / "out.o"
        common = ["-triple=mipsel", "-mcpu=mips32r2", "-filetype=obj"]
        checksums, samples, instructions = {}, {k: [] for k in cases if k != "empty"}, {}
        for name, source in cases.items():
            instructions[name] = {}
            for version, driver in drivers.items():
                args = [driver, *common, source, "-o", output]
                measure(args)
                raw = sha(output)
                assert checksums.setdefault(name, raw) == raw
                if name == "branches":
                    assert text_digest(output) == "2ec06f9b02df6207dac56480b511f2a5bace9b1d4c78daa3096a34f33df5d21a"
                trace = tmp / "profile"
                subprocess.run(["valgrind", "--tool=callgrind", "--callgrind-out-file=" + str(trace), *args],
                               stdout=subprocess.DEVNULL, check=True)
                assert sha(output) == raw
                data = trace.read_text()
                assert "events: Ir" in data.splitlines()
                total, = [int(line.split()[1]) for line in data.splitlines() if line.startswith("summary:")]
                assert total > 0
                with gzip.open(outputs / (name + "-" + version + ".callgrind.gz"), "wb") as out:
                    out.write(data.encode())
                instructions[name][version] = total
        slots = [tmp / "slot0" / "llvm-mc", tmp / "slot1" / "llvm-mc"]
        for phase in (0, 1):
            bins = {}
            for index, version in enumerate(variants):
                slot = slots[index ^ phase]
                slot.parent.mkdir(exist_ok=True)
                shutil.copy2(drivers[version], slot)
                assert sha(slot) == sha(drivers[version])
                bins[version] = slot
            for index in range(-2, 32):
                order = list(samples)
                rng.shuffle(order)
                for name in order:
                    labels = list(variants)
                    if (index + phase) % 2:
                        labels.reverse()
                    row = {"layout": phase, "order": labels}
                    for version in labels:
                        row[version] = measure([bins[version], *common, cases[name], "-o", output])
                        assert sha(output) == checksums[name]
                    if index >= 0:
                        samples[name].append(row)
        results = {n: {metric: summary(rows, metric) for metric in ("cpu", "wall")} for n, rows in samples.items()}
        base = instructions["empty"]
        for name, row in results.items():
            a, b = (instructions[name][v] - base[v] for v in variants)
            row["incremental_native_instructions_pct"] = 100 * (b / a - 1)
        proof = {"driver_sha256": {k: sha(v) for k, v in drivers.items()}, "whole_object_sha256": checksums,
                 "platform": platform.platform(), "affinity": available[0], "sources": {v: (outputs / (v + "-source.txt")).read_text().strip() for v in variants},
                 "pairs_per_case": 64, "callgrind": instructions, "samples": samples, "result": results}
        (outputs / "results.json").write_text(json.dumps(proof, indent=2) + "\n")
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()

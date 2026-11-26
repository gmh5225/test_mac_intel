"""Pair six native drivers on identical source, including cold and mixed workloads."""
from pathlib import Path
import gzip
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mips-mnemonic"))
from compare import child_cpu, digest, inputs

FLAGS = ["-triple=mipsel", "-mcpu=mips32r2", "-filetype=obj"]
REPEATS = 8


def rare_source(fixture):
    lines = [".text", ".set noreorder", ".set noat", "a:", "1:"]
    names = set()
    for line in fixture.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(".") or line.endswith(":"):
            continue
        mnemonic = line.split()[0]
        if mnemonic not in names:
            names.add(mnemonic)
            lines.append(line)
    assert 200 <= len(names) <= 260, len(names)
    return "\n".join([*lines, "1:", ""]), len(names)


def summarize(rows, candidate, baseline):
    med = statistics.median
    rng = random.Random(584113)
    result = {}
    for metric in ("cpu", "wall"):
        groups = [[100 * (row[candidate][metric] / row[baseline][metric] - 1)
                   for row in rows if row["phase"] == phase] for phase in range(6)]
        assert all(len(group) == REPEATS for group in groups)
        samples = sorted(med(sum((rng.choices(group, k=len(group)) for group in groups), []))
                         for _ in range(2500))
        result[metric] = {"median": med(sum(groups, [])), "ci95": [samples[62], samples[2437]],
                          "assignment_medians": list(map(med, groups))}
    return result


def run(exe, source, obj, count):
    t, cpu = time.perf_counter(), child_cpu()
    for _ in range(count):
        subprocess.run([exe, *FLAGS, source, "-o", obj], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"cpu": child_cpu() - cpu, "wall": time.perf_counter() - t}


def write(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def main():
    work = Path(os.environ["RUNNER_TEMP"]) / "mips-probes"
    evidence = Path.cwd() / "lookup-evidence"
    exes = {k: Path(v) for k, v in json.loads((work / "paths.json").read_text()).items()}
    assert set(exes) == {"r13", "r14", "rebuilt", "binary", "early", "set"}
    rare, distinct = rare_source(Path("source/llvm/test/MC/Mips/mips32r2/valid.s"))
    programs = {"empty": ".text\n", "short": ".text\n.set noreorder\naddiu $3,$3,17\n",
                "rare": rare, **inputs()}
    sources = {}
    for name, body in programs.items():
        sources[name] = work / (name + ".s")
        sources[name].write_bytes(body.encode())
    raw = {k: [] for k in sources if k != "empty"}
    objects = {}
    obj = work / "output.o"
    rng = random.Random(1476571)
    for phase in range(6):
        rotated = {}
        for idx, (ver, original) in enumerate(exes.items()):
            path = work / ("slot" + str((idx + phase) % 6)) / "llvm-mc"
            path.parent.mkdir(exist_ok=True)
            shutil.copy2(original, path)
            assert digest(original) == digest(path)
            rotated[ver] = path
        for it in range(-1, REPEATS):
            workloads = list(raw)
            rng.shuffle(workloads)
            for kind in workloads:
                order = list(rotated)
                rng.shuffle(order)
                row = {"phase": phase, "trial": it, "order": order}
                for ver in order:
                    row[ver] = run(rotated[ver], sources[kind], obj, 8 if kind in ("rare", "short") else 1)
                    value = digest(obj)
                    assert objects.setdefault(kind, value) == value, (kind, ver, value)
                if it >= 0:
                    raw[kind].append(row)
        print("Finished location rotation", phase, flush=True)
    assert objects["branches"] == "4adfb3d63922c3d460e5bde74e9fff5557101e58955621aab25263c30079936f"
    assert objects["rare"] == "1a3e796d6cd5359c708ad7e4e8e15b6db21fe0d00f19400fe803f0a0244b28a9"
    ref = json.loads((Path.cwd() / "lookup-evidence/drivers.json").read_text())
    report = {"pairs": 6 * REPEATS, "host": platform.platform(), "flags": FLAGS, "drivers": ref,
              "rare_mnemonics": distinct, "objects": objects, "sources": {k: digest(p) for k, p in sources.items()},
              "samples": raw, "statistics": {}}
    for kind, rows in raw.items():
        report["statistics"][kind] = {f"{test}_vs_{base}": summarize(rows, test, base)
                                      for test in ("r14", "rebuilt", "binary", "early", "set")
                                      for base in ("r13", "r14", "rebuilt", "binary", "early")
                                      if list(exes).index(base) < list(exes).index(test)}
    write(evidence / "timings.json", report)
    traces = {}
    for kind, source in sources.items():
        traces[kind] = {}
        for ver, exe in exes.items():
            trace = work / "callgrind.out"
            subprocess.run(["valgrind", "--tool=callgrind", "--callgrind-out-file=" + str(trace),
                            exe, *FLAGS, source, "-o", obj], check=True, stderr=subprocess.DEVNULL)
            value = digest(obj)
            assert objects.setdefault(kind, value) == value, (kind, ver, value)
            traces[kind][ver], = [int(line.split()[1]) for line in trace.read_text().splitlines()
                                  if line.startswith("summary:")]
            with trace.open("rb") as plain, gzip.open(evidence / (kind + "-" + ver + ".callgrind.gz"), "wb") as out:
                shutil.copyfileobj(plain, out)
        write(evidence / "instructions.json", {"absolute": traces, "objects": objects})
    write(evidence / "instructions.json", {"absolute": traces, "objects": objects,
          "empty_subtracted": {k: {v: count - traces["empty"][v] for v, count in counts.items()}
                               for k, counts in traces.items() if k != "empty"}})


if __name__ == "__main__":
    main()

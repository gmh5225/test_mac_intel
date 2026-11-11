"""Compare the native alias recognizers in full release libraries."""
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess as sp
from tempfile import TemporaryDirectory

import corpus
import run

SOURCE = run.SOURCE
CASES_FOR_COUNTS = ("arm64-ls", "ppc64el-ls", "mips64el-ls", "sparc64-ls", "putty-32-0.85")


def sample(binary, case, mode, repeats):
    args = [binary, case["selector"], run.MODES[mode], case["path"], repeats]
    return json.loads(sp.check_output(list(map(str, args))))


def main(root):
    run.WORK = root
    revision = "5b9cbe48b46842e70a4ce8dcfafcb3f35c2f34cd"
    source = run.fetch("capstone", "https://github.com/NeverSight/capstone.git", revision)
    cases = corpus.prepare(SOURCE, root, run.EVIDENCE, run.command)
    run.command(["clang", "--version"], "compiler")
    linux = platform.system() == "Linux"
    run.command(["lscpu", "--json"] if linux else ["sysctl","machdep.cpu.brand_string","hw.ncpu"], "cpu")
    # Consume the alias ID explicitly as well as the standard formatted text and detail.
    consumer = (SOURCE / "single.cpp").read_text()
    key = "      if (mode) {\n        text_value(result, insn->mnemonic);"
    assert consumer.count(key) == 1
    consumer = consumer.replace(key, "      if (mode) {\n        result.values += insn->alias_id;\n        text_value(result, insn->mnemonic);")
    (root / "consumer.cpp").write_text(consumer)
    run.command(["clang++","-std=c++17","-O3","-DNDEBUG","-I",source/"include","-c",root/"consumer.cpp","-o",root/"consumer.o"], "consumer")
    build = root/"build"
    run.command(["cmake","-S",source,"-B",build,"-G","Ninja","-DCMAKE_BUILD_TYPE=Release","-DCMAKE_C_COMPILER=clang",
                 "-DCAPSTONE_BUILD_MACOS_THIN=ON","-DCAPSTONE_BUILD_CSTOOL=OFF","-DCAPSTONE_BUILD_LEGACY_TESTS=OFF",
                 "-DCAPSTONE_BUILD_SHARED_LIBS=OFF"],"configure")
    bins = {}
    for variant in ("base","trie"):
        if variant == "trie":
            patch = SOURCE / "alias-trie.patch"
            assert run.sha(patch) == (SOURCE/"alias-trie.sha256").read_text().strip()
            run.command(["git","apply","--check",patch],"check",source)
            run.command(["git","apply",patch],"apply",source)
            run.command(["python3",source/"suite/synctools/alias_mnemonic_trie.py","--check"],"generated")
        run.command(["cmake","--build",build,"--target","capstone_static","--parallel","4"],"build-"+variant)
        exe = root / ("bench-"+variant)
        run.command(["clang++",root/"consumer.o",build/"libcapstone.a","-o",exe],"link-"+variant)
        bins[variant] = exe
    bins["control"] = bins["base"]
    if linux:
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    run.write("inputs.json", dict(revision=revision,patch=run.sha(SOURCE/"alias-trie.patch"),
                                  cpu_affinity=sorted(os.sched_getaffinity(0)) if linux else None,
                                  binaries={n:run.sha(p) for n,p in bins.items()}))
    results = []
    for case in cases:
        for mode in (("scan","format","detail") if case["selector"] >= 16 else ("format","detail")):
            first = [sample(exe,case,mode,1) for exe in (bins["base"],bins["trie"])]
            assert first[0]["first"] == first[1]["first"], (case["name"],mode,first)
            repeats = max(1,min(12000,math.ceil(50e6/max(1,min(v["cpu_ns"] for v in first)))))
            cycles = []
            variants = list(bins)
            expected = None
            for i in range(6):
                order = variants[i%3:] + variants[:i%3]
                if i>=3:
                    order.reverse()
                cycle = {}
                for v in order:
                    row = sample(bins[v],case,mode,repeats)
                    if expected is None:
                        expected = row["result"]
                    assert row["result"] == expected and row["first"] == first[0]["first"]
                    cycle[v] = row
                cycles.append(cycle)
                with (run.EVIDENCE/"cycles.jsonl").open("a") as output:
                    output.write(json.dumps(dict(case=case["name"],mode=mode,cycle=i,samples=cycle))+"\n")
            def ratio(which):
                return statistics.median((c["base"]["cpu_ns"] + c["control"]["cpu_ns"])/2/c[which]["cpu_ns"]
                                         if which == "trie" else c["base"]["cpu_ns"]/c["control"]["cpu_ns"]
                                         for c in cycles)
            results.append(dict(case=case["name"],mode=mode,ratio=ratio("trie"),control=ratio("control"),first=first[0]["first"]))
            run.write("measurements.json",results)
    counts = []
    if linux:
        for case in cases:
            if case["name"] not in CASES_FOR_COUNTS:
                continue
            for variant in ("base","trie"):
                label = case["name"]+"-"+variant
                path = root/"callgrind.out"
                run.command(["valgrind","--tool=callgrind","--branch-sim=yes","--callgrind-out-file="+str(path),
                            bins[variant],case["selector"],2,case["path"],1],label)
                data = path.read_text()
                events = next(l for l in data.splitlines() if l.startswith("events:")).split()[1:]
                totals = next(l for l in data.splitlines() if l.startswith("totals:")).split()[1:]
                counts.append(dict(case=case["name"],variant=variant,events=dict(zip(events,map(int,totals)))))
                run.command(["callgrind_annotate","--auto=no","--threshold=99",path],label+"-functions")
                path.unlink()
        run.write("counts.json",counts)


if __name__ == "__main__":
    run.EVIDENCE.mkdir(exist_ok=True)
    with TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as tmp:
        root = Path(tmp)
        try:
            main(root)
        finally:
            size = sum(f.stat().st_size for f in root.rglob("*") if f.is_file())
            shutil.rmtree(root)
            run.write("cleanup.json",dict(removed=not root.exists(),bytes=size))

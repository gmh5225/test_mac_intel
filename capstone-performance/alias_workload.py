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
    revision = "8cc7c945ad66d65aa4fcd4451ad85416c9e5a028"
    source = run.fetch("capstone", "https://github.com/NeverSight/capstone.git", revision)
    cases = corpus.prepare(SOURCE, root, run.EVIDENCE, run.command)
    arch_for = {"arm64":"AARCH64","arm":"ARM","thumb":"ARM"}
    plan = os.environ["ARCH_PLAN"].split(",")
    cases = [c for c in cases if arch_for.get(c["name"].split("-")[0]) in plan]
    assert {arch_for[c["name"].split("-")[0]] for c in cases} == set(plan)
    flags = ["-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF", *["-DCAPSTONE_"+a+"_SUPPORT=ON" for a in plan]]
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
    run.command(["cmake","-S",source,"-B",build,"-G","Ninja",*flags,"-DCMAKE_BUILD_TYPE=Release","-DCMAKE_C_COMPILER=clang",
                 "-DCAPSTONE_BUILD_MACOS_THIN=ON","-DCAPSTONE_BUILD_CSTOOL=OFF","-DCAPSTONE_BUILD_LEGACY_TESTS=OFF",
                 "-DCAPSTONE_BUILD_SHARED_LIBS=OFF"],"configure")
    bins = {}
    for variant in ("base","trie"):
        if variant == "trie":
            patch = SOURCE / "alias-trie.patch"
            assert run.sha(patch) == (SOURCE/"alias-trie.sha256").read_text().strip()
            run.command(["git","apply","--check",patch],"check",source)
            run.command(["git","apply",patch],"apply",source)
            changed = sp.check_output(["git", "diff", "--name-only", "HEAD"], cwd=source, text=True).splitlines()
            assert changed == ['arch/AArch64/AArch64InstPrinter.c', 'suite/auto-sync/src/autosync/cpptranslator/Tests/test_patches.py', 'suite/auto-sync/src/autosync/cpptranslator/patches/StreamOperation.py'], changed
        run.command(["cmake","--build",build,"--target","capstone_static","--parallel","4"],"build-"+variant)
        exe = root / ("bench-"+variant)
        run.command(["clang++",root/"consumer.o",build/"libcapstone.a","-o",exe],"link-"+variant)
        bins[variant] = exe
    assert run.sha(bins["base"]) != run.sha(bins["trie"])
    bins["control"] = bins["base"]
    bins["trie-control"] = bins["trie"]
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
            repeats = max(1,min(12000,math.ceil(160e6/max(1,min(v["cpu_ns"] for v in first)))))
            cycles = []
            variants = list(bins)
            expected = None
            for i in range(12):
                order = variants[i%4:] + variants[:i%4]
                if (i//4)%2:
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
                return statistics.median((c["base"]["cpu_ns"] + c["control"]["cpu_ns"])/(c["trie"]["cpu_ns"] + c["trie-control"]["cpu_ns"])
                                         if which == "trie" else c["base"]["cpu_ns"]/c["control"]["cpu_ns"]
                                         for c in cycles)
            results.append(dict(case=case["name"],mode=mode,ratio=ratio("trie"),control=ratio("control"),trie_control=statistics.median(c["trie"]["cpu_ns"]/c["trie-control"]["cpu_ns"] for c in cycles),first=first[0]["first"]))
            run.write("measurements.json",results)


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

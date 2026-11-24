"""Compare LLVM MIPS disassembly on identical arithmetic functions on each host."""
import argparse
import collections
import hashlib
import json
import os
import platform
from pathlib import Path
import random
import shutil
import statistics
import subprocess

BASE = "0f9776402d2f3aed5daf50e58cdcb820690517cc"
HEAD = "1c37d515ef3b12e8923390f95dc49052a966f00f"
WINDOWS = os.name == "nt"
SUFFIX = ".exe" if WINDOWS else ""
ROUNDS = 24


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(source, work):
    build_dir = work / "build"
    compiler = ["-DCMAKE_C_COMPILER=clang-cl", "-DCMAKE_CXX_COMPILER=clang-cl"] if WINDOWS else [
        "-DCMAKE_C_COMPILER=clang", "-DCMAKE_CXX_COMPILER=clang++"]
    if platform.system() == "Linux":
        compiler.append("-DLLVM_USE_LINKER=lld")
    run("cmake", "-S", source/"llvm", "-B", build_dir, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
        "-DLLVM_TARGETS_TO_BUILD=Mips", "-DLLVM_ENABLE_ASSERTIONS=ON", "-DLLVM_ENABLE_RTTI=ON",
        "-DLLVM_INCLUDE_TESTS=OFF", "-DLLVM_INCLUDE_BENCHMARKS=OFF",
        "-DLLVM_ENABLE_ZSTD=OFF", "-DLLVM_ENABLE_ZLIB=OFF", "-DLLVM_ENABLE_LIBXML2=OFF", *compiler)
    bins = build_dir/"bin"
    def revision():
        return subprocess.check_output(["git", "-C", source, "rev-parse", "HEAD"], text=True).strip()
    assert revision() == BASE
    run("cmake", "--build", build_dir, "--target", "llvm-objdump", "--parallel", "4")
    baseline = work/("r9-objdump"+SUFFIX)
    shutil.copy2(bins/("llvm-objdump"+SUFFIX), baseline)
    run("git", "-C", source, "fetch", "--depth=1", "origin", HEAD)
    run("git", "-C", source, "checkout", "--detach", HEAD)
    assert revision() == HEAD
    run("cmake", "--build", build_dir, "--target", "llc", "llvm-mc", "llvm-objdump", "--parallel", "4")
    return bins, baseline


def make_inputs(bins, work):
    cases = []
    for little in (False, True):
        suffix = "le" if little else "be"
        triple = "mipsel" if little else "mips"
        obj = work/("micro-o32-"+suffix+".o")
        ir = obj.with_suffix(".ll")
        ir.write_text("\n".join(
            f"define i32 @work_{i}(i32 %x, i32 %y) {{\n  %a = add i32 %x, {i*13+7}\n"
            f"  %b = xor i32 %a, %y\n  %c = lshr i32 %b, {i%13+1}\n"
            "  %d = add i32 %c, %y\n  ret i32 %d\n}" for i in range(160))+"\n")
        run(bins/("llc"+SUFFIX), "-mtriple="+triple+"-unknown-linux-gnu", "-target-abi=o32",
            "-mcpu=mips32r2", "-mattr=+micromips,+noabicalls", "-relocation-model=static",
            "-function-sections", "-filetype=obj", ir.name, "-o", obj.name, cwd=work)
        cases.append(obj)
        obj = work/("r6-word-"+suffix+".o")
        asm = obj.with_suffix(".s")
        asm.write_text(".set noreorder\n.set micromips\n.text\n"+"\n".join(
            f".globl f{i}\n.ent f{i}\nf{i}:\naddu $2,$4,$5\nxor $2,$2,$5\n"
            f"or $2,$2,$4\njrc16 $ra\n.end f{i}" for i in range(160))+"\n")
        run(bins/("llvm-mc"+SUFFIX), "-triple="+("mips64el" if little else "mips64"),
            "-mcpu=mips64r6", "-mattr=+micromips", "-filetype=obj", asm.name, "-o", obj.name, cwd=work)
        cases.append(obj)
    return sorted(cases)


def cpu_time_ms(command):
    if WINDOWS:
        import ctypes
        from ctypes import wintypes
        times = [wintypes.FILETIME() for _ in range(4)]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        get_times = kernel.GetProcessTimes
        get_times.argtypes = [wintypes.HANDLE]+[ctypes.POINTER(wintypes.FILETIME)]*4
        get_times.restype = wintypes.BOOL
        with subprocess.Popen(command, stdout=subprocess.DEVNULL) as process:
            assert process.wait() == 0
            if not get_times(int(process._handle), *(ctypes.byref(t) for t in times)):
                raise ctypes.WinError(ctypes.get_last_error())
        return sum((t.dwHighDateTime << 32) + t.dwLowDateTime for t in times[2:]) / 10_000
    import resource
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    run(*command, stdout=subprocess.DEVNULL)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return 1000*((after.ru_utime-before.ru_utime)+(after.ru_stime-before.ru_stime))


def measure(bins, baseline, work, output):
    cases = make_inputs(bins, work)
    exe = {"r9":baseline, "candidate":bins/("llvm-objdump"+SUFFIX)}
    report = {"host":platform.platform(), "base":BASE, "head":HEAD, "rounds":ROUNDS,
              "functions_per_invocation":2560, "unit":"child CPU milliseconds",
              "program_sha256":{k:sha(p) for k,p in exe.items()}, "cells":{}}
    randomize = random.Random(20261125)
    def command(leg, case):
        flags = ["--mcpu=mips64r6","--mattr=+micromips"] if case.stem.startswith("r6-") else []
        return [exe[leg], "-d", "--no-print-imm-hex", "--no-symbolize-operands", *flags]+[case]*16
    for case in cases:
        raw = {leg:subprocess.check_output(command(leg,case)) for leg in exe}
        a,b = [raw[leg].splitlines() for leg in exe]
        assert len(a)==len(b) and all(b"<unknown>" not in v for v in raw.values())
        changed = collections.Counter()
        for old,new in zip(a,b):
            if old == new: continue
            op = new.split(b"\t")[1].decode()
            assert op in {"addiu","addiur2","addius5","srl","srl16"} and old.startswith(new+b" <") and old.endswith(b">")
            changed[op] += 1
        report["cells"][case.stem] = {"input_sha256":sha(case), "samples":[],
                                      "removed_nonbranch_annotations":dict(changed),
                                      "output_sha256":{leg:hashlib.sha256(v).hexdigest() for leg,v in raw.items()}}
    for round_index in range(ROUNDS):
        order = cases.copy()
        randomize.shuffle(order)
        for case in order:
            legs = ["r9","candidate"] if (round_index+cases.index(case))%2==0 else ["candidate","r9"]
            times = {leg:cpu_time_ms(command(leg,case)) for leg in legs}
            assert min(times.values()) > 0
            report["cells"][case.stem]["samples"].append(times)
    for name, cell in report["cells"].items():
        ratios = [sample["candidate"]/sample["r9"] for sample in cell["samples"]]
        cell["paired_median_ratio"] = statistics.median(ratios)
        estimates = sorted(statistics.median(randomize.choices(ratios,k=ROUNDS)) for _ in range(5000))
        cell["resampled_95_percent_median_ratio"] = [estimates[125],estimates[4874]]
        print(name, cell["paired_median_ratio"], cell["resampled_95_percent_median_ratio"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2)+"\n")


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--bins", type=Path)
    parser.add_argument("--baseline", type=Path)
    args=parser.parse_args()
    work=args.work.resolve();work.mkdir(parents=True,exist_ok=True)
    bins,baseline=build(args.source.resolve(),work) if args.source else (args.bins.resolve(),args.baseline.resolve())
    measure(bins,baseline,work,args.output)

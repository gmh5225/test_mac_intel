"""Time equivalent r14/r15 assembler, code generator and ELF linker workloads."""
import argparse
import hashlib
import json
import platform
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from elftools.elf.elffile import ELFFile

if sys.platform == "win32":
    from neverd_windows_child_cpu import child_cpu
else:
    import resource

    def child_cpu():
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        return usage.ru_utime + usage.ru_stime


def measure(command, invocations=1):
    cpu, wall = child_cpu(), time.perf_counter()
    for _ in range(invocations):
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, timeout=120)
    elapsed, used = time.perf_counter() - wall, child_cpu() - cpu
    return {"wall": elapsed / invocations, "cpu": used / invocations,
            "wall_batch": elapsed, "cpu_batch": used}


def signature(file):
    with file.open("rb") as data:
        elf = ELFFile(data)
        if elf["e_type"] == "ET_REL":
            return [[s.name, hashlib.sha256(s.data()).hexdigest()] for s in elf.iter_sections() if s["sh_flags"] & 2]
        return [[s["p_flags"], s["p_vaddr"], s["p_memsz"], hashlib.sha256(s.data()).hexdigest()]
                for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]


def summary(samples, key):
    ratios = [(row["r15"][key] / row["r14"][key] - 1) * 100 for row in samples]
    rng = random.Random(7714)
    bootstrap = sorted(statistics.median(rng.choices(ratios, k=len(ratios))) for _ in range(6000))
    return {"median_pct": statistics.median(ratios), "ci95_pct": [bootstrap[149], bootstrap[5849]]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--rounds", type=int, default=32)
    args = parser.parse_args()
    bins = {"r14": args.old.resolve(), "r15": args.new.resolve()}
    refs = {"r14": "6c769154fbe9db2fe9e2e2dc1b04bebfe64e1312", "r15": "54143a8d7c037ee4c22f1f238bd4d50ca9a5fd00"}
    def tool(label, name):
        return bins[label] / (name + (".exe" if sys.platform == "win32" else ""))
    for label, ref in refs.items():
        assert ref in subprocess.check_output([tool(label, "ld.lld"), "--version"], text=True)
    data = {"platform": platform.platform(), "sources": refs, "rounds": args.rounds, "cases": {}}
    with TemporaryDirectory(prefix="mips-compiler-") as scratch:
        tmp = Path(scratch)
        ir, branches = tmp / "functions.ll", tmp / "branches.s"
        ir.write_text("".join(f"define i32 @f{i}(i32 %a, i32 %b) nounwind {{\n %x = xor i32 %a, {i&127}\n %y = add i32 %x, %b\n ret i32 %y\n}}\n"
                              for i in range(768)))
        branches.write_text(".set noreorder\n.text\n" + "".join(f".Lhead{i}:\n addiu $3, $3, 17\n bne $3, $4, .Lhead{i}\n nop\n" for i in range(32768)))
        commands = {}
        for label in bins:
            for triple, abi, cpu, isa in [("mips","o32","mips32r2","mips16"), ("mips64el","n32","mips64r2","micromips")]:
                commands.setdefault("llc-" + isa + "-" + abi, {})[label] = [tool(label,"llc"), "-mtriple="+triple, "-mcpu="+cpu,
                    "-target-abi="+abi, "-mattr=+"+isa+",+noabicalls", "-filetype=obj", ir]
            commands.setdefault("mc-classic-local-branches", {})[label] = [tool(label,"llvm-mc"), "-triple=mipsel", "-mcpu=mips32r2", "-filetype=obj", branches]
        for abi, triple, cpu, directive in [("o32","mips","mips32r2",".4byte"), ("n64","mips64el","mips64r2",".8byte")]:
            source, obj = tmp/(abi+".s"), tmp/(abi+".o")
            source.write_text(".text\n.set noreorder\n.globl f0\nf0:\n jr $ra\n nop\n.data\n.rept 98304\n "+directive+" f0\n.endr\n")
            measure([tool("r14","llvm-mc"), "-triple="+triple, "-mcpu="+cpu,"-target-abi="+abi,"-filetype=obj",source,"-o",obj])
            commands["lld-96k-"+abi] = {label:[tool(label,"ld.lld"),"--threads=1","-static","-e","f0",obj] for label in bins}
        output = tmp/"result"
        for case, variants in commands.items():
            # A single small LLD process can fall below the Windows job CPU clock tick.
            invocations = 32 if sys.platform == "win32" and case.startswith("lld-") else 1
            fingerprints = []
            for command in variants.values():
                measure([*command, "-o", output])
                fingerprints.append(signature(output))
            assert fingerprints[0] and fingerprints[0] == fingerprints[1], case
            samples = []
            for round_id in range(args.rounds):
                order = ("r14","r15") if round_id % 2 == 0 else ("r15","r14")
                samples.append({label:measure([*variants[label], "-o", output], invocations) for label in order})
            assert all(sample[tag]["cpu_batch"] > 0 for sample in samples for tag in bins), case
            data["cases"][case] = {"cpu":summary(samples,"cpu"), "wall":summary(samples,"wall"),
                                   "samples":samples, "output":fingerprints[0], "invocations_per_sample":invocations}
            print(case, data["cases"][case]["cpu"], data["cases"][case]["wall"], flush=True)
    args.receipt.write_text(json.dumps(data, indent=2)+"\n")


if __name__ == "__main__":
    main()

"""Measure both public modes on identical partially linked r14 originals."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

from neverd_mips_compiler_pairs import child_cpu, signature

REVISIONS = {"r14": "6c769154fbe9db2fe9e2e2dc1b04bebfe64e1312",
             "r15": "54143a8d7c037ee4c22f1f238bd4d50ca9a5fd00"}


def run(argv, env=None):
    subprocess.run(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                   check=True, timeout=60)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def paired(rows, metric):
    groups = [[100 * (r["r15"][metric] / r["r14"][metric] - 1) for r in rows if r["phase"] == phase]
              for phase in (0, 1)]
    rng = random.Random(73914)
    median = statistics.median
    boot = sorted(median(sum((rng.choices(g, k=len(g)) for g in groups), [])) for _ in range(6000))
    return {"median_pct": median(groups[0] + groups[1]), "ci95_pct": [boot[149], boot[5849]],
            "by_location": list(map(median, groups))}


def main():
    parser = argparse.ArgumentParser()
    for name in ("project", "old_dir", "new_dir", "receipt"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--rounds", type=int, default=16, help="paired trials per linker location")
    parser.add_argument("--cli", type=Path, help="use a separate CLI for a local diagnostic run")
    parser.add_argument("--pic", action="store_true", help="use a PIC callee in the partially linked input")
    args = parser.parse_args()
    assert args.rounds > 0 and args.rounds % 4 == 0
    project = args.project.resolve()
    sys.path.insert(0, str(project / "scripts"))
    import check_mips_elf_relink as m

    suffix = ".exe" if os.name == "nt" else ""
    def tools(folder):
        return SimpleNamespace(**{key: folder.resolve() / (name + suffix)
                                  for key, name in [("mc", "llvm-mc"), ("llc", "llc"), ("lld", "ld.lld")]})
    old, new = tools(args.old_dir), tools(args.new_dir)
    linkers = {"r14": old.lld, "r15": new.lld}
    for version, linker in linkers.items():
        assert REVISIONS[version] in subprocess.check_output([linker, "--version"], text=True)
    cli = args.cli.resolve() if args.cli else args.new_dir.resolve() / ("neverd" + suffix)
    env = os.environ.copy()
    env["PATH"] = str(cli.parent) + os.pathsep + env["PATH"]
    if os.name != "nt":
        env["DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"] = str(cli.parent)
    if not args.cli:
        stage = json.loads((args.new_dir / "source.json").read_bytes())
        assert stage["llvm"] == REVISIONS["r15"] and stage["files"][cli.name] == digest(cli)
    records, programs, reference = {}, {}, {}
    rows = {mode: [] for mode in m.MODES}
    rng = random.Random(2911051)
    with tempfile.TemporaryDirectory(prefix="mips-partial-pairs-") as temp:
        root = Path(temp)
        for profile in m.profiles(1):
            d = root / profile.name
            d.mkdir()
            inputs = d / "combined"
            inputs.mkdir()
            model = "pic" if args.pic else "static"
            assert m.build_upgrade_objects(old, new, d, inputs, profile, model) == ["calc.o"]
            obj = {name: m.verify_partial_object(inputs / name, profile) for name in ("calc.o", "updated.o")}
            staged = d / "direct-input"
            staged.mkdir()
            shutil.copy2(d / "updated.o", staged / "calc.o")
            for separate, name in ((False, "base.ld"), (True, "section.ld")):
                m.write(d / name, m.layout(profile, separate))
            m.encode(d / "manifest.json", dict(objects=["calc.o"], original="calc.o", replacement="updated.o",
                     function="calc", layout="base.ld", section=".calc.update", sectionLayout="section.ld"))
            original = d / "original.elf"
            run([old.lld, "-static", "-T", d / "base.ld", "-o", original, d / "calc.o"])
            if args.pic:
                from elftools.elf.elffile import ELFFile
                with original.open("rb") as stream:
                    m.inspect_elf(ELFFile(stream), profile, require_pic_marker=True)
            signatures = {"original": signature(original)}
            reference[profile.name] = {}
            for mode in m.MODES:
                path = d / "ref.elf"
                script = d / ("section.ld" if mode == "section" else "base.ld")
                reference[profile.name][mode] = {}
                for ver, linker in linkers.items():
                    run([linker, "-static", "-T", script, "-o", path, staged / "calc.o"])
                    reference[profile.name][mode][ver] = digest(path)
                    mapped = signature(path)
                    assert signatures.setdefault(mode, mapped) == mapped
            records[profile.name] = d
            programs[profile.name] = {"inputs": obj, "original": digest(original), "mapped": signatures}
        for phase in (0, 1):
            slots = {}
            for i, (ver, linker) in enumerate(linkers.items()):
                slot = root / ("slot-" + str((i + phase) % 2))
                slot.mkdir(exist_ok=True)
                slots[ver] = slot / ("ld.lld" + suffix)
                shutil.copy2(linker, slots[ver])
                assert digest(slots[ver]) == digest(linker)
            schedule = []
            for _ in range(args.rounds // 4):
                block = [(order, rev) for order in [("r14", "r15"), ("r15", "r14")] for rev in [False, True]]
                rng.shuffle(block)
                schedule.extend(block)
            for index, (order, reverse_modes) in enumerate([(("r14", "r15"), False), *schedule]):
                for mode in (reversed(m.MODES) if reverse_modes else m.MODES):
                    row = {"phase": phase, "order": order, "reverse_modes": reverse_modes}
                    for ver in order:
                        cpu, wall = child_cpu(), time.perf_counter()
                        for d in records.values():
                            run([cli, "patch", d / "original.elf", "--relink=" + str(d / "manifest.json"),
                                 "--mode=" + mode, "--original-linker-path=" + str(old.lld),
                                 "--linker-path=" + str(slots[ver]), "-o", d / "updated.elf"], env=env)
                        row[ver] = {"cpu": child_cpu() - cpu, "wall": time.perf_counter() - wall}
                        for name, d in records.items():
                            assert digest(d / "updated.elf") == reference[name][mode][ver], (phase, mode, ver, name)
                    if index:
                        rows[mode].append(row)
    report = {"sources": REVISIONS, "model": "pic" if args.pic else "static",
              "cli_sha256": digest(cli), "host": platform.platform(), "programs": programs,
              "raw_oracles": reference, "linkers": {k: digest(v) for k, v in linkers.items()}, "pairs": 2 * args.rounds,
              "samples": rows, "result": {mode: {metric: paired(values, metric) for metric in ("cpu", "wall")}
                                          for mode, values in rows.items()}}
    args.receipt.write_text(json.dumps(report, indent=2) + "\n")
    print(report["result"], flush=True)


if __name__ == "__main__":
    main()

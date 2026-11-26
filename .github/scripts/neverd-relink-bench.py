"""Paired Release benchmark of the last and proposed MIPS toolchains."""

import hashlib
import json
import platform
import random
import statistics as stats
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter
from types import SimpleNamespace

from elftools.elf.elffile import ELFFile

if sys.platform == "win32":
    from neverd_windows_child_cpu import child_cpu
else:
    import resource

p = Path(__file__).resolve().parent
repo = p.parent.parent
sys.path.insert(0, str(repo / "scripts"))
import check_mips_elf_relink as m

windows = sys.platform == "win32"
suffix = ".exe" if windows else ""
locations = [Path(arg).resolve() for arg in sys.argv[3:5]]
if not locations:
    locations = [p / "r12-bin", p / "r13-bin"]
toolchains = dict(zip(("r12", "r13"), locations, strict=True))
cli = p.parent / "bin" / ("neverd" + suffix)
rng = random.Random(20261126)
rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 32
receipt = sys.argv[2] if len(sys.argv) > 2 else "perf.json"


def run(argv):
    subprocess.run(
        list(map(str, argv)),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=True,
        timeout=60,
    )


def guest_hash(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        image = ELFFile(source)
        for seg in image.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                h.update(str((seg["p_vaddr"], seg["p_flags"], seg["p_memsz"])).encode())
                h.update(seg.data())
    return h.hexdigest()


def cpu():
    if windows:
        return child_cpu()
    t = resource.getrusage(resource.RUSAGE_CHILDREN)
    return t.ru_stime + t.ru_utime


def measure(commands):
    w, t = perf_counter(), cpu()
    for cmd in commands:
        run(cmd)
    return dict(wall=perf_counter() - w, cpu=cpu() - t)


def report(rows):
    result = {}
    for key in ("cpu", "wall"):
        ratios = [(r["r13"][key] / r["r12"][key] - 1) * 100 for r in rows]
        estimates = sorted(
            stats.median(rng.choices(ratios, k=len(ratios))) for _ in range(6000)
        )
        result[key] = {
            "r12_s": stats.median(r["r12"][key] for r in rows),
            "r13_s": stats.median(r["r13"][key] for r in rows),
            "paired_pct": stats.median(ratios),
            "median_95_pct": [estimates[149], estimates[5849]],
            "iqr_pct": [stats.quantiles(ratios)[0], stats.quantiles(ratios)[2]],
        }
    return result


with TemporaryDirectory(prefix="paired-mips-", dir=p) as tmp:
    base = Path(tmp)
    matrix = [
        m.Profile("o32", True, "mips16", shrinking=True, compressed_entry=True),
        m.Profile("n64", True, "micromips", 3, shrinking=True, compressed_entry=True),
        m.Profile("n32", False, historical_isa=5, shrinking=True),
        m.Profile("o32", False),
        m.Profile("n64", False, "classic", 6, linkage="tls"),
        m.Profile("n32", True, "micromips", 2, linkage="pic-soft"),
        m.Profile("o32", True, "classic", 2, linkage="pic-hard"),
        m.Profile("n64", True, "classic", 5, linkage="msa"),
    ]
    public_kinds = m.MODES if windows else ("public",)
    kinds = (*public_kinds, "many-relocations", "codegen")
    commands = {k: {label: [] for label in toolchains} for k in kinds}
    know = {}
    for pf in matrix:
        folder = base / pf.name
        folder.mkdir()
        old = toolchains["r12"]
        args = SimpleNamespace(mc=old / ("llvm-mc" + suffix), llc=old / ("llc" + suffix))
        objects = (
            m.build_linkage_objects(args, folder, pf, m.run)
            if pf.linkage
            else m.build_arithmetic_objects(args, folder, pf)
        )
        for separate, file in ((False, "base.ld"), (True, "section.ld")):
            m.write(folder / file, m.layout(pf, separate))
        m.encode(
            folder / "manifest.json",
            dict(
                objects=objects,
                original="calc.o",
                replacement="updated.o",
                function="calc",
                layout="base.ld",
                sectionLayout="section.ld",
                section=".calc.update",
            ),
        )
        for label, tools in toolchains.items():
            driver = tools / ("ld.lld" + suffix)
            original = folder / (label + ".elf")
            run(
                [
                    driver,
                    "-static",
                    "-T",
                    folder / "base.ld",
                    "-o",
                    original,
                    *[folder / o for o in objects],
                ]
            )
            hashes = [guest_hash(original)]
            for mode in m.MODES:
                output = folder / (label + mode + ".elf")
                cmd = [
                    cli,
                    "patch",
                    original,
                    f"--relink={folder}/manifest.json",
                    f"--linker-path={driver}",
                    f"--mode={mode}",
                    "-o",
                    output,
                ]
                run(cmd)
                hashes.append(guest_hash(output))
                commands[mode if windows else "public"][label].append(cmd)
            if pf.name in know:
                assert know[pf.name] == hashes, pf.name
            know[pf.name] = hashes
            ir = folder / "input.ll"
            m.write(ir, m.calculator(m.Profile(pf.abi, pf.little), True))
            features = "+noabicalls" + ("" if pf.isa == "classic" else ",+" + pf.isa)
            commands["codegen"][label].append(
                [
                    tools / ("llc" + suffix),
                    "-filetype=obj",
                    f"-mtriple={pf.triple}",
                    f"-mcpu={pf.cpu}",
                    f"-target-abi={pf.abi}",
                    f"-mattr={features}",
                    "-o",
                    folder / (label + ".o"),
                    ir,
                ]
            )
    # MIPS linkers scan a large relocation table from a generated callback registry.
    for little in (False, True):
        pf = m.Profile("o32", little)
        folder = base / ("many-" + pf.name)
        folder.mkdir()
        m.run(
            [
                old / ("llvm-mc" + suffix),
                "-filetype=obj",
                "-mcpu=mips32r2",
                "-target-abi=o32",
                f"-triple={pf.triple}",
                "-mattr=+noabicalls",
                "-o",
                folder / "table.o",
                "-",
            ],
            source=".data\n.rept 65536\n.word calc\n.endr\n",
        )
        m.run(
            [
                old / ("llvm-mc" + suffix),
                "-filetype=obj",
                "-mcpu=mips32r2",
                "-target-abi=o32",
                f"-triple={pf.triple}",
                "-mattr=+noabicalls",
                "-o",
                folder / "code.o",
                "-",
            ],
            source=".set noreorder\n.text\n.globl calc\n.ent calc\ncalc:\njr $ra\nnop\n.end calc\n",
        )
        for label, tools in toolchains.items():
            output = folder / (label + ".elf")
            cmd = [
                tools / ("ld.lld" + suffix),
                "-static",
                "-e",
                "calc",
                folder / "code.o",
                folder / "table.o",
                "-o",
                output,
            ]
            run(cmd)
            commands["many-relocations"][label].append(cmd)
            key = "many-" + pf.name
            h = guest_hash(output)
            if key in know:
                assert know[key] == h
            know[key] = h
    if windows:
        kinds = public_kinds
    rows = {k: [] for k in kinds}
    for k in kinds:
        for label in toolchains:
            measure(commands[k][label])
    for idx in range(rounds):
        for k in kinds:
            row = {}
            order = list(toolchains)
            if idx % 2:
                order.reverse()
            for label in order:
                row[label] = measure(commands[k][label])
            rows[k].append(row)
    meta = {
        label: subprocess.check_output([t / ("ld.lld" + suffix), "--version"], text=True).strip()
        for label, t in toolchains.items()
    }
    result = dict(
        revisions=meta,
        host=platform.platform(),
        cli_sha256=m.digest(cli),
        programs=know,
        cli_commands_per_trial=sum(len(commands[k]["r12"]) for k in public_kinds),
        installations={label: folder.name for label, folder in toolchains.items()},
        rounds=rounds,
        summary={k: report(v) for k, v in rows.items()},
        samples=rows,
    )
    m.encode(p / receipt, result)
    print(json.dumps(result["summary"], indent=2))

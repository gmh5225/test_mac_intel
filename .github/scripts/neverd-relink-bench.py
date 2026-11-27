"""Paired Release benchmark of the last and proposed MIPS toolchains."""

import hashlib
import json
import os
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
import check_mips_elf_relink as m  # noqa: E402

windows = sys.platform == "win32"
suffix = ".exe" if windows else ""
locations = [Path(arg).resolve() for arg in sys.argv[3:5]]
if not locations:
    locations = [p / "r12-bin", p / "r15-bin"]
toolchains = dict(zip(("r12", "r15"), locations, strict=True))
full_pair = os.environ.get("NEVERD_PAIR_FULL_INSTALLATIONS") == "1"
cli = p.parent / "bin" / ("neverd" + suffix)
clis = {label: folder / ("neverd" + suffix) if full_pair else cli for label, folder in toolchains.items()}
fixed_cli = os.environ.get("NEVERD_BENCH_FIXED_CLI")
fixed_linker = os.environ.get("NEVERD_BENCH_FIXED_LLD")
components = os.environ.get("NEVERD_BENCH_COMPONENTS") == "1"
drivers = {label: folder / ("ld.lld" + suffix) for label, folder in toolchains.items()}
if fixed_cli:
    clis = {label: clis[fixed_cli] for label in toolchains}
if fixed_linker:
    drivers = {label: drivers[fixed_linker] for label in toolchains}
cli_envs = {}
provenance = {}
for label, executable in clis.items():
    if not full_pair:
        continue
    folder = executable.parent
    record = json.loads((folder / "source.json").read_text())
    assert all(m.digest(folder / name) == value for name, value in record["files"].items())
    env = dict(os.environ)
    env["PATH"] = str(folder) + os.pathsep + env["PATH"]
    env_key = "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"
    if not windows:
        env[env_key] = str(folder)
    probe_env = env.copy()
    if sys.platform == "darwin":
        probe_env["DYLD_PRINT_LIBRARIES"] = "1"
    elif not windows:
        probe_env["LD_DEBUG"] = "libs"
    probe = subprocess.run([executable, "--version"], env=probe_env, check=True, capture_output=True, text=True)
    if not windows:
        assert any(str(folder) in line and "libneverd" in line for line in probe.stderr.splitlines())
    cli_envs[executable] = env
    provenance[label] = record
if full_pair and "neverd" in provenance["r12"]:
    assert provenance["r12"]["dependencies"] == provenance["r15"]["dependencies"]
seed = int(os.environ.get("NEVERD_BENCH_SEED", "20261126"))
rng = random.Random(seed)
rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 32
receipt = sys.argv[2] if len(sys.argv) > 2 else "perf.json"


def run(argv):
    subprocess.run(
        list(map(str, argv)),
        env=cli_envs.get(Path(argv[0])),
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
    before = resource.getrusage(resource.RUSAGE_CHILDREN) if not windows else None
    for cmd in commands:
        run(cmd)
    result = dict(wall=perf_counter() - w, cpu=cpu() - t)
    if before:
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        for field in ("ru_utime", "ru_stime", "ru_minflt", "ru_majflt", "ru_nvcsw", "ru_nivcsw"):
            result[field] = getattr(after, field) - getattr(before, field)
    return result


def report(rows):
    result = {}
    for key in ("cpu", "wall"):
        ratios = [(r["r15"][key] / r["r12"][key] - 1) * 100 for r in rows]
        estimates = sorted(
            stats.median(rng.choices(ratios, k=len(ratios))) for _ in range(6000)
        )
        result[key] = {
            "r12_s": stats.median(r["r12"][key] for r in rows),
            "r15_s": stats.median(r["r15"][key] for r in rows),
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
    public_kinds = m.MODES if windows or full_pair else ("public",)
    kinds = (*public_kinds, "many-relocations", "codegen")
    extras = ("startup", "direct-section", "direct-inplace") if components else ()
    kinds += extras
    commands = {k: {label: [] for label in toolchains} for k in kinds}
    know = {}
    raw_files = {}
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
        staged = folder / "direct-input"
        staged.mkdir()
        (staged / "calc.o").write_bytes((folder / "updated.o").read_bytes())
        raw_files[pf.name] = {}
        for label, tools in toolchains.items():
            driver = drivers[label]
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
            raw_files[pf.name][label] = {"original": m.digest(original)}
            if components:
                commands["startup"][label].append([clis[label], "--version"])
            for mode in m.MODES:
                output = folder / (label + mode + ".elf")
                cmd = [
                    clis[label],
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
                layout = folder / ("section.ld" if mode == "section" else "base.ld")
                reference = folder / (label + mode + "-direct.elf")
                replacement = [driver, "-static", "-T", layout, "-o", reference,
                               *[staged / o if o == "calc.o" else folder / o for o in objects]]
                run(replacement)
                assert output.read_bytes() == reference.read_bytes()
                raw_files[pf.name][label][mode] = m.digest(output)
                if components:
                    reproduce = [driver, "-static", "-T", folder / "base.ld", "-o",
                                 folder / (label + "-reproduced.elf"), *[folder / o for o in objects]]
                    run(reproduce)
                    assert original.read_bytes() == (folder / (label + "-reproduced.elf")).read_bytes()
                    commands["direct-" + mode][label].extend([reproduce, replacement])
                commands[mode if windows or full_pair else "public"][label].append(cmd)
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
    if os.environ.get("NEVERD_DIRECT_LINK_COST") == "1":
        import neverd_mips_direct_cost

        result = neverd_mips_direct_cost.compare(
            commands, toolchains, drivers, matrix, raw_files, know, guest_hash, rounds, seed
        )
        m.encode(p / receipt, result)
        sys.exit(0)
    if windows or full_pair:
        kinds = (*public_kinds, *extras)
    rows = {k: [] for k in kinds}
    for k in kinds:
        for label in toolchains:
            measure(commands[k][label])
    trials = []
    for offset in range(0, rounds, 4):
        block = [(False, False), (False, True), (True, False), (True, True)]
        rng.shuffle(block)
        trials.extend(block[:rounds - offset])
    for reverse_versions, reverse_modes in trials:
        for k in (reversed(kinds) if reverse_modes else kinds):
            order = list(toolchains)
            if reverse_versions:
                order.reverse()
            row = {"order": order, "reverse_modes": reverse_modes}
            for label in order:
                row[label] = measure(commands[k][label])
            rows[k].append(row)
    meta = {
        label: subprocess.check_output([driver, "--version"], text=True).strip()
        for label, driver in drivers.items()
    }
    result = dict(
        revisions=meta,
        host=platform.platform(),
        cli_sha256={label: m.digest(path) for label, path in clis.items()} if full_pair else m.digest(cli),
        sources=provenance,
        programs=know,
        raw_files=raw_files,
        distribution_files={label: json.loads((dir / "source.json").read_bytes()) for label,dir in toolchains.items()},
        driver_hashes={label:m.digest(driver) for label,driver in drivers.items()},
        configuration={"cli":fixed_cli, "linker":fixed_linker, "components":components, "seed":seed},
        cli_commands_per_trial=sum(len(commands[k]["r12"]) for k in public_kinds),
        installations={label: folder.name for label, folder in toolchains.items()},
        rounds=rounds,
        summary={k: report(v) for k, v in rows.items()},
        samples=rows,
    )
    m.encode(p / receipt, result)
    print(json.dumps(result["summary"], indent=2))

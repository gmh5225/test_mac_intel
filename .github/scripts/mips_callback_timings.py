"""Time the same macOS CLI and fixed native linkers on six callback-table programs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import resource
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace

from elftools.elf.elffile import ELFFile

PROJECT = "b8573d6c5e0066be33bb6e5e0657a25a050420b5"
FORKS = {"r12": "6947b7db63e913244e0aa6de087d1ad2e791e86f",
         "r15": "54143a8d7c037ee4c22f1f238bd4d50ca9a5fd00"}
MANIFEST = "e8a187db60921b0571ffc083dc8e354f0f91279c8a7a4117057ddff88178f69b"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def installations(archive, root):
    wanted = {"pair-installs/r12/ld.lld"}
    wanted.update("pair-installs/r15/" + name for name in
                  ("ld.lld", "llc", "llvm-mc", "neverd", "libneverd.dylib", "source.json"))
    with tarfile.open(archive, "r|gz") as tar:
        found = set()
        manifest = None
        for entry in tar:
            if entry.name == "tools.sha256":
                assert entry.isfile() and manifest is None
                manifest = tar.extractfile(entry).read()
            if entry.name in wanted:
                assert entry.isfile() and entry.name not in found
                dest = root / entry.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                with dest.open("xb") as stream:
                    shutil.copyfileobj(tar.extractfile(entry), stream)
                dest.chmod(0o755)
                found.add(entry.name)
    assert found == wanted and hashlib.sha256(manifest).hexdigest() == MANIFEST
    expected = {name: value for value, name in (line.split() for line in manifest.decode().splitlines())}
    actual = {name: digest(root / name) for name in wanted}
    assert all(value == expected[name] for name, value in actual.items())
    return actual


def segments(path):
    with path.open("rb") as stream:
        return [(dict(segment.header), hashlib.sha256(segment.data()).hexdigest())
                for segment in ELFFile(stream).iter_segments() if segment["p_type"] == "PT_LOAD"]


def replace_link(source, destination):
    destination.unlink(missing_ok=True)
    os.link(source, destination)


def cpu_ns():
    elapsed = resource.getrusage(resource.RUSAGE_CHILDREN)
    return round(1e9 * (elapsed.ru_utime + elapsed.ru_stime))


def benchmark(options, root):
    project = options.project.resolve()
    assert subprocess.check_output(["git", "-C", project, "rev-parse", "HEAD"], text=True).strip() == PROJECT
    sys.path.insert(0, str(project / "scripts"))
    import check_mips_elf_relink as m
    import mips_relink_linkage as linkage

    receipt = {"project": PROJECT, "forks": FORKS, "rounds": options.rounds,
               "seed": options.seed, "pointers": linkage.CALLBACK_COUNT,
               "tools": installations(options.archive, root), "outputs": {}, "samples": []}
    slots = root / "pair-installs"
    cli = slots / "r15" / "neverd"
    env = dict(os.environ, DYLD_LIBRARY_PATH=str(cli.parent),
               PATH=str(cli.parent) + os.pathsep + os.environ["PATH"])
    probe = subprocess.run([cli, "--version"], env=dict(env, DYLD_PRINT_LIBRARIES="1"),
                           capture_output=True, text=True, check=True)
    assert any(str(cli.parent) in line and "libneverd" in line for line in probe.stderr.splitlines())
    active = root / "ld.lld"
    for version, commit in FORKS.items():
        assert commit in subprocess.check_output([slots / version / "ld.lld", "--version"], text=True)
    tools = SimpleNamespace(llc=slots / "r15/llc", mc=slots / "r15/llvm-mc")
    cases = []
    for abi in ("o32", "n32", "n64"):
        for little in (False, True):
            profile = m.Profile(abi, little, linkage="callback-table")
            build = root / profile.name
            build.mkdir()
            objects = linkage.build_linkage_objects(tools, build, profile, m.run)
            with (build / "caller.o").open("rb") as stream:
                linkage.verify_callback_relocations(ELFFile(stream), profile)
            for file, section in (("base.ld", False), ("section.ld", True)):
                (build / file).write_text(m.layout(profile, section))
            (build / "manifest.json").write_text(json.dumps(dict(objects=objects, original="calc.o",
                replacement="updated.o", function="calc", layout="base.ld", section=".calc.update",
                sectionLayout="section.ld")))
            cases.append((profile, build, objects))

    def direct(objects, mode, updated, output):
        layout = "section.ld" if mode == "section" else "base.ld"
        names = ["updated.o" if updated and obj == "calc.o" else obj for obj in objects]
        return [active, "-static", "-T", layout, "-o", output, *names]

    def command(kind, objects, mode):
        if kind == "direct":
            return direct(objects, mode, True, "output")
        return [cli, "patch", "input", "--relink=manifest.json", "--linker-path=" + str(active),
                "--mode=" + mode, "-o", "output"]

    load_signatures = {}
    for label in FORKS:
        replace_link(slots / label / "ld.lld", active)
        for profile, build, objects in cases:
            original = "original." + label
            subprocess.run(direct(objects, "inplace", False, original), cwd=build, check=True)
            replace_link(build / original, build / "input")
            for mode in ("section", "inplace"):
                subprocess.run(direct(objects, mode, True, "reference"), cwd=build, check=True)
                subprocess.run(command("full", objects, mode), env=env, cwd=build, check=True)
                expected = digest(build / "reference")
                assert digest(build / "output") == expected
                with (build / "output").open("rb") as stream:
                    placement = m.inspect_elf(ELFFile(stream), profile)
                assert placement["section"] == (".calc.update" if mode == "section" else ".text")
                key = profile.name + "/" + mode
                loaded = segments(build / "output")
                assert load_signatures.setdefault(key, loaded) == loaded
                receipt["outputs"].setdefault(key, {})[label] = expected

    randomizer = random.Random(options.seed)
    cells = [(kind, mode, control) for kind in ("direct", "full")
             for mode in ("section", "inplace") for control in (True, False)]
    for index in range(options.rounds):
        if index % 2 == 0:
            orientations = {cell: randomizer.randrange(2) for cell in cells}
        randomizer.shuffle(cells)
        for cell in cells:
            kind, mode, control = cell
            paths = cases.copy()
            randomizer.shuffle(paths)
            sides = ["baseline", "candidate"]
            if orientations[cell] ^ (index % 2):
                sides.reverse()
            for side in sides:
                label = "r15" if control or side == "candidate" else "r12"
                replace_link(slots / label / "ld.lld", active)
                commands = []
                for _, build, objects in paths:
                    replace_link(build / ("original." + label), build / "input")
                    commands.append((build, command(kind, objects, mode)))
                start_cpu = cpu_ns()
                start = time.perf_counter_ns()
                for build, cmd in commands:
                    subprocess.run(cmd, cwd=build, env=env, check=True, stdout=subprocess.DEVNULL)
                wall = time.perf_counter_ns() - start
                cpu = cpu_ns() - start_cpu
                for profile, build, _ in paths:
                    assert digest(build / "output") == receipt["outputs"][profile.name + "/" + mode][label]
                receipt["samples"].append(dict(round=index, kind=kind, mode=mode, control=control,
                    side=side, first=sides[0], version=label, wall_ns=wall, cpu_ns=cpu))
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=Path)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--rounds", type=int, default=32)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()
    assert args.rounds > 0 and args.rounds % 2 == 0
    with tempfile.TemporaryDirectory(prefix="mips-bench-") as scratch:
        result = benchmark(args, Path(scratch).resolve())
    args.output.write_text(json.dumps(result, indent=2) + "\n")

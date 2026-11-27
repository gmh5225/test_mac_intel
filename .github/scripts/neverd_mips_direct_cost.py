"""Time native MIPS ELF links using the same input and output paths in both arms."""

import hashlib
import os
import platform
import random
import resource
import subprocess
from pathlib import Path
from time import perf_counter_ns


def timed(command, env):
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = perf_counter_ns()
    subprocess.run(command, check=True, env=env, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=45)
    elapsed = (perf_counter_ns() - start) / 1e9
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    user = after.ru_utime - before.ru_utime
    system = after.ru_stime - before.ru_stime
    return [elapsed, user + system, user, system,
            after.ru_minflt - before.ru_minflt, after.ru_majflt - before.ru_majflt]


def compare(commands, installations, drivers, profiles, raw_files, images, guest_hash, rounds, seed):
    rng = random.Random(seed)
    modes = ("section", "inplace")
    names = [p.name for p in profiles]
    normal = dict(os.environ)
    normal.pop("LLD_IN_TEST", None)
    settings = {"normal": normal, "repeat16": {**normal, "LLD_IN_TEST": "16"}}
    all_drivers = dict(drivers, r14=Path(os.environ["NEVERD_MIDDLE_DRIVER"]).resolve(),
                       copy15=Path(os.environ["NEVERD_COPY_DRIVER"]).resolve())
    info = {tag: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                  "version": subprocess.check_output([path, "--version"], text=True).strip()}
            for tag, path in all_drivers.items()}
    assert info["copy15"] == info["r15"]
    for tag, revision in [("r12", "6947b7db63e9"), ("r14", "6c769154fbe9"), ("r15", "54143a8d7c03")]:
        assert revision in info[tag]["version"]

    prepared = {}
    output_hashes = {}
    for mode_index, mode in enumerate(modes, 1):
        argv = commands["direct-" + mode]["r12"]
        assert len(argv) == 2 * len(names)
        for tag, driver in all_drivers.items():
            series = []
            for index, cmd in enumerate(argv):
                profile = names[index // 2]
                expected = mode if index % 2 else "original"
                output = Path(cmd[cmd.index("-o") + 1]).with_name("measured-" + expected + ".elf")
                args = list(cmd)
                args[0], args[args.index("-o") + 1] = driver, output
                series.append(args)
                for env in settings.values():
                    timed(args, env)
                    assert guest_hash(output) == images[profile][mode_index if index % 2 else 0]
                    digest = hashlib.sha256(output.read_bytes()).hexdigest()
                    if tag != "r14":
                        assert digest == raw_files[profile]["r15" if tag == "copy15" else tag][expected]
                    hashes = output_hashes.setdefault(profile, {}).setdefault(tag, {})
                    assert hashes.setdefault(expected, digest) == digest
            prepared[mode, tag] = series
    kinds = {
        "normal": ("r12", "r15"), "repeat16": ("r12", "r15"),
        "startup": ("r12", "r15"), "same15": ("copy15", "r15"),
        "r14-r15": ("r14", "r15"),
    }
    rows = {key: [] for key in kinds}
    assert rounds % 4 == 0
    for _ in range(rounds // 4):
        block = [(False, False), (True, False), (False, True), (True, True)]
        rng.shuffle(block)
        for flip_versions, flip_modes in block:
            schedule = list(kinds)
            rng.shuffle(schedule)
            for kind in schedule:
                tags = list(kinds[kind])
                if flip_versions:
                    tags.reverse()
                row = {"order": tags, "reverse_modes": flip_modes}
                for mode in (("startup",) if kind == "startup" else modes[::-1] if flip_modes else modes):
                    samples = {}
                    for tag in tags:
                        args = ([[all_drivers[tag], "--version"]] * (2 * len(names))
                                if mode == "startup" else prepared[mode, tag])
                        env = settings["repeat16" if kind == "repeat16" else "normal"]
                        samples[tag] = [timed(cmd, env) for cmd in args]
                    row[mode] = samples
                rows[kind].append(row)
    return {"host": platform.platform(), "drivers": info, "slot": {k: v.name for k, v in installations.items()},
            "rounds": rounds, "seed": seed, "fixture_order": names, "outputs": output_hashes,
            "programs": images, "columns": ["wall", "cpu", "user", "sys", "minflt", "majflt"],
            "within_fixture_order": ["original", "replacement"], "samples": rows}

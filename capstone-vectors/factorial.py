"""Separate payload, executable pathname, argv[0], and ASLR effects.

All file replacement and exec setup occur before the existing harness timer.
This diagnoses R1185; it is not a performance qualification or a new decoder.
"""
from pathlib import Path
import hashlib
import itertools
import json
import math
import platform
import random
import statistics
import subprocess as sp
import sys


def setup(work, executables, save):
    payload = {name: executables[name].read_bytes()
               for name in ("integer", "aa", "scan")}
    assert payload["integer"] == payload["aa"]
    assert payload["integer"] != payload["scan"]
    size = max(map(len, payload.values()))
    padded = {key: value + bytes(size - len(value))
              for key, value in payload.items()}
    folder = work / "factor"
    folder.mkdir()
    paths = {"long": folder / "run-integer", "short": folder / "run-scan"}
    for path in paths.values():
        path.write_bytes(padded["integer"])
        path.chmod(0o755)
    inodes = {key: path.stat().st_ino for key, path in paths.items()}
    argv0 = {"long": str(executables["integer"]),
             "short": str(executables["scan"])}
    launcher = work / "exec-with-argv.py"
    launcher.write_text("import os, sys\nos.execv(sys.argv[1], sys.argv[2:])\n")
    check = sp.run(["setarch", platform.machine(), "-R", "/bin/true"],
                   capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    conditions = [dict(key="/".join((code, path, label, aslr)), code=code,
                       path=path, argv0=label, aslr=aslr, kind="factorial")
                  for code, path, label, aslr in itertools.product(
                      payload, paths, argv0, ("random", "fixed"))]
    conditions += [dict(key="original/" + code, code=code, kind="original")
                   for code in payload]
    save("launch-controls.json", dict(
        conditions=conditions, original_sha256={key: hashlib.sha256(value).hexdigest()
                                              for key, value in payload.items()},
        padded_sha256={key: hashlib.sha256(value).hexdigest()
                       for key, value in padded.items()},
        paths={key: dict(path=str(path), inode=inodes[key])
               for key, path in paths.items()}, argv0=argv0, size=size,
        aslr_disable_returncode=check.returncode,
        interpretation="Full payload x pathname x argv[0] x ASLR factorial, "
                       "with byte-identical A/A payload and original launches. "
                       "Each pathname retains its inode while payloads swap."))

    def invoke(condition, tail):
        code = condition["code"]
        if condition["kind"] == "original":
            command = [str(executables[code]), *tail]
        else:
            path = paths[condition["path"]]
            with path.open("r+b") as out:
                assert out.write(padded[code]) == size
            assert path.stat().st_ino == inodes[condition["path"]]
            assert path.stat().st_size == size
            command = [sys.executable, str(launcher), str(path),
                       argv0[condition["argv0"]], *tail]
            if condition["aslr"] == "fixed":
                command = ["setarch", platform.machine(), "-R", *command]
        values = list(map(int, sp.check_output(command).split()))
        assert len(values) == 6 and values[0] > 0 and values[2] > 0
        return values

    return conditions, invoke


def measure(conditions, invoke, case, panel, mode, file, intervals, bits):
    tail = ["capstone", str(mode), "1", str(file), str(intervals), str(bits)]
    probe = invoke(conditions[0], tail)
    repeats = max(1, math.ceil(80e6 / probe[0]))
    tail[2] = str(repeats)
    cycles = []
    expected = None
    rng = random.Random("/".join(map(str, (case, panel, mode))))
    for cycle in range(21):
        order = list(conditions)
        rng.shuffle(order)
        observed = []
        for condition in order + order[::-1]:
            values = invoke(condition, tail)
            if expected is None:
                expected = values[2:]
            assert values[2:] == expected, (case, mode, condition, values, expected)
            observed.append(dict(key=condition["key"], result=values))
        ns = {condition["key"]: statistics.mean(
            row["result"][0] / row["result"][2] for row in observed
            if row["key"] == condition["key"]) for condition in conditions}
        cycles.append(dict(ns=ns, raw=observed))
    return dict(case=case, panel=panel, mode=["scan", "format", "detail"][mode],
                repetitions=repeats, cycles=cycles, signature=expected)
